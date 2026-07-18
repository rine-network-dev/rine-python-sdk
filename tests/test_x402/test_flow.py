"""Payer flow: load wallet+policy from disk, select+sign, reserve spend."""

from __future__ import annotations

from uuid import uuid4

import pytest

from rine._constants import MessageType
from rine._crypto.wallet import save_wallet_key
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.flow import prepare_payment
from rine.x402.journal import read_daily_spent
from rine.x402.policy import save_policy
from rine.x402.types import PaymentPolicy

BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
KEY = bytes(31) + b"\x01"


def _pr(amount: str) -> dict:
    return {
        "x402Version": 2,
        "resource": {"description": "summarize"},
        "accepts": [
            {
                "scheme": "exact",
                "network": BASE,
                "amount": amount,
                "asset": EURC,
                "payTo": "0x808456652fdb597867f38412077a9182bf77359f",
                "maxTimeoutSeconds": 60,
                "extra": {"name": "EURC", "version": "2"},
            }
        ],
    }


def _setup(tmp_path, **policy_overrides) -> str:
    agent_id = str(uuid4())
    save_wallet_key(str(tmp_path), agent_id, KEY)
    base = dict(
        per_tx_cap="5.00",
        daily_cap="10.00",
        allowed_assets=["EURC"],
        allowed_networks=[BASE],
        auto_pay_threshold="1.00",
    )
    base.update(policy_overrides)
    save_policy(str(tmp_path), agent_id, PaymentPolicy(**base))  # type: ignore[arg-type]
    return agent_id


def test_prepare_payment_when_payable_returns_signed_submitted_message(tmp_path) -> None:
    """Prepare payment when payable returns signed submitted message."""
    agent_id = _setup(tmp_path)
    prepared = prepare_payment(
        str(tmp_path), agent_id, _pr("500000"), now=1_700_000_000, nonce=bytes(32)
    )
    assert prepared.message.message_type == MessageType.X402_PAYMENT
    assert prepared.message.payload["payload"]["signature"].startswith("0x")
    assert prepared.canonical_amount == 500_000  # 0.50 EURC in micro-units
    assert prepared.auto_payable is True  # under 1.00 threshold


def test_prepare_payment_when_add_marker_false_emits_no_marker(tmp_path) -> None:
    """Prepare payment threads add_marker=False for a fully-sealed payment."""
    agent_id = _setup(tmp_path)
    sealed = prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
        add_marker=False,
    )
    assert sealed.message.metadata == {}
    marked = prepare_payment(
        str(tmp_path), agent_id, _pr("500000"), now=1_700_000_000, nonce=bytes(32)
    )
    assert marked.message.metadata != {}  # default stays opt-out (marker present)


def test_prepare_payment_when_over_threshold_not_auto_payable(tmp_path) -> None:
    """Prepare payment when over threshold not auto payable."""
    agent_id = _setup(tmp_path)
    prepared = prepare_payment(
        str(tmp_path), agent_id, _pr("2000000"), now=1_700_000_000, nonce=bytes(32)
    )
    assert prepared.auto_payable is False  # 2.00 > 1.00 threshold, still within caps


def test_prepare_payment_when_no_policy_denies(tmp_path) -> None:
    """Prepare payment when no policy denies."""
    agent_id = str(uuid4())
    save_wallet_key(str(tmp_path), agent_id, KEY)  # wallet but no policy
    with pytest.raises(X402Error) as exc:
        prepare_payment(str(tmp_path), agent_id, _pr("100000"))
    assert exc.value.code == X402ErrorCode.NO_ACCEPTABLE_REQUIREMENT


def test_prepare_payment_reserves_journal_at_signing(tmp_path) -> None:
    """Prepare debits the journal as its final act — even if the caller never sends."""
    agent_id = _setup(tmp_path)
    prepare_payment(str(tmp_path), agent_id, _pr("500000"), now=1_700_000_000, nonce=bytes(32))
    # Fail-closed: the budget is spent at signing, before any transmit.
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 500_000


def test_prepare_payment_when_same_message_id_twice_raises_already_paid(tmp_path) -> None:
    """Same message id, same day → already-paid unless forced (S6 double-pay guard)."""
    agent_id = _setup(tmp_path)
    prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        message_id="msg-1",
        now=1_700_000_000,
        nonce=bytes(32),
    )
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            message_id="msg-1",
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert exc.value.code == X402ErrorCode.ALREADY_PAID
    # Only one debit landed — the refused replay left the journal untouched.
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 500_000


def test_prepare_payment_when_force_bypasses_already_paid(tmp_path) -> None:
    """force=True re-pays a seen message id and debits again (single paidIds entry)."""
    agent_id = _setup(tmp_path)
    for _ in range(2):
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            message_id="msg-1",
            force=True,
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 1_000_000
