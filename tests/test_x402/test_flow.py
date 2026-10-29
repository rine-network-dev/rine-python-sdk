"""Payer flow: load wallet+policy from disk, select+sign, reserve spend."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest

from rine._constants import MessageType
from rine._crypto.wallet import save_wallet_key
from rine.types import DecryptedMessage
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.flow import prepare_payment
from rine.x402.journal import read_daily_spent
from rine.x402.policy import save_policy
from rine.x402.types import X402_QUOTE_REF_KEY, PaymentPolicy

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


def _quote(amount: str, status: str = "verified", **overrides: Any) -> DecryptedMessage:
    """The decrypted quote a payer acts on, carrying the sender verdict."""
    return DecryptedMessage.model_validate(
        {
            "id": str(uuid4()),
            "conversation_id": str(uuid4()),
            "from_agent_id": str(uuid4()),
            "to_agent_id": str(uuid4()),
            "type": MessageType.X402_PAYMENT_REQUIRED,
            "direction": "received",
            "encrypted_payload": "enc",
            "created_at": "2024-01-01T00:00:00Z",
            "plaintext": json.dumps(_pr(amount)),
            "decrypt_error": None,
            "verification_status": status,
            **overrides,
        }
    )


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
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=_quote("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
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
        quote=_quote("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
        add_marker=False,
    )
    assert sealed.message.metadata == {}
    marked = prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=_quote("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    assert marked.message.metadata != {}  # default stays opt-out (marker present)


def test_prepare_payment_stamps_message_id_as_signed_quote_ref(tmp_path) -> None:
    """The received quote's message_id is stamped into the signed payment payload."""
    agent_id = _setup(tmp_path)
    quote = _quote("500000")
    prepared = prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=quote,
        message_id=str(quote.id),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    assert prepared.message.payload["extensions"][X402_QUOTE_REF_KEY] == str(quote.id)


def test_prepare_payment_without_message_id_leaves_payment_unbound(tmp_path) -> None:
    """No message_id → no quote-ref stamped (payee must then use expected terms)."""
    agent_id = _setup(tmp_path)
    prepared = prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=_quote("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    assert X402_QUOTE_REF_KEY not in prepared.message.payload["extensions"]


def test_prepare_payment_when_over_threshold_not_auto_payable(tmp_path) -> None:
    """Prepare payment when over threshold not auto payable."""
    agent_id = _setup(tmp_path)
    prepared = prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("2000000"),
        quote=_quote("2000000"),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    assert prepared.auto_payable is False  # 2.00 > 1.00 threshold, still within caps


def test_prepare_payment_when_no_policy_denies(tmp_path) -> None:
    """Prepare payment when no policy denies."""
    agent_id = str(uuid4())
    save_wallet_key(str(tmp_path), agent_id, KEY)  # wallet but no policy
    with pytest.raises(X402Error) as exc:
        prepare_payment(str(tmp_path), agent_id, _pr("100000"), quote=_quote("100000"))
    assert exc.value.code == X402ErrorCode.NO_ACCEPTABLE_REQUIREMENT


def test_prepare_payment_reserves_journal_at_signing(tmp_path) -> None:
    """Prepare debits the journal as its final act — even if the caller never sends."""
    agent_id = _setup(tmp_path)
    prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=_quote("500000"),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    # Fail-closed: the budget is spent at signing, before any transmit.
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 500_000


def test_prepare_payment_when_same_message_id_twice_raises_already_paid(tmp_path) -> None:
    """Same message id, same day → already-paid unless forced (double-pay guard)."""
    agent_id = _setup(tmp_path)
    quote = _quote("500000")
    prepare_payment(
        str(tmp_path),
        agent_id,
        _pr("500000"),
        quote=quote,
        message_id=str(quote.id),
        now=1_700_000_000,
        nonce=bytes(32),
    )
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            quote=quote,
            message_id=str(quote.id),
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert exc.value.code == X402ErrorCode.ALREADY_PAID
    # Only one debit landed — the refused replay left the journal untouched.
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 500_000


def test_prepare_payment_when_force_bypasses_already_paid(tmp_path) -> None:
    """force=True re-pays a seen message id and debits again (single paidIds entry)."""
    agent_id = _setup(tmp_path)
    quote = _quote("500000")
    for _ in range(2):
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            quote=quote,
            message_id=str(quote.id),
            force=True,
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 1_000_000


@pytest.mark.parametrize(
    ("status", "code"),
    [
        ("unverifiable", X402ErrorCode.SENDER_UNVERIFIABLE),
        ("sender-mismatch", X402ErrorCode.INAUTHENTIC_SENDER),
        ("invalid", X402ErrorCode.INAUTHENTIC_SENDER),
    ],
)
def test_prepare_payment_when_quote_sender_not_verified_refuses_before_signing(
    tmp_path, status: str, code: str
) -> None:
    """A quote whose sender verdict is not ``verified`` is never signed against or debited.

    A check that could not run carries its own retryable code, not the inauthentic one.
    """
    agent_id = _setup(tmp_path)
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            quote=_quote("500000", status),
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert exc.value.code == code
    assert exc.value.details == {"verification_status": status}
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"decrypt_error": "AEAD failure"},
        {"a2a_cleartext": True},
        {"from_agent_id": None},
    ],
    ids=["failed-to-decrypt", "a2a-cleartext", "no-sender"],
)
def test_prepare_payment_when_unverifiable_quote_cannot_pass_on_retry_refuses_as_inauthentic(
    tmp_path, overrides: dict[str, Any]
) -> None:
    """A quote that failed to decrypt, is cleartext A2A or has no sender cannot pass on a retry."""
    agent_id = _setup(tmp_path)
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            quote=_quote("500000", "unverifiable", **overrides),
            now=1_700_000_000,
            nonce=bytes(32),
        )
    assert exc.value.code == X402ErrorCode.INAUTHENTIC_SENDER
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 0


def test_prepare_payment_when_requirement_is_not_the_quotes_refuses_before_debit(tmp_path) -> None:
    """A verified quote vouches for its own body only, never for another requirement."""
    agent_id = _setup(tmp_path)
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path), agent_id, _pr("900000"), quote=_quote("500000"), now=1_700_000_000
        )
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 0


def test_prepare_payment_when_message_id_is_not_the_quotes_refuses_before_debit(tmp_path) -> None:
    """The quote reference stamped into the payment is the quote that was verified."""
    agent_id = _setup(tmp_path)
    with pytest.raises(X402Error) as exc:
        prepare_payment(
            str(tmp_path),
            agent_id,
            _pr("500000"),
            quote=_quote("500000"),
            message_id=str(uuid4()),
            now=1_700_000_000,
        )
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH
    assert read_daily_spent(str(tmp_path), agent_id, 1_700_000_000) == 0


def test_prepare_payment_when_verified_quote_failed_to_decrypt_refuses(tmp_path) -> None:
    """A verdict next to a decrypt error is not a verdict."""
    agent_id = _setup(tmp_path)
    quote = _quote("500000")
    quote.decrypt_error = "payload did not open"
    with pytest.raises(X402Error) as exc:
        prepare_payment(str(tmp_path), agent_id, _pr("500000"), quote=quote, now=1_700_000_000)
    assert exc.value.code == X402ErrorCode.INAUTHENTIC_SENDER
