"""reserve_spend: atomic enforce+debit under the lock, replay guard, rollover."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.journal import _journal_path, read_daily_spent, reserve_spend
from rine.x402.types import PaymentPolicy

BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
T = 1_740_000_000  # a fixed UTC instant


def _req(amount: str) -> dict:
    return {
        "scheme": "exact",
        "network": BASE,
        "amount": amount,
        "asset": EURC,
        "payTo": "0xpayee",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "EURC", "version": "2"},
    }


def _policy(**overrides) -> PaymentPolicy:
    base = dict(
        per_tx_cap="5.00",
        daily_cap="1.00",
        allowed_assets=["EURC"],
        allowed_networks=[BASE],
        auto_pay_threshold="1.00",
    )
    base.update(overrides)
    return PaymentPolicy(**base)  # type: ignore[arg-type]


def _journal(tmp_path, agent_id) -> dict:
    return json.loads(open(_journal_path(str(tmp_path), agent_id)).read())


def test_reserve_spend_when_payable_debits_and_records_id(tmp_path) -> None:
    """A payable reservation returns its value and writes the v2 journal + paidIds."""
    agent_id = str(uuid4())
    value = reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="m1", now_seconds=T
    )
    assert value == 300_000
    j = _journal(tmp_path, agent_id)
    assert j["spentCanonical"] == "300000" and j["paidIds"] == ["m1"]


def test_reserve_spend_when_accumulated_over_cap_refuses_and_leaves_journal(tmp_path) -> None:
    """The reservation that would breach dailyCap raises and never debits."""
    agent_id = str(uuid4())
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="a", now_seconds=T
    )
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="b", now_seconds=T
    )
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="c", now_seconds=T
    )
    with pytest.raises(X402Error) as exc:
        reserve_spend(
            str(tmp_path), agent_id, _policy(), _req("300000"), message_id="d", now_seconds=T
        )
    assert exc.value.code == X402ErrorCode.DAILY_CAP_EXCEEDED
    assert read_daily_spent(str(tmp_path), agent_id, T) == 900_000  # only the 3 that fit


def test_reserve_spend_when_no_policy_denies_and_writes_nothing(tmp_path) -> None:
    """Deny-by-default under the lock; the journal is never created."""
    agent_id = str(uuid4())
    with pytest.raises(X402Error) as exc:
        reserve_spend(str(tmp_path), agent_id, None, _req("100000"), now_seconds=T)
    assert exc.value.code == X402ErrorCode.NO_POLICY
    assert read_daily_spent(str(tmp_path), agent_id, T) == 0


def test_reserve_spend_when_next_utc_day_resets(tmp_path) -> None:
    """Rollover: a reservation the next UTC day starts the bucket fresh."""
    agent_id = str(uuid4())
    reserve_spend(str(tmp_path), agent_id, _policy(), _req("900000"), now_seconds=T)
    reserve_spend(str(tmp_path), agent_id, _policy(), _req("900000"), now_seconds=T + 86_400)
    assert read_daily_spent(str(tmp_path), agent_id, T + 86_400) == 900_000


def test_reserve_spend_tolerates_old_v1_journal(tmp_path) -> None:
    """A v1 journal (no paidIds) is read, then upgraded to v2 on the next debit."""
    from rine.x402.journal import record_spend

    agent_id = str(uuid4())
    record_spend(str(tmp_path), agent_id, 300_000, T)  # writes a v1 body, no paidIds
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="m1", now_seconds=T
    )
    j = _journal(tmp_path, agent_id)
    assert j["spentCanonical"] == "600000" and j["paidIds"] == ["m1"]


def test_reserve_spend_when_same_id_twice_raises_already_paid(tmp_path) -> None:
    """Same message id, same day → already-paid; force debits again with one id entry."""
    agent_id = str(uuid4())
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="m1", now_seconds=T
    )
    with pytest.raises(X402Error) as exc:
        reserve_spend(
            str(tmp_path), agent_id, _policy(), _req("300000"), message_id="m1", now_seconds=T
        )
    assert exc.value.code == X402ErrorCode.ALREADY_PAID
    reserve_spend(
        str(tmp_path),
        agent_id,
        _policy(),
        _req("300000"),
        message_id="m1",
        force=True,
        now_seconds=T,
    )
    j = _journal(tmp_path, agent_id)
    assert j["spentCanonical"] == "600000" and j["paidIds"] == ["m1"]  # id de-duplicated


def test_reserve_spend_when_no_message_id_leaves_paidids_empty(tmp_path) -> None:
    """The HTTP/no-id path debits but never records a paidIds entry."""
    agent_id = str(uuid4())
    reserve_spend(str(tmp_path), agent_id, _policy(), _req("300000"), now_seconds=T)
    assert _journal(tmp_path, agent_id)["paidIds"] == []
