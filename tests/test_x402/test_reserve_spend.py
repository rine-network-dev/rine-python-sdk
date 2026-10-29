"""reserve_spend: atomic enforce+debit under the lock, replay guard, rollover."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from uuid import uuid4

import pytest

from rine.x402.errors import CorruptSpendJournalError, X402Error, X402ErrorCode
from rine.x402.journal import _journal_path, read_daily_spent, record_spend, reserve_spend
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


def _write_journal(tmp_path, agent_id: str, raw: bytes) -> str:
    """Write ``raw`` as the agent's journal file and return its path."""
    path = _journal_path(str(tmp_path), agent_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    return path


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


def test_reserve_spend_when_clock_moved_back_a_day_then_cap_and_paid_ids_hold(tmp_path) -> None:
    """A journal dated tomorrow (clock set back across midnight) still counts."""
    agent_id = str(uuid4())
    reserve_spend(
        str(tmp_path), agent_id, _policy(), _req("300000"), message_id="m1", now_seconds=T
    )
    with pytest.raises(X402Error) as exc:
        reserve_spend(
            str(tmp_path),
            agent_id,
            _policy(),
            _req("300000"),
            message_id="m1",
            now_seconds=T - 86_400,
        )
    assert exc.value.code == X402ErrorCode.ALREADY_PAID
    assert read_daily_spent(str(tmp_path), agent_id, T - 86_400) == 300_000


def test_reserve_spend_tolerates_old_v1_journal(tmp_path) -> None:
    """A v1 journal (no paidIds) is read, then upgraded to v2 on the next debit."""
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


@pytest.mark.parametrize(
    "corrupt",
    [
        pytest.param('{"day": "2025-02-19", "spent', id="truncated-json"),
        pytest.param('{"day": "2025-02-19", "spentCanonical": "lots"}', id="non-numeric-total"),
        pytest.param('{"spentCanonical": "5"}', id="missing-day"),
        pytest.param(
            '{"day": "2025-02-18", "spentCanonical": "5", "paidIds": [1]}',
            id="non-string-paid-ids-on-a-prior-day",
        ),
        pytest.param('{"day": "2025-02-19", "spentCanonical": 5}', id="numeric-total"),
        pytest.param('{"day": "2025-02-21", "spentCanonical": "5"}', id="two-days-ahead"),
        pytest.param('{"day": "2035-02-19", "spentCanonical": "5"}', id="far-future-year"),
        pytest.param(b"\xff\xfe", id="not-utf8"),
        pytest.param(
            b'{"day": "2025-02-19", "spentCanonical": "5", "paidIds": ["\xff"]}',
            id="not-utf8-inside-a-string",
        ),
    ],
)
def test_reserve_spend_when_journal_is_corrupt_then_refuses_and_names_the_file(
    tmp_path, corrupt: str | bytes
) -> None:
    """A journal that cannot be read refuses every payment, naming the file, and stays as is."""
    agent_id = str(uuid4())
    raw = corrupt if isinstance(corrupt, bytes) else corrupt.encode()
    path = _write_journal(tmp_path, agent_id, raw)

    with pytest.raises(CorruptSpendJournalError, match=re.escape(path)):
        read_daily_spent(str(tmp_path), agent_id, T)
    with pytest.raises(CorruptSpendJournalError, match=re.escape(path)):
        reserve_spend(str(tmp_path), agent_id, _policy(), _req("1"), now_seconds=T)
    with pytest.raises(CorruptSpendJournalError, match=re.escape(path)):
        record_spend(str(tmp_path), agent_id, 1, T)
    with open(path, "rb") as handle:
        assert handle.read() == raw


@pytest.mark.parametrize(
    ("now", "journal_day", "kept"),
    [
        pytest.param("2026-01-31T12:00:00+00:00", "2026-02-01", True, id="month-end"),
        pytest.param("2026-12-31T12:00:00+00:00", "2027-01-01", True, id="year-end"),
        pytest.param("2026-12-31T12:00:00+00:00", "2027-01-02", False, id="year-end-plus-two"),
    ],
)
def test_read_daily_spent_when_journal_is_dated_across_a_calendar_boundary_then_the_day_decides(
    tmp_path, now: str, journal_day: str, kept: bool
) -> None:
    """Tomorrow keeps its spend and two days ahead refuses, across a month and a year end."""
    agent_id = str(uuid4())
    path = _write_journal(
        tmp_path, agent_id, json.dumps({"day": journal_day, "spentCanonical": "5"}).encode()
    )
    now_seconds = datetime.fromisoformat(now).timestamp()
    if kept:
        assert read_daily_spent(str(tmp_path), agent_id, now_seconds) == 5
    else:
        with pytest.raises(CorruptSpendJournalError, match=re.escape(path)):
            read_daily_spent(str(tmp_path), agent_id, now_seconds)


def test_read_daily_spent_when_journal_is_days_ahead_then_the_message_names_the_clock(
    tmp_path,
) -> None:
    """The error says the journal is dated later than today, so the clock is what to check."""
    agent_id = str(uuid4())
    path = _write_journal(tmp_path, agent_id, b'{"day": "2025-02-21", "spentCanonical": "5"}')
    with pytest.raises(CorruptSpendJournalError) as exc:
        read_daily_spent(str(tmp_path), agent_id, T)
    assert str(exc.value) == (
        f"{path} is dated 2025-02-21, later than today's date 2025-02-19, so check the "
        "system clock; payments are refused until the clock is right or the file is repaired"
    )


def test_read_daily_spent_when_journal_is_missing_then_reads_zero(tmp_path) -> None:
    """No journal yet is an empty day, not a corrupt one."""
    assert read_daily_spent(str(tmp_path), str(uuid4()), T) == 0
