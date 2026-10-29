"""Daily-spend journal (schema v2) + atomic reserve-under-lock (the TOCTOU fix).

Split out of ``policy.py`` to keep each module small. The journal at
``keys/{agent_id}/wallet-spend.json`` is v2 — ``{"day": "YYYY-MM-DD",
"spentCanonical": "<int>", "paidIds": [...]}``, UTC day-bucketed and interoperable
with the TypeScript wallet (readers tolerate a v1 body with no ``paidIds``).
:func:`reserve_spend` is the authoritative writer: it re-enforces policy and debits
atomically under the cross-process spend lock, and the debit is permanent
(fail-closed, no refund path).
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from rine._config import _write_atomic, keys_dir
from rine._crypto.keys import _validate_path_id
from rine.x402._spend_lock import spend_lock
from rine.x402.assets import requirement_canonical_amount
from rine.x402.errors import CorruptSpendJournalError, X402Error, X402ErrorCode
from rine.x402.policy import enforce_policy

if TYPE_CHECKING:
    from rine.x402.types import PaymentPolicy, PaymentRequirements


def _journal_path(config_dir: str, agent_id: str) -> str:
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(keys_dir(config_dir, agent_id), "wallet-spend.json")


def _utc_day(now_seconds: float) -> str:
    return datetime.fromtimestamp(now_seconds, UTC).strftime("%Y-%m-%d")


_DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_CANONICAL_AMOUNT_RE = re.compile(r"[0-9]+")


def _is_spend_journal(value: object) -> bool:
    """Whether ``value`` has the v2 journal shape; a v1 body has no ``paidIds``."""
    if not isinstance(value, dict):
        return False
    day = value.get("day")
    spent = value.get("spentCanonical")
    return (
        isinstance(day, str)
        and _DAY_RE.fullmatch(day) is not None
        and isinstance(spent, str)
        and _CANONICAL_AMOUNT_RE.fullmatch(spent) is not None
        and (
            "paidIds" not in value
            or (
                isinstance(value["paidIds"], list)
                and all(isinstance(paid_id, str) for paid_id in value["paidIds"])
            )
        )
    )


def _read_journal_today(
    config_dir: str, agent_id: str, now_seconds: float
) -> tuple[str, int, list[str]]:
    """Today's bucket as ``(day, spent_canonical, paid_ids)``.

    A missing or prior-day journal reads as ``(today, 0, [])``, and a v1 journal
    (no ``paidIds`` key) still reads. A journal dated tomorrow is still the bucket,
    with its own day: the clock moved back across UTC midnight, and that spend is
    today's.

    Raises:
        CorruptSpendJournalError: The journal exists but is not UTF-8, cannot be parsed
            as one, or is dated more than a day ahead, so the daily cap never fails open.
    """
    path = _journal_path(config_dir, agent_id)
    today = _utc_day(now_seconds)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return today, 0, []
    except UnicodeDecodeError as exc:
        raise CorruptSpendJournalError(path) from exc
    try:
        journal = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorruptSpendJournalError(path) from exc
    if not _is_spend_journal(journal):
        raise CorruptSpendJournalError(path)
    if journal["day"] > _utc_day(now_seconds + 86_400):
        raise CorruptSpendJournalError(
            path,
            f"is dated {journal['day']}, later than today's date {today}, so check the system "
            "clock; payments are refused until the clock is right or the file is repaired",
        )
    if journal["day"] < today:
        return today, 0, []
    return journal["day"], int(journal["spentCanonical"]), list(journal.get("paidIds", []))


def read_daily_spent(config_dir: str, agent_id: str, now_seconds: float | None = None) -> int:
    """Today's spend in canonical micro-units (0 if the journal is missing or a prior day).

    Raises:
        CorruptSpendJournalError: The journal exists but cannot be read.
    """
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    return _read_journal_today(config_dir, agent_id, now)[1]


def record_spend(
    config_dir: str, agent_id: str, canonical_amount: int, now_seconds: float | None = None
) -> None:
    """Add a spend to today's bucket, atomic write, preserving ``paidIds``.

    Day-rollover resets the bucket, and a journal dated more than a day ahead raises
    :class:`CorruptSpendJournalError`. Retained for status displays and tests; no
    flow calls this — the pay path reserves via :func:`reserve_spend`, which is
    the only cap-enforcing writer.
    """
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    day, spent, paid_ids = _read_journal_today(config_dir, agent_id, now)
    payload = {
        "day": day,
        "spentCanonical": str(spent + canonical_amount),
        "paidIds": paid_ids,
    }
    _write_atomic(_journal_path(config_dir, agent_id), json.dumps(payload, separators=(",", ":")))


def reserve_spend(
    config_dir: str,
    agent_id: str,
    policy: PaymentPolicy | None,
    req: PaymentRequirements,
    *,
    message_id: str | None = None,
    force: bool = False,
    now_seconds: float | None = None,
) -> int:
    """Enforce policy and debit the daily journal atomically, under a lock.

    This is the LAST local act before a caller transmits; the debit is permanent
    (fail-closed, no refund path). Under the cross-process lock the journal is
    re-read fresh (UTC rollover applies), a replay is refused (``message_id``
    already in ``paidIds`` and not ``force`` → ``already-paid``), the full
    :func:`enforce_policy` re-runs against the freshly read spend, then
    ``spent + value`` is written and ``message_id`` recorded.

    Returns the canonical micro-unit value reserved. Raises
    :class:`rine.x402.errors.X402Error` (``wallet-busy``, ``already-paid``, or any
    policy code) with the journal untouched on refusal, or
    :class:`rine.x402.errors.CorruptSpendJournalError` when the journal cannot be read.
    """
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    with spend_lock(config_dir, agent_id):
        day, spent, paid_ids = _read_journal_today(config_dir, agent_id, now)
        if message_id is not None and not force and message_id in paid_ids:
            raise X402Error(
                X402ErrorCode.ALREADY_PAID,
                f"Payment for message {message_id} already reserved today",
                {"messageId": message_id},
            )
        enforce_policy(policy, req, spent)
        value = requirement_canonical_amount(req)
        if message_id is not None and message_id not in paid_ids:
            paid_ids = [*paid_ids, message_id]
        payload = {
            "day": day,
            "spentCanonical": str(spent + value),
            "paidIds": paid_ids,
        }
        _write_atomic(
            _journal_path(config_dir, agent_id),
            json.dumps(payload, separators=(",", ":")),
        )
        return value
