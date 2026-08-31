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
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from rine._config import _write_atomic, keys_dir
from rine._crypto.keys import _validate_path_id
from rine.x402._spend_lock import spend_lock
from rine.x402.assets import requirement_canonical_amount
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.policy import enforce_policy

if TYPE_CHECKING:
    from rine.x402.types import PaymentPolicy, PaymentRequirements


def _journal_path(config_dir: str, agent_id: str) -> str:
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(keys_dir(config_dir, agent_id), "wallet-spend.json")


def _utc_day(now_seconds: float) -> str:
    return datetime.fromtimestamp(now_seconds, UTC).strftime("%Y-%m-%d")


def _read_journal_today(
    config_dir: str, agent_id: str, now_seconds: float
) -> tuple[int, list[str]]:
    """Today's ``(spent_canonical, paid_ids)``; ``(0, [])`` after a UTC rollover.

    Tolerates a v1 journal (no ``paidIds`` key) so an old writer's file still reads.
    """
    try:
        with open(_journal_path(config_dir, agent_id)) as f:
            j = json.load(f)
        if j.get("day") == _utc_day(now_seconds):
            paid = j.get("paidIds")
            paid_ids = [str(x) for x in paid] if isinstance(paid, list) else []
            return int(j["spentCanonical"]), paid_ids
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        pass
    return 0, []


def read_daily_spent(config_dir: str, agent_id: str, now_seconds: float | None = None) -> int:
    """Today's spend in canonical micro-units (0 if the journal is a prior day)."""
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    return _read_journal_today(config_dir, agent_id, now)[0]


def record_spend(
    config_dir: str, agent_id: str, canonical_amount: int, now_seconds: float | None = None
) -> None:
    """Add a spend to today's bucket, atomic write, preserving ``paidIds``.

    Day-rollover resets the bucket. Retained for status displays and tests; no
    flow calls this — the pay path reserves via :func:`reserve_spend`, which is
    the only cap-enforcing writer.
    """
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    spent, paid_ids = _read_journal_today(config_dir, agent_id, now)
    payload = {
        "day": _utc_day(now),
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
    policy code) with the journal untouched on refusal.
    """
    now = now_seconds if now_seconds is not None else datetime.now(UTC).timestamp()
    with spend_lock(config_dir, agent_id):
        spent, paid_ids = _read_journal_today(config_dir, agent_id, now)
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
            "day": _utc_day(now),
            "spentCanonical": str(spent + value),
            "paidIds": paid_ids,
        }
        _write_atomic(
            _journal_path(config_dir, agent_id),
            json.dumps(payload, separators=(",", ":")),
        )
        return value
