"""The operator statement: the one field a Fleet console send adds to the payload it signs.

The signature binds domain, recipient and payload, and nothing about time or purpose, so a
replayed or relabelled row would verify as the operator's own. Putting purpose, recipient, a
nonce and an instant inside the signed payload lets the receiving plugin decide authority
from signed bytes alone. The row's ``type`` is unsigned and is never read for this.

Twin of ``rine-core/src/operator-statement.ts``; both are held to the same cases by
``rine-core/test/fixtures/agent-notices.json``.
"""

from __future__ import annotations

import json
import re
from calendar import timegm
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn

#: The payload key that carries the statement.
OPERATOR_STATEMENT_KEY = "rine.operator"

#: The only purpose that confers operator class.
OPERATOR_COMMAND_PURPOSE = "operator.command"

#: How long after ``issued_at`` a statement still counts as a new instruction (24 hours).
OPERATOR_WINDOW_MS = 24 * 60 * 60 * 1000

#: How far ahead of the reader's clock ``issued_at`` may be before the statement is refused.
OPERATOR_FUTURE_SKEW_MS = 5 * 60 * 1000

_NONCE = re.compile(r"[A-Za-z0-9_-]{1,128}")
_INSTANT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))"
)
_STATEMENT_VERSION = 1
_MAX_OFFSET_HOUR = 23
_MAX_OFFSET_MINUTE = 59


@dataclass(frozen=True, slots=True)
class OperatorStatement:
    """A well-formed operator statement, not yet held against any pin or clock."""

    purpose: str
    agent: str
    nonce: str
    #: ``issued_at`` as epoch milliseconds.
    issued_at_ms: int


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(name)


def _instant_ms(text: str) -> int | None:
    """Epoch milliseconds of an RFC 3339 instant with an offset, ``None`` for anything else.

    Fields must be a real calendar time: no 30 February, no hour 24, no leap second, no
    year 0, and an offset inside a day.
    """
    match = _INSTANT.fullmatch(text)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match[i]) for i in range(1, 7))
    sign, offset_hour, offset_minute = match[8], int(match[9] or 0), int(match[10] or 0)
    if offset_hour > _MAX_OFFSET_HOUR or offset_minute > _MAX_OFFSET_MINUTE:
        return None
    try:
        stamp = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None
    offset = offset_hour * 3600 + offset_minute * 60
    seconds = timegm(stamp.timetuple()) - (offset if sign == "+" else -offset if sign else 0)
    micros = int((match[7] or "").ljust(6, "0")[:6])
    return seconds * 1000 + micros // 1000


def parse_operator_statement(plaintext: str) -> OperatorStatement | None:
    """The statement a decrypted payload carries, or ``None`` short of a complete version 1.

    ``None`` covers no field, a wrong type, a nonce outside ``[A-Za-z0-9_-]{1,128}`` and an
    ``issued_at`` that is not an RFC 3339 instant with an offset. Unknown keys inside the
    statement are ignored.
    """
    try:
        payload: Any = json.loads(plaintext, parse_constant=_reject_constant)
    except ValueError:
        return None
    statement = payload.get(OPERATOR_STATEMENT_KEY) if isinstance(payload, dict) else None
    if not isinstance(statement, dict):
        return None
    version = statement.get("v")
    if isinstance(version, bool) or not isinstance(version, int | float):
        return None
    if version != _STATEMENT_VERSION:
        return None
    purpose, agent = statement.get("purpose"), statement.get("agent")
    nonce, issued_at = statement.get("nonce"), statement.get("issued_at")
    if not isinstance(purpose, str) or not isinstance(agent, str):
        return None
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        return None
    if not isinstance(issued_at, str):
        return None
    issued_at_ms = _instant_ms(issued_at)
    if issued_at_ms is None:
        return None
    return OperatorStatement(purpose, agent, nonce, issued_at_ms)


def strip_operator_statement(decrypted: object) -> object:
    """``decrypted`` without the statement key, so a stranger's own copy never reaches a model.

    Anything that is not a JSON object passes unchanged.
    """
    if not isinstance(decrypted, dict) or OPERATOR_STATEMENT_KEY not in decrypted:
        return decrypted
    return {key: value for key, value in decrypted.items() if key != OPERATOR_STATEMENT_KEY}
