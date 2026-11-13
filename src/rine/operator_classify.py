"""The six-condition classifier that decides whether a message is from the agent's operator.

Plugin code runs it, never the model, and the same function serves the wake path and the read
path so the two cannot disagree. A message is operator class only when all six hold:

1. it verified, and it is a 1:1 message;
2. ``from_agent_id`` is the pinned seat's id (never a handle);
3. the key that verified the signature is the pinned key, compared in full;
4. the SIGNED purpose is ``operator.command`` and the signed agent is this one (the row's
   ``type`` is unsigned and is never read);
5. ``issued_at`` is inside the window and not more than five minutes ahead;
6. the ledger has not seen the nonce on a different row or ciphertext.

Every input is required. A pin that is absent is an explicit ``None``, so a missing value can
never compare equal to a missing value. Twin of ``rine-core/src/operator-classify.ts``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from rine._constants import EncryptionVersion
from rine._crypto._sender_verdict import sender_matches
from rine._operator_ledger import LedgerEntry, LedgerLoc, update_ledger
from rine.operator_pin import pin_matches_key, pin_matches_sender
from rine.operator_statement import (
    OPERATOR_COMMAND_PURPOSE,
    OPERATOR_FUTURE_SKEW_MS,
    OPERATOR_WINDOW_MS,
    parse_operator_statement,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._crypto.message import DecryptResult
    from rine.operator_pin import OperatorPin

#: How a message reaches a model: as the operator's word, as the operator's past word, or as data.
SenderClass = Literal["operator", "operator_history", "other"]

#: Why a row got its class: the condition that failed, or how it passed.
ClassReason = Literal[
    "new",
    "redelivered",
    "expired",
    "already_rendered",
    "no_pin",
    "not_direct",
    "not_verified",
    "wrong_sender",
    "wrong_key",
    "no_statement",
    "wrong_purpose",
    "wrong_recipient",
    "future",
    "context_only",
    "replay",
    "substituted",
    "ledger_unavailable",
]


@dataclass(frozen=True, slots=True)
class OperatorVerdict:
    """A row's class and the reason for it."""

    sender_class: SenderClass
    reason: ClassReason


@dataclass(frozen=True, slots=True)
class OperatorContext:
    """What the classifier needs about this agent, fixed for a surface's lifetime."""

    #: The pinned seat, or ``None`` when none is configured, disabled or unreadable.
    pin: OperatorPin | None
    #: This agent's own id: the statement must be addressed to it.
    self_agent_id: str
    #: Where the ledger lives.
    config_dir: str
    #: The reader's clock in epoch milliseconds.
    now: Callable[[], int]
    #: Where a replay or a ledger failure is reported.
    warn: Callable[[str], None]


@dataclass(frozen=True, slots=True)
class OperatorRowInput:
    """One received row, as opened."""

    row_id: str
    from_agent_id: str
    encryption_version: str
    encrypted_payload: str
    #: The decrypt outcome, or ``None`` for a row that could not be opened at all.
    result: DecryptResult | None
    #: True when this call hands the text to a model, which is what uses up a statement.
    renders_text: bool
    #: The server's ``context_only`` mark (a hold was involved), or ``None``. Any non-empty
    #: value makes the row context: an operator verdict becomes ``operator_history``.
    context_only: str | None = None


#: The verdict for a row that was never opened.
UNOPENED_VERDICT = OperatorVerdict("other", "not_verified")


def _digest_of(encrypted_payload: str) -> str:
    return hashlib.sha256(encrypted_payload.encode("utf-8")).hexdigest()


def _decide_by_ledger(
    entries: dict[str, LedgerEntry],
    ctx: OperatorContext,
    row: OperatorRowInput,
    nonce: str,
    issued_at_ms: int,
) -> OperatorVerdict:
    """Condition 6: the ledger's say, recorded in the same locked step."""
    digest = _digest_of(row.encrypted_payload)
    seen = entries.get(nonce)
    if seen is None:
        entries[nonce] = LedgerEntry(row.row_id, digest, row.renders_text, issued_at_ms)
        return OperatorVerdict("operator", "new")
    if seen.row_id != row.row_id:
        ctx.warn(
            f"operator statement nonce seen on row {seen.row_id} arrived again on row "
            f"{row.row_id}: a replay"
        )
        return OperatorVerdict("other", "replay")
    if seen.digest != digest:
        ctx.warn(
            f"row {row.row_id} carries a different ciphertext than the one classified earlier"
        )
        return OperatorVerdict("other", "substituted")
    if seen.rendered:
        return OperatorVerdict("operator_history", "already_rendered")
    if row.renders_text:
        entries[nonce] = LedgerEntry(seen.row_id, seen.digest, True, seen.issued_at_ms)
    return OperatorVerdict("operator", "redelivered")


def classify_operator_row(ctx: OperatorContext, row: OperatorRowInput) -> OperatorVerdict:
    """Classify one received row. Never raises: a failure to consult the ledger is ``other``."""
    pin, result = ctx.pin, row.result
    if pin is None:
        return OperatorVerdict("other", "no_pin")
    if row.encryption_version != EncryptionVersion.HPKE_HYBRID_V2:
        return OperatorVerdict("other", "not_direct")
    if result is None or not result.verified or result.verification_status != "verified":
        return OperatorVerdict("other", "not_verified")
    if not pin_matches_sender(pin, row.from_agent_id):
        return OperatorVerdict("other", "wrong_sender")
    if not pin_matches_key(pin, result.verifying_key):
        return OperatorVerdict("other", "wrong_key")
    statement = parse_operator_statement(result.plaintext)
    if statement is None:
        return OperatorVerdict("other", "no_statement")
    if statement.purpose != OPERATOR_COMMAND_PURPOSE:
        return OperatorVerdict("other", "wrong_purpose")
    if not sender_matches(statement.agent, ctx.self_agent_id):
        return OperatorVerdict("other", "wrong_recipient")
    now = ctx.now()
    if statement.issued_at_ms > now + OPERATOR_FUTURE_SKEW_MS:
        return OperatorVerdict("other", "future")
    context_only = bool(row.context_only)
    if not context_only and now - statement.issued_at_ms > OPERATOR_WINDOW_MS:
        return OperatorVerdict("operator_history", "expired")
    loc = LedgerLoc(ctx.config_dir, ctx.self_agent_id)
    try:
        # A context row still goes through the ledger, so its nonce is spent: the same
        # statement replayed in a later row, sent after the resume, is refused as a replay.
        decided = update_ledger(
            loc,
            now,
            lambda entries: _decide_by_ledger(
                entries, ctx, row, statement.nonce, statement.issued_at_ms
            ),
        )
        if context_only and decided.sender_class == "operator":
            return OperatorVerdict("operator_history", "context_only")
        return decided
    except Exception as err:  # noqa: BLE001 - any ledger failure must fail closed to data
        ctx.warn(f"operator ledger unavailable, treating the row as data: {err}")
        return OperatorVerdict("other", "ledger_unavailable")
