"""What the server's refusal of one pending escrow upload means for that file.

Four outcomes, closed: the slot already holds this agent's own row (the send gate
asks for nothing more), the server will never take it, it may yet, or the server is
too busy or down to say, so no other file should be tried now either. A refusal is
only terminal when it carries a code this module knows: a bare 403 or 404 may be a
proxy or a deploy window, so it is retried like any other refusal. The TypeScript
twin is ``rine-core/src/mls-escrow-answer.ts``.
"""

from __future__ import annotations

from enum import Enum, StrEnum, auto
from typing import TYPE_CHECKING

from rine._mls.wire import api_error_code
from rine.errors import PrincipalRevokedError

if TYPE_CHECKING:
    from rine.errors import RineApiError

HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR = 500


class EscrowCode(StrEnum):
    """The server's machine-readable ``error`` key for a refused escrow upload."""

    SLOT_TAKEN = "escrow_slot_taken"  # 409, the slot holds this agent's own row: stored
    FORK_LIMIT = "escrow_fork_limit"  # 409, terminal
    NO_SEAT = "escrow_no_seat"  # 403, terminal
    GROUP_NOT_FOUND = "group_not_found"  # 404, terminal
    BRANCH_REVOKED = "branch_revoked"  # 422, terminal
    AGENT_REVOKED = "agent_revoked"  # 422, terminal


#: Codes that end an upload for good: the file will never be accepted.
TERMINAL_CODES: frozenset[EscrowCode] = frozenset(
    {
        EscrowCode.FORK_LIMIT,
        EscrowCode.NO_SEAT,
        EscrowCode.GROUP_NOT_FOUND,
        EscrowCode.BRANCH_REVOKED,
        EscrowCode.AGENT_REVOKED,
    }
)


class Answer(Enum):
    """What a refusal means for the pending file it answered."""

    STORED = auto()
    REFUSED = auto()
    RETRY = auto()
    BACKOFF = auto()


def escrow_code(exc: RineApiError) -> EscrowCode | None:
    """The refusal's code as an enum, or ``None`` when absent or not one we know."""
    code = api_error_code(exc)
    if code is None:
        return None
    try:
        return EscrowCode(code)
    except ValueError:
        return None


def classify_refusal(exc: RineApiError) -> Answer:
    """Sort a refusal: the slot is already filled, never going to be, may yet be, or unknown.

    A revoked agent or branch named by a 401 is terminal like the codes below: the 401
    carries no escrow code, but no later attempt can succeed either.
    """
    if isinstance(exc, PrincipalRevokedError):
        return Answer.REFUSED
    code = escrow_code(exc)
    if code is EscrowCode.SLOT_TAKEN:
        return Answer.STORED
    if code in TERMINAL_CODES:
        return Answer.REFUSED
    if exc.status == HTTP_TOO_MANY_REQUESTS or exc.status >= HTTP_SERVER_ERROR:
        return Answer.BACKOFF
    return Answer.RETRY
