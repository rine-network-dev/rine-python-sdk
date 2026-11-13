"""Governance holds: why the server refuses a principal that is otherwise in good standing.

A hold is an org freeze, a branch suspension or an agent suspension. The server states it in
two places and this module is the one reader of both: a bearer route refuses with a 403 whose
``error`` is the hold, and the token mint refuses with a 400 ``unauthorized_client`` whose
``reason`` is the hold and whose ``error_description`` is the sentence to show the person.
``HoldCode`` mirrors the server's ``Hold`` and the TypeScript ``HoldCode`` in ``rine-core``;
``rine-core/test/fixtures/governance-codes.json`` is the list all three are held equal to.
"""

from __future__ import annotations

from enum import StrEnum
from http import HTTPStatus

from rine.errors import AuthenticationError, _error_body


class HoldCode(StrEnum):
    """Why a principal is held, in the order the server checks."""

    ORG_FROZEN = "org_frozen"
    BRANCH_SUSPENDED = "branch_suspended"
    AGENT_SUSPENDED = "agent_suspended"


_HOLD_CODES = {hold.value: hold for hold in HoldCode}

#: The ``error`` the token mint answers with when it refuses a held principal.
_MINT_REFUSAL = "unauthorized_client"


class PrincipalHeldError(AuthenticationError):
    """The token mint refused the caller because its agent, branch or organisation is held.

    The credentials are fine and retrying cannot help until the hold is lifted; once it is,
    the next mint succeeds. ``detail`` is the server's own sentence for this principal (an
    agent's, or a branch key's), ready to show; branch on ``hold``, never on the sentence.

    Args:
        hold: Which hold the server named.
        detail: The server's explanation.
        raw: Optional raw response body.
    """

    def __init__(self, hold: HoldCode, detail: str, raw: object = None) -> None:
        """Build the error from the hold the server named."""
        self.hold = hold
        super().__init__(detail, raw)


def hold_of(status: int | None, raw: object) -> HoldCode | None:
    """The hold a failed response names, or ``None`` when it names none.

    ``raw`` is the response body text (``RineApiError.raw``). Only the two shapes the server
    uses count: a 403 naming the hold in ``error``, and the mint's 400 naming it in ``reason``.
    """
    body = _error_body(raw)
    if body is None:
        return None
    if status == HTTPStatus.FORBIDDEN:
        code = body.get("error")
    elif status == HTTPStatus.BAD_REQUEST and body.get("error") == _MINT_REFUSAL:
        code = body.get("reason")
    else:
        return None
    return _HOLD_CODES.get(code) if isinstance(code, str) else None


def held_mint_error(status: int, detail: str, raw: object) -> PrincipalHeldError | None:
    """The typed error for a token-mint refusal that names a hold, else ``None``.

    Only the mint's 400 is a held mint: a 403 is a bearer route's refusal, which stays an
    ``AuthorizationError`` whose body ``hold_of`` reads.
    """
    hold = hold_of(status, raw) if status == HTTPStatus.BAD_REQUEST else None
    return None if hold is None else PrincipalHeldError(hold, detail, raw)
