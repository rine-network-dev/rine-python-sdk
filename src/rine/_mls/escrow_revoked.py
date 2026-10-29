"""What a revoked principal means for escrow work.

Four different refusals say the same thing, from three places: the branch's escrow key
read answers 410, an upload or an acting route answers 422 with ``branch_revoked`` or
``agent_revoked``, and any bearer route or the token mint answers 401 naming the revoked
agent or branch. Each ends every file's hope: nothing this agent holds can be sealed to or
accepted by the server again. This module maps them onto the one loss they record. A code
counts only on the status the server gives it, so an echo of the code on any other status
is an ordinary refusal.

A 401 names the principal the request was signed as, not the agent being swept. It speaks
for the swept agent only when that agent signed the request itself. For any other bearer it
says nothing about this agent's escrow: :func:`names_other_principal` is true there and the
caller defers instead of giving up, because a give-up deletes the file for good.

The TypeScript twin is ``rine-core/src/mls-escrow-revoked.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.escrow_answer import EscrowCode, escrow_code
from rine._mls.escrow_gap import EscrowLoss
from rine._mls.escrow_keys import BranchRevokedError
from rine._principal import PrincipalKind
from rine.errors import PrincipalRevokedError, RevokedScope, RineApiError, RineError

if TYPE_CHECKING:
    from rine._mls.actor import MlsActor

__all__ = ["names_other_principal", "revoked_loss"]

#: The status of an escrow upload's or an acting route's revocation answer.
HTTP_UNPROCESSABLE = 422

_BY_SCOPE = {
    RevokedScope.AGENT: EscrowLoss.AGENT_REVOKED,
    RevokedScope.BRANCH: EscrowLoss.BRANCH_REVOKED,
}

_BY_CODE = {
    EscrowCode.BRANCH_REVOKED: EscrowLoss.BRANCH_REVOKED,
    EscrowCode.AGENT_REVOKED: EscrowLoss.AGENT_REVOKED,
}


def revoked_loss(exc: Exception) -> EscrowLoss | None:
    """The loss a revocation refusal records, or ``None`` when ``exc`` is not one."""
    if isinstance(exc, BranchRevokedError):
        return EscrowLoss.BRANCH_REVOKED
    if isinstance(exc, PrincipalRevokedError):
        return _BY_SCOPE[exc.scope]
    if isinstance(exc, RineApiError) and exc.status == HTTP_UNPROCESSABLE:
        code = escrow_code(exc)
        return _BY_CODE.get(code) if code is not None else None
    return None


def names_other_principal(actor: MlsActor, exc: Exception) -> bool:
    """True when ``exc`` revokes a principal that is not the agent being swept.

    A client signed as the agent itself speaks for it. A branch, org or reader client does
    not: its revocation says nothing about an agent on another branch, so the file waits.
    """
    if not isinstance(exc, PrincipalRevokedError):
        return False
    try:
        principal = actor.client.principal
    except RineError:
        return True
    return not (principal.kind is PrincipalKind.AGENT and principal.ident == actor.agent_id)
