"""Admitting the history generations of one agent into an allowed set.

An old epoch can still hold a rotated agent's superseded leaf, so every chain-verified
generation below the current one is inserted, and nothing is ever removed. A generation that
does not verify, or whose leaf key equals another generation's, is skipped rather than fatal.

The TypeScript twin is ``admitHistory`` in ``rine-core/src/mls-allowed-history.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._crypto._agent_keys import get_agent_keys_sync
from rine._crypto.certs import ChainError
from rine._mls.binding import AllowedGenerationConflictError, credential_identity

if TYPE_CHECKING:
    from rine._mls.binding import AllowedIdentities
    from rine._mls.heartbeat import MlsActor


def admit_history(
    actor: MlsActor, allowed: AllowedIdentities, agent_id: str, key_gen: int
) -> bool:
    """Insert every chain-verified generation of ``agent_id`` below ``key_gen``.

    A generation that fails the chain is skipped, never fatal: an old leaf can still sit in
    a tree this device has to read, but a generation the server cannot prove is not one this
    client will accept. So is one whose leaf key equals another generation of the same agent
    (the server refuses that at rotation, and if one reaches a client anyway it must not
    abort the admission of the agent's other, valid generations); the set keeps the first
    pair it was given, which is the current one. Any other error (network, malformed
    response, any other refusal of an insert) is a real failure and propagates.

    Returns:
        Whether any generation went in.
    """
    admitted = False
    for gen in range(key_gen):
        history = _verified_generation(actor, agent_id, gen)
        if history is None:
            continue
        try:
            allowed.insert(credential_identity(agent_id), history, gen)
        except AllowedGenerationConflictError:
            continue
        admitted = True
    return admitted


def _verified_generation(actor: MlsActor, agent_id: str, gen: int) -> bytes | None:
    """A peer's history generation's leaf key, or ``None`` when it does not chain."""
    try:
        return get_agent_keys_sync(actor.client, agent_id, gen=gen)[0].mls_public_key
    except ChainError:
        return None


__all__ = ["admit_history"]
