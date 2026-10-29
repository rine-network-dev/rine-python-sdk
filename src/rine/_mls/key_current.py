"""Whether the key this device holds is the key the agent publishes now.

Two things must never run from a device holding a superseded generation: a self-update,
which would only move a leaf to that stale key, and a key-package drain, which would replace
the agent's published pool with packages the server refuses. Both ask this one question,
chain-verified, so no copy of the predicate exists.

The TypeScript twin is ``diskKeyIsCurrent`` in ``rine-core/src/mls-key-current.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._actor import AGENT_HEADER
from rine._crypto.keys import load_agent_keys
from rine._mls.tree import fetch_verified_batch_keys

if TYPE_CHECKING:
    from rine._mls.actor import MlsActor


def disk_key_is_current(actor: MlsActor) -> bool:
    """True when the disk keys' generation and MLS public key equal the agent's current ones.

    The published keys are read chain-verified. A read that fails propagates: a caller that
    cannot tell "not current" from an outage must not report either.
    """
    keys = load_agent_keys(actor.config_dir, actor.agent_id)
    published = fetch_verified_batch_keys(
        actor.client, [actor.agent_id], {AGENT_HEADER: actor.agent_id}
    )
    current = published.get(actor.agent_id.lower())
    return (
        current is not None
        and current.key_gen == keys.key_gen
        and current.mls_public_key == keys.mls.public_key
    )
