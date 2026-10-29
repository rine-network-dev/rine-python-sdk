"""Admitting peers into the acting agent's MLS allowed set.

The native core refuses any credential outside the ``AllowedIdentities`` set a
client is opened with, so a group with a peer on another device can never be
joined until that peer's chain-verified ``(agent id, leaf key)`` pair is in the
set. This module is what puts it there.

Two rules shape it:

* **Every verified generation is inserted, and nothing is ever removed.** An old
  epoch can still hold a rotated or revoked agent's superseded leaf, so the
  current generation alone is not enough to read it. A successor leaf is accepted
  only for the same agent and a strictly newer generation.
* **A generation whose chain does not verify is skipped, never fatal.** An old
  leaf can still sit in a tree, but a generation the server cannot prove is not
  one this client will accept. Any other error (network, malformed response) is
  a real failure and propagates.

The TypeScript twin is ``rine-core/src/mls-allowed.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from rine._actor import AGENT_HEADER
from rine._crypto.keys import agent_keys_exist, load_agent_keys
from rine._logging import logger
from rine._mls.allowed_history import admit_history
from rine._mls.binding import allowed_for, credential_identity
from rine._mls.tree import fetch_verified_batch_keys, read_group_tree
from rine.errors import RineApiError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._mls.heartbeat import MlsActor
    from rine._mls.tree import GroupTree


def admit_peers(
    actor: MlsActor, agent_ids: Iterable[str], *, include_self_history: bool = False
) -> list[str]:
    """Chain-verify the peers and insert every verified generation.

    A peer that does not verify is skipped — never inserted — and so is a
    history generation that does not verify. Every generation that DOES verify is
    inserted, because an old leaf can still sit in the ratchet tree of an epoch
    this device has to read, and entries are never removed.

    An agent whose keys live on this device keeps its current pair from disk, which
    the seeded set already holds, so that pair is not fetched. Its older
    generations are: an old epoch can still carry a rotated agent's superseded
    leaf, and a fresh process holds only the current pair, so without them it
    would refuse that agent's commits and the Welcomes built on its old leaf.
    A gen-0 local agent costs no read.

    The acting agent's own older generations are left out unless
    ``include_self_history`` asks for them: a leaf sealed to its superseded key
    installs a seat this agent can read but never write, because its signer is the
    current key and the leaf holds the old one.

    Args:
        actor: Who is acting, and through which client.
        agent_ids: The peers to admit, in any case.
        include_self_history: Also admit the acting agent's own history generations.

    Returns:
        The lower-case canonical ids that were inserted.

    Raises:
        ChainError: Never — a chain failure skips the entry.
        Exception: Any other read failure propagates.
    """
    allowed = allowed_for(actor.config_dir, actor.agent_id)
    inserted: list[str] = []
    peers: list[str] = []
    for agent_id in agent_ids:
        if not agent_keys_exist(actor.config_dir, agent_id):
            peers.append(agent_id)
            continue
        if agent_id.lower() == actor.agent_id.lower() and not include_self_history:
            continue
        key_gen = load_agent_keys(actor.config_dir, agent_id).key_gen
        if admit_history(actor, allowed, agent_id.lower(), key_gen):
            inserted.append(agent_id.lower())
    for agent_id, keys in fetch_verified_batch_keys(actor.client, peers).items():
        allowed.insert(credential_identity(agent_id), keys.mls_public_key, keys.key_gen)
        inserted.append(agent_id)
        admit_history(actor, allowed, agent_id, keys.key_gen)
    return inserted


def _admit_tree(actor: MlsActor, tree: GroupTree) -> None:
    admit_peers(actor, sorted({*tree.member_ids, *tree.outstanding_ids}))


def admit_group_peers(actor: MlsActor, group_id: str) -> None:
    """Admit everyone the server says may hold a leaf in this group.

    The wider ``outstanding`` set is deliberate here — unlike the admit set of a
    batch, this is the population that may already occupy a leaf, and a leaf this
    client cannot name is a message it cannot read. Errors from the tree read
    propagate: an unreadable tree means the population is unknown, and admitting
    a partial one would silently drop peers.

    Args:
        actor: Who is acting, and through which client.
        group_id: The rine group id.

    Raises:
        Exception: Whatever the tree read or a peer's key read raises.
    """
    _admit_tree(actor, read_group_tree(actor.client, group_id, {AGENT_HEADER: actor.agent_id}))


WelcomeAdmission = Literal["admitted", "not-seated", "group-gone", "unreachable"]
"""What a group's roster said when a Welcome's peers were admitted — never a bool.

``not-seated`` (403): this agent holds no seat it can read the roster with. An
invitation it has not accepted yet is the ordinary case: the Welcome was minted at
invite time, and accepting later needs those exact bytes. ``group-gone`` (404):
the group no longer exists. ``unreachable``: anything else — a network failure, a
5xx, a peer key read that failed — which the next pass may clear. The TypeScript
twin (``mls-welcome-admission.ts`` ``WelcomeAdmission``) has the same four values.
"""


WELCOME_VERIFICATION_LIMIT = 64
"""How many members one Welcome open may chain-verify beyond the roster it was admitted against.

An honest Welcome misses only the members seated or removed since the roster read. Its
tree is not authenticated before the leaves are checked, so a forger could name agents
without end; a Welcome that needs more than this is unusable.
"""


def admit_welcome_peers(actor: MlsActor, group_id: str) -> WelcomeAdmission:
    """:func:`admit_group_peers` for a Welcome about to be opened, answer classified.

    Only the roster read is classified as definitive: a 403 or 404 from a peer's key
    read says nothing about this agent's place in the group, so a failure after the
    roster was read is ``unreachable``.

    Args:
        actor: Who is acting, and through which client.
        group_id: The rine group id.

    Returns:
        Which of the four answers the roster gave.
    """
    try:
        tree = read_group_tree(actor.client, group_id, {AGENT_HEADER: actor.agent_id})
    except Exception as err:
        if isinstance(err, RineApiError) and err.status == 403:
            return "not-seated"
        if isinstance(err, RineApiError) and err.status == 404:
            return "group-gone"
        logger.warning("Could not read the roster of group %s", group_id, exc_info=True)
        return "unreachable"
    try:
        _admit_tree(actor, tree)
    except Exception:
        logger.warning("Could not admit the peers of group %s", group_id, exc_info=True)
        return "unreachable"
    return "admitted"


__all__ = [
    "WELCOME_VERIFICATION_LIMIT",
    "WelcomeAdmission",
    "admit_group_peers",
    "admit_peers",
    "admit_welcome_peers",
]
