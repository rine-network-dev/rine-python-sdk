"""Getting into a group's MLS state — the joiner side of the group lifecycle.

Two ways in, tried in that order:

1. **A Welcome**, minted by whoever added this agent. The normal path for closed,
   majority and unanimity enrollment (:mod:`rine._mls.welcomes`).
2. **An external commit**, for a rine member nobody minted a Welcome for — open
   enrollment, where the server admits a joiner with no member in the loop
   (:mod:`rine._mls.external_join`).

Both key local state by the **rine group UUID**, the same key sending and reading
use, so a joined agent can immediately do both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine._mls.api import read_group
from rine._mls.binding import open_mls_client
from rine._mls.external_join import ExternalJoin, external_join_mls_group
from rine._mls.group_access import load_mls_group
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcomes import process_mls_welcomes

if TYPE_CHECKING:
    from rine.types import GroupRead


def install_mls_state(client: Any, config_dir: str, agent_id: str, group: GroupRead) -> None:
    """Establish this agent's local MLS state for a group it belongs to.

    A no-op for a group whose MLS state has not been founded, and for one this
    agent has already joined.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The joining agent's UUID.
        group: The group, read fresh enough to carry its current MLS latch.

    Raises:
        MlsWelcomeRefusedError: A Welcome **for this group** was refused. The
            group substitution guard is the one failure this path does not
            absorb: a client that quietly carried on would fall through to the
            external-join fallback for a group it just decided not to trust.
    """
    if group.mls_group_id is None:
        return
    group_id = str(group.id)
    # A refusal names ONE group, and this call is establishing ONE group's state,
    # so the batch is asked about that group only: a refusal naming it is raised
    # and every other group's is withheld and logged. Both halves are inside
    # ``process_mls_welcomes`` on purpose — leaving the second one here is how the
    # TypeScript twin ended up aborting unrelated reads — and without the first
    # the server chose which refusal survived, by choosing the delivery ids the
    # queue was ordered by (measured, not hypothetical).
    process_mls_welcomes(client, config_dir, agent_id, for_group=group_id)

    mls = open_mls_client(config_dir, agent_id, cipher_suite=group.mls_cipher_suite)
    if load_mls_group(mls, group_id) is not None:
        return
    external_join_mls_group(
        ExternalJoin(
            client=client,
            config_dir=config_dir,
            agent_id=agent_id,
            group_id=group_id,
            extra_headers={AGENT_HEADER: agent_id},
            cipher_suite=group.mls_cipher_suite,
        )
    )


def join_mls_state(client: Any, group_id: str, agent: str | None) -> None:
    """Install MLS state for a group this SDK just joined, best-effort.

    The rine membership stands either way: state can be installed on any later
    read or send, so a failure is reported rather than raised.

    Raises:
        MlsWelcomeRefusedError: The one exception to "best-effort". A refused
            Welcome for **this** group is a security decision, not a setup
            hiccup: carrying on quietly would fall through to the external-join
            fallback for a group this client has just decided not to trust.

            Both stacks are required to be loud AND to agree, so this is
            a contract rather than a stack preference. 🔴 Do not soften it to
            match a TypeScript verb that warns — when the two disagree, the fix
            belongs on the quiet side. (Written because they did disagree: when
            this raise landed, ``rine-core``'s ``processMlsWelcomes`` raised but
            every TypeScript join verb above it caught the refusal and warned.)
    """
    try:
        agent_id = client._resolve_agent_id(agent)
        install_mls_state_by_id(client._http, client._config_dir, agent_id, group_id)
    except MlsWelcomeRefusedError:
        raise
    except Exception:
        _report_join_failure(group_id)


async def join_mls_state_async(client: Any, group_id: str, agent: str | None) -> None:
    """Async counterpart of :func:`join_mls_state`.

    Only the agent lookup differs; the join itself is the same function, run on a
    worker thread.

    Raises:
        MlsWelcomeRefusedError: As :func:`join_mls_state`.
    """
    from rine._mls.bridge import with_sync_http

    try:
        agent_id = await client._resolve_agent_id(agent)
        await with_sync_http(
            client,
            lambda http: install_mls_state_by_id(http, client._config_dir, agent_id, group_id),
        )
    except MlsWelcomeRefusedError:
        raise
    except Exception:
        _report_join_failure(group_id)


def install_mls_state_by_id(client: Any, config_dir: str, agent_id: str, group_id: str) -> None:
    """:func:`install_mls_state` for a caller that holds only the group's id.

    Reads the group first, so the MLS client is opened on the group's *own*
    ciphersuite rather than the current default — a group created on the
    classical suite is therefore still joinable.
    """
    install_mls_state(client, config_dir, agent_id, read_group(client, agent_id, group_id))


def _report_join_failure(group_id: str) -> None:
    logger.warning(
        "MLS setup failed for group %s — this agent is a member, but reading and "
        "sending in the group will keep retrying the setup until it succeeds",
        group_id,
        exc_info=True,
    )
