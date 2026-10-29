"""Establishing a seated agent's local MLS state, and what a join's 409 makes of it.

The one place that decides how an agent that is seated in a group gets state for it:
a Welcome first, its own seat retaken second, an external join last
(:mod:`rine._mls.welcomes`, :mod:`rine._recover_reseat`, :mod:`rine._mls.external_join`).
The TypeScript twin is ``establishMlsMembership`` in ``rine-core/src/mls-join-establish.ts``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine._mls.api import read_group
from rine._mls.binding import NoSeatToReplaceError, PeerNotAdmittedError, open_mls_client
from rine._mls.external_join import ExternalJoin, external_join_mls_group
from rine._mls.group_access import holds_mls_state, load_mls_group
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine._mls.stranded_seat import welcome_kept
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcomes import process_mls_welcomes
from rine._mls.wire import api_error_code
from rine._recover_reseat import ReseatStatus, retake_seat
from rine._resources.group_ops import unwrap_items
from rine.errors import ConflictError, CryptoError
from rine.types import GroupMember


class MlsEstablishment(StrEnum):
    """What :func:`establish_mls_membership` did for one group."""

    NOT_MLS = "not_mls"
    HELD = "held"
    INSTALLED = "installed"
    RESEATED = "reseated"
    EXTERNAL_JOINED = "external_joined"
    FAILED = "failed"


_ESTABLISHED = (
    MlsEstablishment.INSTALLED,
    MlsEstablishment.RESEATED,
    MlsEstablishment.EXTERNAL_JOINED,
)


def is_already_a_member(err: BaseException) -> bool:
    """Whether ``err`` is the server's 409 for an agent the group already seats."""
    return isinstance(err, ConflictError) and api_error_code(err) == "already_a_member"


def establish_mls_state(
    http: Any, config_dir: str, agent_id: str, group_id: str
) -> MlsEstablishment:
    """Get this agent's local MLS state for a group it is seated in, in this order.

    1. Not an MLS group: nothing to do.
    2. A Welcome for this group, scoped. State that loads after it is installed; a
       Welcome kept on the spool stops the ladder, because replacing the leaf would
       orphan the KeyPackage it is sealed to.
    3. The agent's own seat, retaken by external commit.
    4. An external-commit join, for an agent the tree holds no leaf for.

    Any failure other than a refusal for this group is warned about and reported as
    :attr:`MlsEstablishment.FAILED`: the rine membership stands either way.

    Raises:
        MlsWelcomeRefusedError: A Welcome **for this group** was refused, or the tree holds
            a member this agent cannot verify (``peer_not_admitted``). A security decision,
            not a setup hiccup: carrying on quietly would fall through to the external join
            for a group this client has just decided not to trust. Both stacks are required
            to be loud AND to agree.
    """
    try:
        return _establish(http, config_dir, agent_id, group_id)
    except MlsWelcomeRefusedError:
        raise
    except Exception:
        report_join_failure(group_id)
        return MlsEstablishment.FAILED


def _establish(http: Any, config_dir: str, agent_id: str, group_id: str) -> MlsEstablishment:
    group = read_group(http, agent_id, group_id)
    if group.mls_group_id is None:
        return MlsEstablishment.NOT_MLS
    group_id = str(group.id)
    held = load_mls_group(open_mls_client(config_dir, agent_id), group_id) is not None
    process_mls_welcomes(http, config_dir, agent_id, for_group=group_id)
    if load_mls_group(open_mls_client(config_dir, agent_id), group_id) is not None:
        return MlsEstablishment.HELD if held else MlsEstablishment.INSTALLED
    if welcome_kept(config_dir, agent_id, group_id):
        raise CryptoError("a Welcome for this group is kept for a later attempt")
    try:
        reseat = retake_seat(http, config_dir, agent_id, group_id)
    except NoSeatToReplaceError:
        pass
    except PeerNotAdmittedError as err:
        raise peer_not_admitted_refusal(group_id) from err
    else:
        if reseat.status is not ReseatStatus.RESEATED:
            raise CryptoError(reseat.reason or f"the seat in group {group_id} was not retaken")
        return MlsEstablishment.RESEATED
    external_join_mls_group(
        ExternalJoin(
            client=http,
            config_dir=config_dir,
            agent_id=agent_id,
            group_id=group_id,
            extra_headers={AGENT_HEADER: agent_id},
        )
    )
    return MlsEstablishment.EXTERNAL_JOINED


def member_after_conflict(
    client: Any, err: BaseException, group_id: str, agent: str | None
) -> GroupMember | None:
    """This agent's member row, when ``err`` is a 409 whose seat it then established.

    ``None`` means the 409 stands: it is not the existing-member answer, the agent's state
    loads already, the acting agent cannot be resolved, nothing was established, or the
    roster cannot be read or does not list the agent.

    Raises:
        MlsWelcomeRefusedError: As :func:`establish_mls_state`.
    """
    if not is_already_a_member(err):
        return None
    try:
        agent_id = client._resolve_agent_id(agent)
    except Exception:
        return None  # the 409 stands: a failed actor lookup must not replace it
    return _member_after_conflict(client._http, client._config_dir, agent_id, group_id)


async def member_after_conflict_async(
    client: Any, err: BaseException, group_id: str, agent: str | None
) -> GroupMember | None:
    """Async counterpart of :func:`member_after_conflict`, run on a worker thread."""
    from rine._mls.bridge import with_sync_http

    if not is_already_a_member(err):
        return None
    try:
        agent_id = await client._resolve_agent_id(agent)
    except Exception:
        return None  # the 409 stands: a failed actor lookup must not replace it
    return await with_sync_http(
        client, lambda http: _member_after_conflict(http, client._config_dir, agent_id, group_id)
    )


def _member_after_conflict(
    http: Any, config_dir: str, agent_id: str, group_id: str
) -> GroupMember | None:
    if holds_mls_state(config_dir, agent_id, group_id):
        return None
    if establish_mls_state(http, config_dir, agent_id, group_id) not in _ESTABLISHED:
        return None
    try:
        rows = unwrap_items(
            http.get(f"/groups/{group_id}/members", extra_headers={AGENT_HEADER: agent_id})
        )
        members = [GroupMember.model_validate(row) for row in rows]
    except Exception:
        # The seat is on the server and the state is local, but no member row came back
        # to report, so the 409 stands.
        return None
    return next((m for m in members if str(m.agent_id) == agent_id.lower()), None)


def report_join_failure(group_id: str) -> None:
    logger.warning(
        "MLS setup failed for group %s — this agent is a member, but reading and "
        "sending in the group will keep retrying the setup until it succeeds",
        group_id,
        exc_info=True,
    )
