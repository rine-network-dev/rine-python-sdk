"""Founding a group's MLS state — the creator side of the group lifecycle.

Initialization is one commit: the founder creates the group, adds every member
the server already holds a KeyPackage for, and publishes the resulting commit,
per-member Welcomes and GroupInfo together. Local state is written only once the
server has accepted that commit, so a rejected init leaves nothing behind to
conflict with the retry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine._logging import logger
from rine._mls.api import MlsCommit, MlsWelcome, claim_key_package, mls_commit, mls_init
from rine._mls.binding import UnreadableKeyPackageError, open_mls_client
from rine._mls.group_access import mls_group_id_bytes
from rine._mls.key_packages import replenish_mls_key_packages
from rine.errors import CryptoError

if TYPE_CHECKING:
    from rine.types import GroupRead


@dataclass(frozen=True)
class MlsInitOutcome:
    """What founding the group's MLS state achieved."""

    epoch: int
    members_added: int


def init_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    extra_headers: dict[str, str],
) -> MlsInitOutcome:
    """Found the MLS state for an existing rine group.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The founding agent's UUID; must be the group's designated admin.
        group_id: The rine group UUID. It is also the MLS group id, so MLS state
            is keyed by the group a user knows rather than by the server's opaque
            ``mls_group_id`` latch.
        extra_headers: Acting-agent headers for the group requests.

    Returns:
        The committed epoch and how many members the init commit added.

    Raises:
        CryptoError: If a member's published KeyPackage cannot be read.
        RineApiError: If the server refuses the init or the commit.
    """
    # Every MLS operation doubles as the heartbeat that keeps this agent's own
    # KeyPackage pool above its low-water mark, so it never becomes un-addable.
    replenish_mls_key_packages(client, config_dir, agent_id)

    members = mls_init(client, group_id, extra_headers)
    mls = open_mls_client(config_dir, agent_id)

    invitees: list[str] = []
    key_packages: list[bytes] = []
    for member in members:
        if not member.has_key_package or member.agent_id.lower() == agent_id.lower():
            continue
        blob = claim_key_package(client, member.agent_id, extra_headers)
        if blob is None:
            # The pool emptied between the readiness report and the claim. The
            # member joins later by invite; founding the group must not block.
            logger.warning(
                "No MLS KeyPackage available for %s — founding the group without them",
                member.agent_id,
            )
            continue
        invitees.append(member.agent_id)
        key_packages.append(blob)

    try:
        group = mls.create_group_with_members(mls_group_id_bytes(group_id), key_packages)
    except UnreadableKeyPackageError as exc:
        raise CryptoError(
            "A member's published MLS KeyPackage cannot be read by this MLS core "
            f"({', '.join(invitees)}). They are running an older rine release: MLS "
            "groups need every participant on the current one. Ask them to upgrade "
            "and republish their KeyPackages, then create the group again."
        ) from exc

    bundle = group.last_commit()
    if bundle is None:  # pragma: no cover - a fresh group always carries its commit
        raise CryptoError("MLS group was founded without an init commit")

    epoch = mls_commit(
        client,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=group.cipher_suite(),
            welcomes=tuple(
                MlsWelcome(agent_id=a, welcome=w)
                for a, w in zip(invitees, bundle.welcomes, strict=True)
            ),
        ),
        extra_headers,
    )

    # Only now: a commit the server refused must leave no local state, so the
    # retry starts from the same place this attempt did.
    group.save()
    return MlsInitOutcome(epoch=epoch, members_added=len(invitees))


def found_mls_state(client: Any, group: GroupRead, agent: str | None) -> None:
    """Found MLS state for a group this SDK just created, best-effort.

    The group exists either way: a failure here leaves it usable by every other
    surface and re-initializable later, so it is reported rather than raised.

    Open-enrollment groups are skipped — the server refuses MLS there, so an
    attempt could only ever fail.
    """
    if group.enrollment_policy == "open":
        return
    try:
        agent_id = client._resolve_agent_id(agent)
        init_mls_group(
            client._http, client._config_dir, agent_id, str(group.id), {"X-Rine-Agent": agent_id}
        )
    except Exception:
        _report_init_failure(group)


async def found_mls_state_async(client: Any, group: GroupRead, agent: str | None) -> None:
    """Async counterpart of :func:`found_mls_state`.

    Only the agent lookup differs from the sync path; the init itself is the same
    function, run on a worker thread.
    """
    from rine._mls.bridge import with_sync_http

    if group.enrollment_policy == "open":
        return
    try:
        agent_id = await client._resolve_agent_id(agent)
        await with_sync_http(
            client,
            lambda http: init_mls_group(
                http, client._config_dir, agent_id, str(group.id), {"X-Rine-Agent": agent_id}
            ),
        )
    except Exception:
        _report_init_failure(group)


def _report_init_failure(group: GroupRead) -> None:
    logger.warning(
        "MLS init failed for group %s — the group was created but has no MLS state "
        "yet; retry it before sending",
        group.handle,
        exc_info=True,
    )
