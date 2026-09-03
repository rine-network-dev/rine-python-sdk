"""Founding a group's MLS state — the creator side of the group lifecycle.

Founding is the ``seated = 1`` entry point of the shared admission loop
(:mod:`rine._mls.admission_loop`): the founder creates the group, and every
agent the server reports as admissible is seated in batches sized to the tree
they join. Local state is written only once the server has accepted a commit,
so a rejected commit leaves nothing behind to conflict with the retry.

Before this it was **one** commit carrying every Welcome, which the server's
32-Welcome cap put a hard ceiling on: founding a group of 34 failed outright,
and there was no add path to finish what the commit could not carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine._mls.add_members import requested_ids
from rine._mls.admission import MlsAdmissionResult
from rine._mls.admission_loop import run_admission
from rine._mls.admission_state import Admission
from rine._mls.api import mls_init
from rine._mls.heartbeat import MlsActor, mls_heartbeat
from rine.types import MlsInitFailure

if TYPE_CHECKING:
    from rine.types import GroupRead


def init_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    extra_headers: dict[str, str],
) -> MlsAdmissionResult:
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
        The epoch reached, how many commits it took, and one outcome per agent
        the founding roster named — the same answer
        :func:`rine._mls.add_members.add_mls_group_members` gives, because it is
        the same loop.

    Raises:
        CryptoError: If a member's published KeyPackage cannot be read.
        RineApiError: If the server refuses the init or a commit.
    """
    # Forced rather than gated: founding is about to spend key packages, and the
    # founder's own pool is the one no other member can top up.
    mls_heartbeat(MlsActor(client=client, config_dir=config_dir, agent_id=agent_id), "forced")

    roster = mls_init(client, group_id, extra_headers)
    admission = Admission(
        client=client,
        config_dir=config_dir,
        agent_id=agent_id,
        group_id=group_id,
        extra_headers=extra_headers,
    )
    admission.order = [
        m.agent_id.lower() for m in roster if m.agent_id.lower() != agent_id.lower()
    ]
    candidates = requested_ids([m.agent_id for m in roster if m.has_key_package], agent_id)
    for member in roster:
        if not member.has_key_package and member.agent_id.lower() != agent_id.lower():
            # The server holds nothing to add them with. Reported rather than
            # raised: the group founds, and they are seated by a later add.
            admission.skip(member.agent_id, "no_key_package")
    # The founder alone. Every other agent on the roster is a joiner, whether it
    # is already a member or holds an invitation nobody has accepted yet — an
    # invitee's leaf is committed before they join, which is the whole point.
    return run_admission(admission, candidates, 1)


@dataclass(frozen=True)
class MlsInitReport:
    """What founding a created group's MLS state achieved, for the caller.

    ``create`` cannot re-derive this from the group it holds: the create response
    predates the init, and a swallowed failure looks exactly like a policy skip.
    """

    attempted: bool
    failure: MlsInitFailure | None = None
    admission: MlsAdmissionResult | None = None
    """Per-member outcomes, when the init ran and landed.

    A roster is admitted in batches and a member can be skipped without the
    founding failing, so "the init landed" and "everybody got a leaf" are two
    different facts and a caller that only learns the first cannot tell a
    complete group from a partial one.
    """

    @property
    def landed(self) -> bool:
        """Whether MLS state was actually founded — the create re-read's gate."""
        return self.attempted and self.failure is None


_NOT_ATTEMPTED = MlsInitReport(attempted=False)  # a skipped founding, never a failed one


def found_mls_state(
    client: Any, group: GroupRead, agent: str | None, *, enable_mls: bool | None
) -> MlsInitReport:
    """Found MLS state for a group this SDK just created, best-effort.

    The group exists either way: a failure here leaves it usable by every other
    surface and re-initializable later, so it is reported rather than raised.

    Two things skip the founding, and neither is a failure: ``enable_mls=False``,
    the caller asking for a sender-key group outright, and open enrollment, where
    the server refuses MLS so an attempt could only ever fail. This function is
    the one place both are stated — the same single expression
    ``rine-ts-sdk/src/resources/groups-create.ts`` calls ``skipMls`` — and
    callers read the report rather than re-deriving either rule.
    """
    if enable_mls is False or group.enrollment_policy == "open":
        return _NOT_ATTEMPTED
    try:
        agent_id = client._resolve_agent_id(agent)
        admission = init_mls_group(
            client._http, client._config_dir, agent_id, str(group.id), {AGENT_HEADER: agent_id}
        )
    except Exception as exc:
        return _report_init_failure(group, exc)
    return MlsInitReport(attempted=True, admission=admission)


async def found_mls_state_async(
    client: Any, group: GroupRead, agent: str | None, *, enable_mls: bool | None
) -> MlsInitReport:
    """Async counterpart of :func:`found_mls_state`.

    Only the agent lookup differs from the sync path; the init itself is the same
    function, run on a worker thread.
    """
    from rine._mls.bridge import with_sync_http

    if enable_mls is False or group.enrollment_policy == "open":
        return _NOT_ATTEMPTED
    try:
        agent_id = await client._resolve_agent_id(agent)
        admission = await with_sync_http(
            client,
            lambda http: init_mls_group(
                http, client._config_dir, agent_id, str(group.id), {AGENT_HEADER: agent_id}
            ),
        )
    except Exception as exc:
        return _report_init_failure(group, exc)
    return MlsInitReport(attempted=True, admission=admission)


def _report_init_failure(group: GroupRead, exc: Exception) -> MlsInitReport:
    logger.warning(
        "MLS init failed for group %s — the group was created but has no MLS state "
        "yet; retry it before sending",
        group.handle,
        exc_info=True,
    )
    # An exception with no message still has to say something, so fall back to
    # its class name.
    return MlsInitReport(
        attempted=True, failure=MlsInitFailure(reason=str(exc) or type(exc).__name__)
    )
