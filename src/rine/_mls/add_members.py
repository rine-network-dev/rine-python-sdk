"""The add path an existing member runs — and, with it, the resume path.

They are the same verb. Passing every agent a group knows about seats exactly
the ones that are not seated yet, which is what makes a partly-founded group
recoverable without re-initialising it: ``mls_group_id`` is a one-way latch and
``POST /mls/init`` refuses once it is set, so a founding that stopped at commit
5 of 39 had no way forward at all.

Python had **no** member-side add of any kind before this. Every Python join was
a joiner-paid external commit, which costs the whole group the same aggregate
download and gives the invitee no Welcome waiting when they arrive.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._actor import AGENT_HEADER
from rine._mls.admission_loop import run_admission
from rine._mls.admission_state import Admission
from rine._mls.failures import group_failures
from rine._mls.group_access import holds_mls_state, open_mls_group
from rine._mls.heartbeat import MlsActor, mls_heartbeat
from rine._mls.revoked_seats import hold_for_revoked_seats, tree_agent_ids
from rine._mls.tree import fetch_agent_identities, leaf_index, read_group_tree
from rine._mls.welcomes import process_mls_welcomes

if TYPE_CHECKING:
    from rine._mls.admission import MlsAdmissionResult


def _ensure_admitter_state(client: Any, config_dir: str, agent_id: str, group_id: str) -> None:
    """Install a Welcome this agent holds but has never opened, so it can commit.

    An admitter who was themselves admitted by Welcome and has not read the group
    yet holds NO local state, so :func:`open_mls_group` refuses — and every caller
    of the add path treats that as best-effort, which seats the applicant in the
    rine group and leaves them OUTSIDE the MLS one, losing every message until
    they self-heal. That is the ordinary shape of a ``majority`` group, where the
    deciding vote is routinely cast by a member who joined and has not read
    anything yet.

    The decrypt path and the join path both install pending Welcomes before they
    need state; this is that same step, for the admission path. The TypeScript
    twin is ``ensureAdmitterState`` in ``rine-core/src/mls-ops-admit.ts`` and the
    two must keep the same ordering and the same scope.

    Scoped with ``for_group`` because it establishes exactly ONE group's state:
    unscoped, the server picks which refusal is raised through its own response
    ordering, so a substituted Welcome for any other group would abort an
    admission that has nothing to do with it.

    Called BEFORE the group handle is opened, deliberately — the install writes
    through its own client handle, so a handle opened first is not guaranteed to
    see the result.
    """
    if holds_mls_state(config_dir, agent_id, group_id):
        return
    process_mls_welcomes(client, config_dir, agent_id, for_group=group_id)


def add_mls_group_members(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    member_agent_ids: list[str],
    extra_headers: dict[str, str] | None = None,
) -> MlsAdmissionResult:
    """Seat agents in an established group's ratchet tree, in batched commits.

    Already-seated ids and this agent's own are **reported, not refused** — that
    is what makes the call a resume: run it twice and the second run adds
    nobody and says so per member.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The acting agent's UUID; it must be a member of the group and
            hold its MLS state.
        group_id: The rine group UUID.
        member_agent_ids: Agents to seat, in the order they should be admitted.
        extra_headers: Acting-agent headers for the group requests.

    Returns:
        The epoch reached, how many commits it took, and one outcome per
        requested id in request order.

    Raises:
        NoMlsGroupStateError: This agent holds no local state for the group.
        GroupEvictedError: This agent's own leaf is gone from the group, so it
            can admit nobody to it.
        RineApiError: The server refused a commit for a reason that dropping the
            recipients it named cannot fix.
    """
    headers = dict(extra_headers or {AGENT_HEADER: agent_id})
    # Forced rather than gated: this admission is about to spend key packages.
    # Each member's own pool is theirs to top up — a client can only publish key
    # packages for an agent whose signing key it holds.
    mls_heartbeat(MlsActor(client=client, config_dir=config_dir, agent_id=agent_id), "forced")

    with group_failures(group_id):
        # An admitter that has never opened its own Welcome holds no state at
        # all, and the seat below is best-effort for every caller — so establish
        # it here rather than fail silently and leave the applicant outside.
        _ensure_admitter_state(client, config_dir, agent_id, group_id)
        tree = read_group_tree(client, group_id, headers)
        group = open_mls_group(config_dir, agent_id, group_id)
        admission = Admission(
            client=client,
            config_dir=config_dir,
            agent_id=agent_id,
            group_id=group_id,
            extra_headers=headers,
            group=group,
            saved=True,
            epoch=group.epoch(),
        )

        wanted = requested_ids(member_agent_ids, agent_id, admission)
        # The de-duplicated REQUEST order, self included — not just the ids that
        # went on to be admitted, or the acting agent's own outcome would sort to
        # the end instead of to where the caller named it.
        admission.order = list(dict.fromkeys(a.lower() for a in member_agent_ids))
        identities = fetch_agent_identities(
            client, list(dict.fromkeys([*wanted, *tree_agent_ids(group)]))
        )
        candidates: list[str] = []
        for member in wanted:
            identity = identities.get(member.lower())
            if identity is not None and leaf_index(group, identity) is not None:
                admission.skip(member, "already_in_group")
            else:
                candidates.append(member)
        candidates = hold_for_revoked_seats(admission, group, candidates, identities)

        # The tree already counts an agent this call is about to seat when that
        # agent holds an invitation — a voucher takes its seat the moment it is
        # minted — so those come back out of the occupancy, or every batch is
        # sized against a tree that has not been built yet. A candidate the tree
        # does not know about was never in it and must not be subtracted. Never
        # below 1: the acting agent itself is always seated.
        unbuilt = sum(1 for c in candidates if c.lower() in tree.ids)
        seated = max(1, tree.occupancy - unbuilt)
        if not tree.outstanding_known:
            # The outstanding population could not be read, so ``occupancy``
            # counts members alone and under-states the tree — and a batch is
            # sized from it. Under-stating it does not mint a POST the server
            # refuses, but it does mint one several times the budget that keeps
            # founding responsive: a resume over a group with 2 members and 300
            # unread invitations would size at 32 and weigh ~21 MB against an
            # 8 MiB budget. Assume instead that every candidate is already in
            # the tree, which is the shape a resume actually has and is never an
            # under-estimate.
            seated = max(seated, len(candidates))
        return run_admission(admission, candidates, seated)


def requested_ids(
    member_agent_ids: list[str], agent_id: str, admission: Admission | None = None
) -> list[str]:
    """The caller's ids, de-duplicated, in order, without this agent's own.

    A repeated id would consume a second one-time KeyPackage and mint a second
    leaf for one agent, and the two are not distinguishable by identity.

    The ids dropped here are still **reported**, as ``already_in_group``, when
    an ``admission`` is given. The contract is "one outcome per requested id, in
    request order"; dropping the acting agent and the duplicates silently made
    ``len(outcomes)`` one short of the TypeScript twin's for the very same
    operation — ``/mls/init``'s roster includes the founder — so any surface
    rendering "seated X of N" printed a different denominator per language.
    """
    self_key = agent_id.lower()
    seen: set[str] = {self_key}
    reported: set[str] = set()
    wanted: list[str] = []
    for member in member_agent_ids:
        key = member.lower()
        if key in seen:
            # The acting agent is always in its own group. A repeat of anyone
            # else already has its outcome from the first occurrence; recording
            # a second would break "one outcome per requested id".
            if admission is not None and key == self_key and key not in reported:
                reported.add(key)
                admission.skip(member, "already_in_group")
            continue
        seen.add(key)
        wanted.append(member)
    return wanted


__all__ = ["add_mls_group_members", "requested_ids"]
