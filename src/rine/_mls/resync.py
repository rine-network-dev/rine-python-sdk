"""Recovering a group this agent can no longer follow — the ladder, and its rungs.

Two rungs, ordered, cheap one first:

1. **Replay.** The member is merely behind and the server still holds the
   commits it missed. Reads only: no commit, no epoch, nothing billed to anybody
   else. This is :func:`~rine._mls.sync.sync_mls_group` against the replaying
   ``since_epoch`` the server now honours.
2. **Resync.** Replay cannot bridge the gap — the server holds no commit it can
   deliver, or the chain will not apply to this member's state. One external
   commit replaces this agent's own leaf at the current epoch, and it is O(N):
   every member downloads and processes it.

The expensive rung is never the first answer to a three-commit gap, and a caller
that paid for it is told so — :class:`MlsRecoveryResult` names the rung and how
far behind the member was.

What this is *not*: a way back for an agent whose local state is gone. The stale
leaf index comes from the stale handle and from nowhere else, so state that will
not load has no resync at all. The TypeScript twin is
``rine-core/src/mls-ops-resync.ts``, with the same rungs and the same refusal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, Literal

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine._mls.allowed import admit_group_peers
from rine._mls.api import MlsCommit, fetch_group_info
from rine._mls.binding import DEFAULT_CIPHER_SUITE, GroupInactiveError, open_mls_client
from rine._mls.commit import post_mls_commit
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.escrow_settle import settle_escrow
from rine._mls.failures import group_failures, is_epoch_conflict, is_unprocessable_commit
from rine._mls.group_access import load_mls_group, note_mls_state_changed
from rine._mls.heartbeat import MlsActor
from rine._mls.rotated_leaf import MlsRotatedLeafError, admit_refused_peers_for_resync
from rine._mls.sync import sync_mls_group
from rine._mls.sync_api import fetch_group_epochs
from rine._mls.wire import api_error_code
from rine.errors import CryptoError, MlsResyncUnavailableError

if TYPE_CHECKING:
    # Annotation-only, and this module is imported by ``_resources.group_sync``
    # alongside ``_group_recovery`` itself: a runtime import here would pull the
    # recovery vocabulary in through the MLS ladder for a field nothing resolves
    # at run time. Safe because the dataclass below never has its hints read
    # back — no ``get_type_hints`` call exists anywhere in this package.
    from rine._group_recovery import KeyPackageTopUp
    from rine._seat_update import SeatUpdate

#: The server's ``error`` key when a replay cannot carry this agent to the group:
#: it holds no deliverable commit for the gap. The ladder's escalation signal —
#: branch on this code, never on the sentence.
MLS_RESYNC_REQUIRED = "mls_resync_required"

#: Which rung of the ladder a recovery actually took.
MlsRecoveryRung = Literal["replay", "resync"]


def _replay_exhausted(err: BaseException) -> bool:
    """Whether a failed replay is the ladder's signal to pay for the expensive rung.

    Two signals, and only two. The server refusing a replay it cannot serve is
    the explicit one. The other is a protocol-level refusal escaping the replay
    itself: :func:`~rine._mls.sync.sync_mls_group`'s own orphan reconciliation
    re-bootstraps with a plain external join, which MLS refuses for an agent the
    tree already holds (``duplicate signature key, hpke key or identity found at
    index N``, measured) — so a seated member whose tentative commit was
    rolled back reaches exactly this point, and the rung that fixes it is the
    resync. Left unhandled it surfaced a protocol error naming a leaf the
    operator never asked about.

    A **local** failure never escalates: a store, panic or poisoned handle is
    this process's problem, and billing every member an O(N) commit for it would
    be a self-inflicted denial of service. Nor does an eviction — an agent whose
    leaf a Remove commit took has nothing to re-seat.
    """
    if api_error_code(err) == MLS_RESYNC_REQUIRED:
        return True
    return is_unprocessable_commit(err) and not isinstance(err, GroupInactiveError)


def _resync_failure(group_id: str, err: BaseException) -> CryptoError:
    """A resync that was tried and refused, said in rine's own words.

    The core's message alone names no group, no rung and no remedy — it is an
    mls-rs sentence about a protocol state — and handing that to an operator is
    the failure this verb exists to replace. Everything the operator can
    act on comes first; the core's text is kept, last, because it is what
    distinguishes one refusal from another in a bug report.
    """
    return CryptoError(
        f"Recovering MLS group {group_id} failed on the resync rung. Replaying the "
        "commits the server still holds could not carry this agent, and the external "
        "commit that would re-seat its own leaf was refused. A resync recovers stale "
        "or corrupt local state, never absent state: if this agent's state cannot "
        "reach the group's stored epochs at all, ask an admin to remove it from the "
        "group and invite it again — re-admission mints a new leaf and a fresh "
        f"Welcome. The refusal was: {err}"
    )


@dataclass(frozen=True)
class MlsRecoveryResult:
    """Where a recovery left the group, and what it cost to get there."""

    regime: Literal["mls"]
    """Which encryption regime this recovery ran against — the discriminant of
    ``rine._group_recovery.GroupRecoveryResult``. A sender-key group has no
    epoch, no commit, no ratchet tree and no leaf, so it cannot be reported as a
    third value of :data:`MlsRecoveryRung` without faking five of the fields
    below. Declared first and with no default: a discriminant with a default is
    one a future arm can forget to set."""

    rung: MlsRecoveryRung
    """``replay`` costs reads; ``resync`` cost one O(N) commit that every member
    of the group downloads and processes. Reported because an operator who paid
    for the second is entitled to know they did."""

    from_epoch: int
    """The epoch this agent's local state was at before recovery started."""

    epoch: int
    """The epoch it holds now."""

    behind: int | None
    """How many epochs behind the group's **confirmed** epoch this agent was when
    recovery started, or ``None`` when the group published no confirmed GroupInfo
    to measure against."""

    processed: int
    """Commits applied by the replay rung. Zero when replay bridged nothing."""

    evicted: bool
    """True when recovery ended with this agent out of the ratchet tree: a Remove
    commit it replayed evicted it. The backlog it already holds secrets for still
    opens; nothing committed after the Remove ever will."""

    key_packages: KeyPackageTopUp | None = None
    """What the key-package top-up that rode along with this recovery did.

    ``None`` when the recovery was not driven through
    :func:`rine._resources.group_sync.sync_group_state` — this module's own
    ladder publishes nothing. A surface projecting this into JSON omits the key
    rather than emitting a null, the ``mls_never_founded_note`` rule. The
    TypeScript twin is ``keyPackages`` (``rine-core/src/mls-ops-resync.ts``)."""

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What the escrow drains of this recovery (the replayed commits, or the resync
    and the state it replaced) could not do."""

    seat: SeatUpdate | None = None
    """Where moving the agent's leaf to its current key ended; set by ``sync_group_state``."""


def recover_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
) -> MlsRecoveryResult:
    """Catch this agent's MLS state up with its group, on the cheapest rung that works.

    Escalates to the resync rung on exactly three signals, and on nothing else:
    the server refusing the replay it cannot serve, a protocol-level refusal
    escaping the replay itself (:func:`_replay_exhausted`), and a replay that ran
    but left this agent short of the epoch the group was at when recovery
    started. The last is measured against the epoch read *before* the replay, so
    a busy group advancing underneath a healthy catch-up is not mistaken for a
    wedge and billed an O(N) commit for it.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The recovering agent's UUID.
        group_id: The rine group UUID.

    Returns:
        Which rung ran, how far behind this agent was, and where it ended up.

    Raises:
        MlsResyncUnavailableError: This agent's local state will not load at all.
        GroupEvictedError: This agent's leaf is gone from the group's tree.
        MlsRotatedLeafError: This agent rotated its key after it was seated, so its
            old leaf cannot resync.
        CryptoError: The group publishes no GroupInfo to commit against, or a
            competing commit keeps winning the epoch.
    """
    headers = {AGENT_HEADER: agent_id}
    with group_failures(group_id):
        stale = load_mls_group(open_mls_client(config_dir, agent_id), group_id)
        if stale is None:
            raise MlsResyncUnavailableError(group_id)
        from_epoch = stale.epoch()
        # The ONLY source of the stale leaf. Never ``GET /groups/{id}/members``,
        # never a server-supplied index — the server does not know leaf indices.
        stale_leaf = stale.current_member_index()

        target = _confirmed_epoch(client, group_id, headers)
        behind = None if target is None else max(0, target - from_epoch)
        processed = 0
        replay_escrow = EscrowReport()

        try:
            replayed = sync_mls_group(
                client, config_dir, agent_id, group_id, carry_unreported=True
            )
            processed = replayed.processed
            replay_escrow = replayed.escrow
            # An eviction is a settled answer, not a gap: this agent has no leaf
            # to re-seat, so a resync would commit about a leaf that is gone.
            if replayed.evicted or target is None or replayed.epoch >= target:
                return MlsRecoveryResult(
                    regime="mls",
                    rung="replay",
                    from_epoch=from_epoch,
                    epoch=replayed.epoch,
                    behind=behind,
                    processed=processed,
                    evicted=replayed.evicted,
                    escrow=replay_escrow,
                )
        except Exception as err:
            if not _replay_exhausted(err):
                raise

        resynced = _resync_with_retry(client, config_dir, agent_id, group_id, stale_leaf, headers)
        resync_target = resynced.target
        # The up-front measurement is the honest one; this only fills a distance
        # that was unmeasurable before the resync's own GroupInfo read answered it.
        if behind is None and resync_target is not None:
            behind = max(0, resync_target - from_epoch)
        return MlsRecoveryResult(
            regime="mls",
            rung="resync",
            from_epoch=from_epoch,
            epoch=resynced.epoch,
            behind=behind,
            processed=processed,
            evicted=False,
            escrow=replay_escrow.merge(resynced.escrow),
        )


def _confirmed_epoch(client: Any, group_id: str, headers: dict[str, str]) -> int | None:
    """The group's confirmed epoch, or ``None`` when it cannot be read.

    A group with no confirmed GroupInfo, and one whose newest is still awaiting a
    peer ACK, are both unmeasurable rather than wedged — so the distance is
    reported as unknown and the ladder never escalates on a distance it could not
    read. It still escalates on the server's explicit refusal.
    """
    try:
        return fetch_group_epochs(client, group_id, headers).confirmed
    except Exception:
        logger.debug("MLS group-info read failed for group %s", group_id, exc_info=True)
        return None


def _resync_with_retry(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    stale_leaf: int,
    headers: dict[str, str],
) -> _Resynced:
    """Resync, with the single rebuild every commit-posting path in rine gets.

    A resync is an O(N) commit against a group free to move while it is in
    flight, so losing the epoch CAS is expected rather than exceptional. One
    rebuild against a freshly fetched GroupInfo; a second failure is surfaced,
    because retrying forever against an advancing epoch is a self-inflicted
    denial of service — and each attempt bills every member.

    ``stale_leaf`` is reused unchanged across the retry: a leaf index belongs to
    its member until that member is removed, so a peer's commit landing first
    does not move it.
    """
    try:
        return _resync_once(client, config_dir, agent_id, group_id, stale_leaf, headers)
    except Exception as err:
        # Not a lost CAS: the resync itself was refused, and that refusal is the
        # operator's answer rather than a race to rebuild against, so it gets
        # rine's words instead of the core's. An eviction keeps its own
        # vocabulary — ``group_failures`` turns it into a membership fact — and so
        # does a rotated agent's seat.
        if not is_epoch_conflict(err):
            if isinstance(err, GroupInactiveError | MlsRotatedLeafError):
                raise
            raise _resync_failure(group_id, err) from err
        first_error = err
    try:
        return _resync_once(client, config_dir, agent_id, group_id, stale_leaf, headers)
    except Exception as retry_error:
        raise CryptoError(
            f"Resyncing MLS group {group_id} failed after one retry — a peer's commit "
            f"keeps landing first: {retry_error}"
        ) from first_error


@dataclass(frozen=True)
class _Resynced:
    """What one posted resync commit achieved."""

    epoch: int
    target: int | None
    """The epoch the group's GroupInfo named, when it named one."""

    escrow: EscrowReport


def _resync_once(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    stale_leaf: int,
    headers: dict[str, str],
) -> _Resynced:
    """One resync attempt: fetch the current GroupInfo, build the commit, post it.

    The GroupInfo is fetched here rather than reused from the distance
    measurement, because a replay may have advanced the group in between and a
    commit built against a superseded GroupInfo loses the server's epoch CAS.

    No Welcomes: an external commit admits nobody, so the bundle's ``welcomes``
    is empty and the post names no joiners. Local state is adopted only after the
    server accepts, so a refused commit leaves the stale state intact.
    """
    info = fetch_group_info(client, group_id, headers)
    if info.blob is None:
        raise CryptoError(
            f"Cannot resync MLS group {group_id}: it has published no GroupInfo to commit "
            "against. An existing member must publish one first."
        )
    actor = MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)
    # The external commit meets every current leaf, so the chain-verified peers
    # must be admitted before it is built.
    admit_group_peers(actor, group_id)
    mls = open_mls_client(config_dir, agent_id)
    group = admit_refused_peers_for_resync(
        actor, mls, partial(mls.resync_by_external_commit, info.blob, stale_leaf), group_id
    )
    bundle = group.last_commit()
    if bundle is None:  # pragma: no cover - a resync always commits
        raise CryptoError(f"MLS resync for group {group_id} produced no commit")
    epoch = post_mls_commit(
        actor,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=DEFAULT_CIPHER_SUITE,
        ),
        headers,
    )
    settled = settle_escrow(actor, group_id)
    drained = drain_escrow(actor, group_id, group, carry_unreported=True)
    note_mls_state_changed(config_dir, agent_id, group_id)
    return _Resynced(epoch, info.epoch, settled.merge(drained.report()))


__all__ = [
    "MLS_RESYNC_REQUIRED",
    "MlsRecoveryResult",
    "MlsRecoveryRung",
    "recover_mls_group",
]
