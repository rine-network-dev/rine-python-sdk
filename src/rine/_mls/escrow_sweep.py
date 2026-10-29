"""The group-less escrow sweep: backlog snapshots and every pending file.

A pending file outlives the group state it was sealed from, and a state set aside
by a wipe (:mod:`rine._mls.escrow_snapshots`) holds exports nobody sealed yet. A
drain can only see the group it holds, so this sweep is the one that clears both:
it reopens each backlog snapshot (:mod:`rine._mls.escrow_backlog`), seals what it
holds, then uploads every pending file, resolving each by the server's answer as
:func:`rine._mls.escrow_upload.upload_files` does. One snapshot that fails never
keeps the pending files from going up.

It runs at most once per :data:`rine._constants.MLS_HEARTBEAT_MIN_INTERVAL_S` for
one (config dir, agent) in one process, never inside a drain: from the MLS
heartbeat, and once at client start-up when ``escrow-pending/`` or
``escrow-backlog/`` is not empty (:func:`startup_escrow_sweep`). A 429, a 5xx or a
network failure ends the pass and keeps every file; a file's own retry schedule
(:mod:`rine._mls.escrow_retry`) decides when it is tried again. A revoked branch or a
revoked agent is the one key failure that ends every file's hope: each snapshot and
pending file is deleted after a gap marker records its epochs. A 401 revoking some other
principal than the swept agent (a branch or org client's bearer) defers instead: it says
nothing about that agent's files. The epochs a pass lost are
left in :mod:`rine._mls.escrow_handoff` for the next drain or sync result to report. The gate is
stamped before the pass, so a pass that failed is not repeated until the next
interval.

The TypeScript twin is ``rine-core/src/mls-escrow-sweep.ts``.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._constants import MLS_HEARTBEAT_MIN_INTERVAL_S
from rine._crypto.derive import UUID_RE
from rine._crypto.keys import load_agent_keys
from rine._logging import logger
from rine._mls.actor import MlsActor
from rine._mls.escrow_backlog import BacklogResult, give_up_snapshots, process_backlog
from rine._mls.escrow_gap import LocatedGap
from rine._mls.escrow_handoff import note_unreported
from rine._mls.escrow_keys import resolve_escrow_key
from rine._mls.escrow_report import EscrowReport
from rine._mls.escrow_revoked import names_other_principal, revoked_loss
from rine._mls.escrow_scratch import clear_scratch
from rine._mls.escrow_snapshots import list_snapshots
from rine._mls.escrow_store import PENDING_NAME_RE, group_dirs, list_pending
from rine._mls.escrow_upload import Upload, give_up_files, upload_files
from rine.errors import RineError

if TYPE_CHECKING:
    from typing import Any

#: When the sweep last started per ``(config dir, agent)``, process-wide and monotonic.
_last_sweep: dict[tuple[str, str], float] = {}


@dataclass(frozen=True, slots=True)
class SweepOutcome:
    """What one sweep did: the snapshots it reopened and the files it uploaded."""

    backlog: BacklogResult
    upload: Upload

    def report(self) -> EscrowReport:
        """The epochs this sweep recorded as lost, as the typed record results carry."""
        return EscrowReport(gaps=(*self.backlog.gaps, *self.upload.gaps))

    @property
    def located(self) -> tuple[LocatedGap, ...]:
        """The same epochs with the group each belongs to."""
        return (*self.backlog.located, *self.upload.located)


def has_escrow_work(config_dir: str, agent_id: str) -> bool:
    """True when this agent has a pending file or a backlog snapshot to clear.

    Reads file names only: the heartbeat asks on every beat, and a pending file
    is read in full by :func:`rine._mls.escrow_store.list_pending`.
    """
    for _, directory in group_dirs(config_dir, agent_id):
        try:
            if any(PENDING_NAME_RE.fullmatch(name) for name in os.listdir(directory)):
                return True
        except OSError:
            continue
    return bool(list_snapshots(config_dir, agent_id))


def _handed_off(actor: MlsActor, outcome: SweepOutcome) -> SweepOutcome:
    """Leave the epochs this sweep lost for the next drain or sync result to report."""
    note_unreported(actor.config_dir, actor.agent_id, outcome.located)
    return outcome


def sweep_pending_escrow(actor: MlsActor, *, now: float | None = None) -> SweepOutcome | None:
    """Clear the backlog, then upload every due pending file, once per heartbeat interval.

    Best effort: with nothing to do, or inside the interval, it makes no call, and
    a key that cannot be verified leaves every file where it is.

    Returns:
        What the sweep did, or ``None`` when it did not run or could not start.
    """
    if not has_escrow_work(actor.config_dir, actor.agent_id):
        return None
    gate = (actor.config_dir, actor.agent_id)
    clock = time.monotonic()
    previous = _last_sweep.get(gate)
    if previous is not None and clock - previous < MLS_HEARTBEAT_MIN_INTERVAL_S:
        return None
    _last_sweep[gate] = clock
    clear_scratch(actor.config_dir, actor.agent_id)
    try:
        key = resolve_escrow_key(actor)
        keys = load_agent_keys(actor.config_dir, actor.agent_id)
    except RineError as exc:
        loss = None if names_other_principal(actor, exc) else revoked_loss(exc)
        if loss is None:
            logger.debug("MLS escrow sweep deferred: no verified branch escrow key", exc_info=True)
            return None
        return _handed_off(
            actor,
            SweepOutcome(
                give_up_snapshots(actor, loss),
                give_up_files(actor, list_pending(actor.config_dir, actor.agent_id), loss),
            ),
        )
    backlog = process_backlog(actor, key, keys, now=now)
    files = list_pending(actor.config_dir, actor.agent_id)
    uploaded = upload_files(actor, files, key, keys, due_only=True, now=now)
    return _handed_off(actor, SweepOutcome(backlog, uploaded))


def agents_with_escrow_work(config_dir: str, only_agent_id: str | None = None) -> list[str]:
    """Every agent of this config dir that holds a pending file or a backlog snapshot.

    Directory reads only, so a caller can decide whether a sweep is worth starting
    (an async client skips its worker thread when this is empty). ``only_agent_id``
    limits the answer to that one agent.
    """
    try:
        names = sorted(os.listdir(os.path.join(config_dir, "keys")))
    except OSError:
        return []
    return [
        n
        for n in names
        if UUID_RE.fullmatch(n)
        and (only_agent_id is None or n == only_agent_id)
        and has_escrow_work(config_dir, n)
    ]


def startup_escrow_sweep(http: Any, config_dir: str, only_agent_id: str | None = None) -> None:
    """Sweep the agents of this config dir that hold escrow work; never raises.

    Called when a client starts, so files a previous process left behind (a leave
    or a recovery ends the process that wrote them) are not stranded until the
    first MLS operation. ``only_agent_id`` limits the pass to the one agent the
    client's principal can act as: an agent principal acts as itself and no other,
    so a sibling's files would only draw refusals that count against their retry
    budget.
    """
    for agent_id in agents_with_escrow_work(config_dir, only_agent_id):
        try:
            sweep_pending_escrow(MlsActor(http, config_dir, agent_id))
        except Exception:
            logger.debug("MLS escrow start-up sweep failed for agent %s", agent_id, exc_info=True)


def reset_escrow_sweep_gate() -> None:
    """Forget every gate. Test-only: a process boundary is what clears it in life."""
    _last_sweep.clear()
