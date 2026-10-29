"""The store of old-state snapshots a settle set aside for the sweep.

A deferred drain leaves untaken exports only in the stored snapshot. When that
state is about to be wiped or replaced and no verified escrow key is at hand,
the settle cannot seal them (it may not wait on the network), so it copies the
state file here, with the protection a live one has (a 0600 file in a 0700 dir),
and the sweep reopens, seals and deletes it later.

Layout under :func:`rine._config.mls_store_dir` (the store root the live state
lives in)::

    escrow-backlog/<group_id>/<epoch>.snapshot           a copy of groups/<hex>/state.bin
    escrow-backlog/<group_id>/<epoch>-<8 hex>.snapshot   a second state parked at the same epoch
    escrow-backlog/<group_id>/<stem>.queued              the epochs a snapshot held (escrow_queued)
    escrow-backlog/.open-<random>/                       scratch store root of a pass in flight

A second state parked at an epoch that already has one is a different state (a
resync and a rejoin can land on the same epoch number), so it takes a distinct
name rather than replace the first. Reopening and sealing is
:mod:`rine._mls.escrow_backlog`. The TypeScript twin is
``rine-core/src/mls-escrow-snapshots.ts``, with the same layout.
"""

from __future__ import annotations

import contextlib
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._atomic_file import link_exclusive
from rine._config import mls_store_dir
from rine._crypto.derive import canonical_uuid
from rine._logging import logger
from rine._mls.escrow_atomic import copy_atomic
from rine._mls.escrow_queued import clear_queued, write_queued
from rine._mls.escrow_retry import clear_attempts
from rine._mls.escrow_store import group_dirs_in, mls_root
from rine._mls.group_access import mls_state_path

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Parent of every group's backlog dir, under the MLS store root.
BACKLOG_DIR = "escrow-backlog"
SNAPSHOT_SUFFIX = ".snapshot"

#: ``<epoch>[-<8 hex>].snapshot`` — the only name :func:`list_snapshots` will read back.
SNAPSHOT_NAME_RE = re.compile(rf"^(\d+)(?:-[0-9a-f]{{8}})?{re.escape(SNAPSHOT_SUFFIX)}$")

#: Prefix of the scratch store root a reopened snapshot lives in.
SCRATCH_PREFIX = ".open-"

#: Prefix of a snapshot copy that is not yet complete.
STAGE_PREFIX = ".stage-"


@dataclass(frozen=True, slots=True)
class BacklogSnapshot:
    """One parked old state, keyed by the group and epoch it was taken at."""

    group_id: str
    epoch: int
    path: str


def backlog_root(config_dir: str, agent_id: str) -> str:
    """The parent of every group's backlog dir."""
    return mls_root(config_dir, agent_id, BACKLOG_DIR)


def _group_dir(config_dir: str, agent_id: str, group_id: str) -> str:
    """The backlog dir of one group. Validates the id before joining."""
    canonical_uuid(group_id, "group id")
    return os.path.join(backlog_root(config_dir, agent_id), group_id)


def park_snapshot(
    config_dir: str,
    agent_id: str,
    group_id: str,
    epoch: int,
    queued: int,
    dropped: int = 0,
    fps: Mapping[int, bytes] | None = None,
) -> bool:
    """Copy the group's live state aside so a later sweep can seal its exports.

    ``queued`` is how many exports the state holds and ``dropped`` how many older ones the
    full queue had already pushed out, and ``fps`` is the fork each queued epoch was held at;
    all three are recorded beside the snapshot so the epochs, and the forks they belong to,
    are still named if the snapshot is never readable. That record is advisory:
    a failure to write it is logged and does not undo the park.

    The bytes go file to file, never through this process's memory, and are on
    disk before this returns: the caller wipes or replaces the stored state next.
    The copy is linked into place, so a second writer, even in another process,
    never replaces the first one's bytes.

    Returns:
        Whether a snapshot was parked. ``False`` when the agent holds no state
        file for the group, so there is nothing to park.

    Raises:
        CryptoError: ``group_id`` is not a canonical UUID.
        OSError: The copy could not be made durable, or no free name was left.
    """
    directory = _group_dir(config_dir, agent_id, group_id)
    state = mls_state_path(mls_store_dir(config_dir, agent_id), group_id)
    staged = os.path.join(directory, f"{STAGE_PREFIX}{os.urandom(8).hex()}")
    try:
        with open(state, "rb") as source:
            copy_atomic(source, staged)
    except FileNotFoundError:
        return False
    try:
        names = (
            f"{epoch}{SNAPSHOT_SUFFIX}",
            f"{epoch}-{os.urandom(4).hex()}{SNAPSHOT_SUFFIX}",
        )
        path = next(
            (p for p in (os.path.join(directory, n) for n in names) if link_exclusive(staged, p)),
            None,
        )
        if path is None:
            raise FileExistsError(f"no free snapshot name for group {group_id} at epoch {epoch}")
    finally:
        os.unlink(staged)
    try:
        write_queued(path, epoch, queued, dropped, fps)
    except OSError:
        logger.warning("MLS escrow snapshot for group %s: queued epochs not recorded", group_id)
    return True


def list_snapshots(config_dir: str, agent_id: str) -> list[BacklogSnapshot]:
    """Every parked snapshot for this agent, sorted by (group id, epoch, name).

    A missing backlog dir is ``[]``. Scratch dirs, staged copies and given-up
    snapshots are not listed, and neither is a name this module did not write.
    """
    snapshots: list[BacklogSnapshot] = []
    for group_id, directory in group_dirs_in(backlog_root(config_dir, agent_id)):
        try:
            names = os.listdir(directory)
        except OSError:
            continue  # Gone between the readdir and this one: nothing left to list.
        for name in names:
            match = SNAPSHOT_NAME_RE.fullmatch(name)
            if match is not None:
                snapshots.append(
                    BacklogSnapshot(group_id, int(match.group(1)), os.path.join(directory, name))
                )
    snapshots.sort(key=lambda s: (s.group_id, s.epoch, s.path))
    return snapshots


def delete_snapshot(snapshot: BacklogSnapshot) -> None:
    """Delete a sealed snapshot, and its group dir once nothing else is in it."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(snapshot.path)
    clear_attempts(snapshot.path)
    clear_queued(snapshot.path)
    with contextlib.suppress(OSError):  # Other snapshots or sidecars remain: the dir stays.
        os.rmdir(os.path.dirname(snapshot.path))
