"""Removing the scratch stores and staged copies a killed process left in the backlog.

Layout and names are :mod:`rine._mls.escrow_snapshots`'s; this only clears what a pass that
died before cleaning up left behind.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import time

from rine._mls.escrow_snapshots import SCRATCH_PREFIX, STAGE_PREFIX, backlog_root
from rine._mls.escrow_store import group_dirs_in

#: A scratch store or staged copy older than this belongs to a process that died.
STALE_AFTER_S = 3600.0


def _remove_stale(path: str, now: float) -> None:
    with contextlib.suppress(OSError):  # Gone already, or in use by a live process.
        if now - os.stat(path).st_mtime < STALE_AFTER_S:
            return
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)


def clear_scratch(config_dir: str, agent_id: str, now: float | None = None) -> None:
    """Remove the scratch stores and staged copies a killed process left behind.

    Looks in the backlog root and in every group dir, and takes only those older
    than :data:`STALE_AFTER_S`: a younger one may belong to a process that is
    working on it now, and removing it would fail that process's pass.
    """
    instant = time.time() if now is None else now
    root = backlog_root(config_dir, agent_id)
    dirs = [root, *(directory for _, directory in group_dirs_in(root))]
    for directory in dirs:
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if name.startswith((SCRATCH_PREFIX, STAGE_PREFIX)):
                _remove_stale(os.path.join(directory, name), instant)
