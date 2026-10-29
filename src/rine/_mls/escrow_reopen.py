"""Opening a parked snapshot in a scratch store, so its exports can be read or discarded.

A parked snapshot (:mod:`rine._mls.escrow_snapshots`) holds the plaintext exports a settle
could not seal. Both the sealing pass and the give-up pass of
:mod:`rine._mls.escrow_backlog` reopen it here: the bytes are copied into a scratch store
root under the backlog directory, opened there, and the scratch is removed whatever happens,
so the live store is never touched.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from typing import TYPE_CHECKING

from rine._mls.binding import open_mls_client
from rine._mls.escrow_atomic import copy_atomic
from rine._mls.escrow_snapshots import SCRATCH_PREFIX, BacklogSnapshot, backlog_root
from rine._mls.group_access import load_mls_group, mls_state_path
from rine.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rine._mls.binding import MlsGroup
    from rine._mls.heartbeat import MlsActor


class SnapshotUnreadableError(CryptoError):
    """The parked state could not be opened, which is the only failure that uses up an attempt."""


def _open_staged(actor: MlsActor, snapshot: BacklogSnapshot, scratch: str) -> MlsGroup:
    """Copy the snapshot into a scratch store root and open the group it holds.

    Raises:
        SnapshotUnreadableError: The stored state does not open or holds no group.
        OSError: The scratch store could not be written, which says nothing about the snapshot.
    """
    with open(snapshot.path, "rb") as source:
        copy_atomic(source, mls_state_path(scratch, snapshot.group_id))
    try:
        client = open_mls_client(actor.config_dir, actor.agent_id, store_dir=scratch)
        group = load_mls_group(client, snapshot.group_id)
    except OSError:
        raise
    except Exception as exc:
        raise SnapshotUnreadableError(
            f"backlog snapshot for group {snapshot.group_id} does not open"
        ) from exc
    if group is None:
        raise SnapshotUnreadableError(
            f"backlog snapshot for group {snapshot.group_id} holds no state"
        )
    return group


@contextlib.contextmanager
def reopened(actor: MlsActor, snapshot: BacklogSnapshot) -> Iterator[MlsGroup]:
    """Open the snapshot in a scratch store that never touches the live one.

    The scratch store is removed whatever happens.
    """
    root = backlog_root(actor.config_dir, actor.agent_id)
    scratch = os.path.join(root, f"{SCRATCH_PREFIX}{os.urandom(6).hex()}")
    os.makedirs(scratch, mode=0o700)
    try:
        yield _open_staged(actor, snapshot, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
