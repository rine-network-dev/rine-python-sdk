"""Atomic, durable file writes for the escrow stores.

Every pending file, retry sidecar, gap marker, head record and backlog snapshot is
published through here, so a crash leaves either the old file or the whole new one,
and a caller that deletes the source of the bytes afterwards cannot lose both.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from typing import TYPE_CHECKING

from rine._atomic_file import create_atomic_exclusive, write_via_temp

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO


def _durable_in_dir(path: str, write: Callable[[], object]) -> None:
    """Run ``write`` for ``path`` in its private directory, then fsync that directory.

    The directory is created 0o700. Flushing its entry after ``write`` means a
    caller that deletes the source of the bytes afterwards cannot lose both.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    write()
    with contextlib.suppress(OSError):  # A filesystem that cannot fsync a directory.
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def write_atomic(path: str, content: bytes) -> None:
    """Write ``content`` to ``path`` atomically and durably, replacing any file there.

    The bytes go through a 0o600 temp renamed into place (see
    :func:`rine._atomic_file.write_via_temp`), so a reader never sees a half-written
    file and two writers never share a temp name.
    """
    _durable_in_dir(path, lambda: write_via_temp(path, lambda handle: handle.write(content)))


def create_exclusive(path: str, content: bytes) -> None:
    """Create ``path`` holding ``content`` durably unless it exists; an existing file is kept.

    A second writer, even in another process, can never replace the first one's
    bytes. See :func:`rine._atomic_file.create_atomic_exclusive` for the guarantee on
    a filesystem without hard links.
    """
    _durable_in_dir(path, lambda: create_atomic_exclusive(path, content))


def copy_atomic(source: BinaryIO, path: str) -> None:
    """Copy an open file to ``path`` atomically and durably, without reading it into memory.

    For plaintext group state: it never sits in a Python object that outlives the
    copy. Placed as :func:`write_atomic` places its bytes.
    """
    _durable_in_dir(
        path, lambda: write_via_temp(path, lambda handle: shutil.copyfileobj(source, handle))
    )
