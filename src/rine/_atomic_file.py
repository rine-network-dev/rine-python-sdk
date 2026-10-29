"""The temp-file step every atomic write in the SDK shares.

It imports nothing from the rest of the package, so ``rine._config`` and the
escrow stores under ``rine._mls`` can both use it without an import cycle.
"""

from __future__ import annotations

import contextlib
import errno
import os
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

#: What a filesystem without hard links answers to ``os.link``.
NO_HARD_LINKS = frozenset(
    {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.ENOSYS}
)


def write_via_temp(
    path: str,
    fill: Callable[[BinaryIO], object],
    place: Callable[[str, str], object] | None = None,
) -> None:
    """Fill a temp file beside ``path``, make it durable, then ``place`` it at ``path``.

    The temp is created exclusively with mode 0o600 under a random name, so its
    bytes are never readable at the umask default and two writers never share
    it. It is flushed and fsynced before ``place(temp, path)`` runs (``os.replace``
    by default), so a crash never leaves ``path`` empty. The temp is removed if
    anything fails.
    """
    tmp = f"{path}.{os.urandom(8).hex()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fill(handle)
            handle.flush()
            os.fsync(handle.fileno())
        (place or os.replace)(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _copy_exclusive(source: str, path: str) -> bool:
    """Copy ``source`` to ``path`` only if it does not exist; ``False`` when it does.

    The copy is not atomic, so a crash mid-copy can leave a short file at ``path``. Only
    a filesystem without hard links gets here, and every caller writes a file small
    enough that the window is narrow: a short file reads as absent or corrupt, never as
    someone else's bytes.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "wb") as dest, open(source, "rb") as src:
            shutil.copyfileobj(src, dest)
            dest.flush()
            os.fsync(dest.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    return True


def link_exclusive(source: str, path: str) -> bool:
    """Put ``source`` at ``path`` unless it exists: a hard link, else an exclusive copy.

    Returns whether this call created ``path``; an existing file is never replaced.
    """
    try:
        os.link(source, path)
    except FileExistsError:
        return False
    except OSError as exc:
        if exc.errno not in NO_HARD_LINKS:
            raise
        return _copy_exclusive(source, path)
    return True


def create_atomic_exclusive(path: str, content: bytes) -> bool:
    """Create ``path`` holding ``content`` unless it exists; ``False`` when it already did.

    The bytes are made durable in a temp beside ``path`` (see :func:`write_via_temp`)
    and then linked into place, so a file another writer created after any earlier
    existence check is kept. With hard links ``path`` never appears half-written; a
    crash between the link and the temp's removal leaves that 0o600 temp beside it.
    Without hard links the bytes are copied into ``path`` itself (see
    :func:`link_exclusive`), so a crash mid-copy can leave it short.
    """
    created = False

    def place(tmp: str, target: str) -> None:
        nonlocal created
        created = link_exclusive(tmp, target)
        os.unlink(tmp)

    write_via_temp(path, lambda handle: handle.write(content), place)
    return created
