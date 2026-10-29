"""The escrow bytes an agent has sealed but not yet uploaded.

The native group hands its escrow exports over exactly once — ``take_escrow_exports()``
— and they survive only until the next ``group.save()``, so the sealed bytes are
written here before anything else touches them. Only the sealed bytes are stored;
the uploader signature is recomputed at upload time, because the server answers 422
when ``key_gen`` is not the uploader's CURRENT generation.

Layout under :func:`rine._config.mls_store_dir` (the head record is
:mod:`rine._mls.escrow_head`)::

    escrow-pending/<group_id>/<epoch>-<fp hex>.bin       sealed bytes, 0600
    escrow-pending/<group_id>/<epoch>-<fp hex>.attempts  retry state of a file not yet taken

The TypeScript twin is ``rine-core/src/mls-escrow-pending.ts`` — same names, same keys.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
from dataclasses import dataclass

from rine._config import mls_store_dir
from rine._crypto.derive import UUID_RE, canonical_uuid
from rine._mls.escrow_atomic import create_exclusive
from rine._mls.escrow_retry import clear_attempts
from rine.errors import CryptoError

#: Parent of every group's pending dir, under the MLS store root.
PENDING_DIR = "escrow-pending"
PENDING_SUFFIX = ".bin"

#: A fork fingerprint is 16 raw bytes, written as 32 lower-case hex characters.
FP_LENGTH = 16
FP_HEX_LENGTH = 32
#: An epoch as the escrow file names spell it: ASCII digits with no leading zero and at most
#: 15 of them, so every epoch has exactly one name and reads the same here as in the
#: TypeScript twin, whose numbers are exact up to 2**53. One capturing group.
EPOCH_NAME_PATTERN = "(0|[1-9][0-9]{0,14})"
#: ``<epoch>-<32 hex>.bin`` — the only name :func:`list_pending` will read back.
PENDING_NAME_RE = re.compile(
    rf"^{EPOCH_NAME_PATTERN}-([0-9a-f]{{{FP_HEX_LENGTH}}}){re.escape(PENDING_SUFFIX)}$"
)


@dataclass(frozen=True, slots=True)
class PendingEscrow:
    """One sealed escrow waiting for upload, keyed by its slot."""

    group_id: str
    epoch: int
    fp: bytes
    sealed: bytes


def mls_root(config_dir: str, agent_id: str, name: str) -> str:
    """``<mls store>/<name>`` — the parent of every group's files of that kind."""
    return os.path.join(mls_store_dir(config_dir, agent_id), name)


def pending_dir(config_dir: str, agent_id: str, group_id: str) -> str:
    """The dir holding one group's pending escrows. Validates the id before joining."""
    canonical_uuid(group_id, "group id")
    return os.path.join(mls_root(config_dir, agent_id, PENDING_DIR), group_id)


def pending_path(config_dir: str, agent_id: str, pending: PendingEscrow) -> str:
    """The file path a pending escrow is filed under. Validates the group id."""
    name = f"{pending.epoch}-{pending.fp.hex()}{PENDING_SUFFIX}"
    return os.path.join(pending_dir(config_dir, agent_id, pending.group_id), name)


def write_pending(config_dir: str, agent_id: str, pending: PendingEscrow) -> None:
    """Persist one sealed escrow; a slot that already has a file is left untouched.

    The first sealing of a slot wins, even between two processes sharing a config
    dir: sealing is randomised, so a second file for the same slot would differ and
    the server answers 409 to a different row.

    Raises:
        CryptoError: ``group_id`` is not a canonical UUID, or ``fp`` is not 16 bytes.
    """
    path = pending_path(config_dir, agent_id, pending)
    if len(pending.fp) != FP_LENGTH:
        raise CryptoError(f"escrow fingerprint must be {FP_LENGTH} bytes, got {len(pending.fp)}")
    create_exclusive(path, pending.sealed)


def _is_real_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def group_dirs_in(root: str) -> list[tuple[str, str]]:
    """``(group id, dir)`` of every group dir directly under ``root``, sorted by group id.

    Only canonical-UUID directory names count: those are the names this module writes. A link
    to a directory is not one, as in the TypeScript twin.
    """
    try:
        names = os.listdir(root)
    except OSError:
        return []
    return [
        (name, os.path.join(root, name))
        for name in sorted(names)
        if UUID_RE.fullmatch(name) and _is_real_dir(os.path.join(root, name))
    ]


def group_dirs(config_dir: str, agent_id: str) -> list[tuple[str, str]]:
    """``(group id, dir)`` of every group dir under the pending root."""
    return group_dirs_in(mls_root(config_dir, agent_id, PENDING_DIR))


def list_pending(
    config_dir: str, agent_id: str, group_id: str | None = None
) -> list[PendingEscrow]:
    """Every pending escrow for this agent, sorted by (group id, epoch, fp hex).

    A missing dir is ``[]``. ``*.tmp`` files and names that do not parse as
    ``<digits>-<32 hex>.bin`` are ignored: the first is a write in flight, the
    second is not something this module wrote. A group dir whose name is not a
    canonical UUID is ignored for the same reason. ``group_id`` limits the listing
    to one group.

    Raises:
        CryptoError: ``group_id`` is given and is not a canonical UUID.
    """
    if group_id is not None:
        dirs = [(group_id, pending_dir(config_dir, agent_id, group_id))]
    else:
        dirs = group_dirs(config_dir, agent_id)

    pending: list[PendingEscrow] = []
    for gid, directory in dirs:
        try:
            names = os.listdir(directory)
        except OSError:
            continue  # Gone between the readdir and this one: nothing left to list.
        for name in names:
            match = PENDING_NAME_RE.fullmatch(name)
            if match is None:
                continue
            try:
                with open(os.path.join(directory, name), "rb") as f:
                    sealed = f.read()
            except OSError:
                continue  # Torn between the readdir and the read: skip, do not fail.
            pending.append(
                PendingEscrow(
                    group_id=gid,
                    epoch=int(match.group(1)),
                    fp=bytes.fromhex(match.group(2)),
                    sealed=sealed,
                )
            )
    pending.sort(key=lambda p: (p.group_id, p.epoch, p.fp.hex()))
    return pending


def delete_pending(config_dir: str, agent_id: str, pending: PendingEscrow) -> None:
    """Drop a pending escrow once its upload has a final outcome. Missing is success.

    The retry sidecar goes with it: the file is gone, so its schedule is too.
    """
    path = pending_path(config_dir, agent_id, pending)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    clear_attempts(path)
