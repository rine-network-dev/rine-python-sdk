"""The newest drained epoch of a group and its fork fingerprint.

A sender needs the live fork's escrow to be sealed before it sends. The drain remembers
the newest epoch and its fp in a tiny record per group, which the send gate compares with
the group's live fingerprint. Layout under :func:`rine._config.mls_store_dir`::

    escrow-head/<group_id>.json   {"epoch": n, "fp": "<hex>"}

The TypeScript twin is ``rine-core/src/mls-escrow-head.ts`` — same names, same keys.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass

from rine._crypto.derive import canonical_uuid
from rine._mls.escrow_atomic import write_atomic
from rine._mls.escrow_store import FP_HEX_LENGTH, mls_root

#: Parent of every group's head record, under the MLS store root.
HEAD_DIR = "escrow-head"
HEAD_SUFFIX = ".json"
FP_HEX_RE = re.compile(rf"^[0-9a-f]{{{FP_HEX_LENGTH}}}$")


@dataclass(frozen=True, slots=True)
class EscrowHead:
    """The newest drained epoch of a group and the fork fingerprint it was drained at."""

    epoch: int
    fp: bytes


def _head_path(config_dir: str, agent_id: str, group_id: str) -> str:
    """The head record path for one group. Validates the id before joining."""
    canonical_uuid(group_id, "group id")
    return os.path.join(mls_root(config_dir, agent_id, HEAD_DIR), f"{group_id}{HEAD_SUFFIX}")


def write_head(
    config_dir: str, agent_id: str, group_id: str, head: EscrowHead, *, live: bool = False
) -> None:
    """Remember the newest drained epoch and its fork fingerprint.

    The head never moves to a LOWER epoch: a stale drain finishing after a newer
    one must not rewind what a sender reads as the current fp. The one exception is
    ``live``, which the drain sets when ``head`` is the live group's own current epoch
    and fork: a resync or rejoin onto another fork can land below the old head, and
    that head would then name a fork the group has left. A corrupt existing head
    reads as absent, so it is replaced rather than blocking the write.
    """
    existing = read_head(config_dir, agent_id, group_id)
    if not live and existing is not None and existing.epoch > head.epoch:
        return
    body = json.dumps({"epoch": head.epoch, "fp": head.fp.hex()})
    write_atomic(_head_path(config_dir, agent_id, group_id), body.encode("utf-8"))


def read_head(config_dir: str, agent_id: str, group_id: str) -> EscrowHead | None:
    """The remembered head, or ``None`` when it is absent, malformed or unreadable."""
    try:
        with open(_head_path(config_dir, agent_id, group_id)) as f:
            raw = f.read()
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    epoch = data.get("epoch")
    fp = data.get("fp")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        return None
    if not isinstance(fp, str) or not FP_HEX_RE.fullmatch(fp):
        return None
    return EscrowHead(epoch=epoch, fp=bytes.fromhex(fp))


def clear_head(config_dir: str, agent_id: str, group_id: str, head: EscrowHead) -> None:
    """Forget the head when it is exactly ``head``: the escrow it vouches for is given up.

    A head pointing at another epoch or fork fingerprint is left alone.
    """
    if read_head(config_dir, agent_id, group_id) == head:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(_head_path(config_dir, agent_id, group_id))
