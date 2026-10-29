"""The last key generation whose KeyPackages and group seats this host settled.

A key rotation mints a new generation, and the host must then republish its
KeyPackages and move its leaf in every group. That work is host-local and has to
survive a restart, so the generation it last completed is remembered per agent in
``keys/<agent>/mls-rotation.json`` as ``{"key_packages": n, "seats": n}``.

The marker is local bookkeeping, never part of a key transfer: the key files a
transfer carries are listed explicitly, and this is not one of them. The
TypeScript twin is ``rine-core/src/mls-rotation-marker.ts``; both read and write
the same file.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from rine._config import _write_atomic, keys_dir

_MARKER_FILE = "mls-rotation.json"


@dataclass(frozen=True)
class RotationMarker:
    """The generations whose KeyPackages and seats this host last settled."""

    key_packages: int = 0
    seats: int = 0


def _generation(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def read_rotation_marker(config_dir: str, agent_id: str) -> RotationMarker:
    """The remembered marker, or generation 0 when it is absent or unreadable.

    A missing or unreadable file, invalid JSON and a field that is not a
    non-negative integer all read as 0, so a generation-0 agent is never behind.
    The two fields are read independently: a valid one survives a malformed other.
    """
    try:
        with open(
            os.path.join(keys_dir(config_dir, agent_id), _MARKER_FILE), encoding="utf-8"
        ) as f:
            record = json.load(f)
    except (OSError, ValueError):
        return RotationMarker()
    if not isinstance(record, dict):
        return RotationMarker()
    return RotationMarker(
        key_packages=_generation(record.get("key_packages")),
        seats=_generation(record.get("seats")),
    )


def write_rotation_marker(config_dir: str, agent_id: str, marker: RotationMarker) -> None:
    """Remember the generations this host settled, atomically."""
    path = os.path.join(keys_dir(config_dir, agent_id), _MARKER_FILE)
    _write_atomic(path, json.dumps(asdict(marker), separators=(",", ":")))


__all__ = ["RotationMarker", "read_rotation_marker", "write_rotation_marker"]
