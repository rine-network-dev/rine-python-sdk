"""``profiles.json``: which principal each named profile acts as.

The file holds no secret. A profile names a principal and the ids needed to find
that principal's key files; a runtime dir carries ``agent:`` and ``branch:``
principals only, and the owner dir carries the ``org:`` principal.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from rine._config import PROFILES_FILE, _write_atomic, refuse_retired_sign_in
from rine._file_lock import FileLockTiming, file_lock
from rine.errors import ConfigError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rine._types import Profile

DEFAULT_PROFILE = "default"

#: A writer holds the lock only across one read and one write of a small file.
_PROFILES_LOCK = FileLockTiming(stale_ms=5000, timeout_ms=10000, poll_ms=50)


def load_profiles(config_dir: str) -> dict[str, Profile]:
    """Load ``profiles.json`` from a directory.

    Args:
        config_dir: Path to the directory.

    Returns:
        Dict of profile name to profile. Empty dict on a missing or malformed file.

    Raises:
        ConfigError: The directory holds only the retired sign-in file, or the
            profiles file cannot be read.
    """
    refuse_retired_sign_in(config_dir)
    path = os.path.join(config_dir, PROFILES_FILE)
    try:
        with open(path) as f:
            data: Any = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except PermissionError:
        raise ConfigError(
            f"Permission denied reading {path}. Check file permissions (should be 0o600)."
        ) from None
    return data if isinstance(data, dict) else {}


@contextmanager
def _profiles_lock(config_dir: str) -> Iterator[str]:
    """Hold the dir's profiles lock, the one the TypeScript writers take; yields the file path.

    Waits block the thread, for at most the lock's timeout, then raise
    :class:`~rine.errors.ConfigError`.
    """
    path = os.path.join(config_dir, PROFILES_FILE)
    lock = f"{path}.lock"
    with file_lock(
        lock,
        _PROFILES_LOCK,
        lambda: ConfigError(f"{lock} is held by another process; retry when it finishes"),
    ):
        yield path


def _write_profiles(path: str, profiles: dict[str, Profile]) -> None:
    _write_atomic(path, json.dumps(profiles, indent=2))


def save_profiles(config_dir: str, profiles: dict[str, Profile]) -> None:
    """Save ``profiles.json`` atomically with 0o600 permissions, under the dir's profiles lock."""
    with _profiles_lock(config_dir) as path:
        _write_profiles(path, profiles)


def get_profile(config_dir: str, profile: str = DEFAULT_PROFILE) -> Profile | None:
    """One named profile, or ``None`` when the directory has no such entry."""
    return load_profiles(config_dir).get(profile)


def add_profile_if_absent(config_dir: str, profile: str, entry: Profile) -> bool:
    """Add ``entry`` under ``profile`` unless that name is taken.

    The read and the write happen under the dir's profiles lock, so a writer in
    another process never drops an entry this one adds.

    Returns:
        Whether it wrote.
    """
    with _profiles_lock(config_dir) as path:
        profiles = load_profiles(config_dir)
        if profile in profiles:
            return False
        profiles[profile] = entry
        _write_profiles(path, profiles)
    return True
