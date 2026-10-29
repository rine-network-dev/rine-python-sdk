"""The owner dir: where ``root.key`` and the recovery phrase live.

It is a different directory from the runtime config dir an agent reads, so an
agent with file tools never sits next to the org root. ``root.key`` is the org's
32-byte root as base64url on one line; the phrase is the same bytes as 24 words.
Whoever reads either controls the org permanently, so a root is never written
where git would commit it or a project runtime would resolve it.
"""

from __future__ import annotations

import contextlib
import os

from rine._atomic_file import create_atomic_exclusive
from rine._config import _ensure_dir, _write_atomic
from rine._crypto.phrase import phrase_from_entropy
from rine._utils import from_base64url, to_base64url
from rine.errors import ConfigError

OWNER_DIR_ENV = "RINE_OWNER_DIR"
ROOT_KEY_FILE = "root.key"
PHRASE_FILE = "recovery-phrase.txt"
ROOT_SIZE = 32

#: What the owner does with the recovery phrase, as every surface states it; bound to
#: ``PHRASE_INSTRUCTION`` in ``rine-core/src/owner.ts`` by
#: ``tests/test_owner-words-twin_group0.py``.
PHRASE_INSTRUCTION = (
    "Store these 24 words offline, then delete the file. They restore your org's identities, "
    "group seats and readable history, never your wallets. "
    "Anyone who reads them controls the org permanently."
)


def resolve_owner_dir() -> str:
    """The owner dir: ``RINE_OWNER_DIR``, else ``~/.config/rine-owner``."""
    env_dir = os.environ.get(OWNER_DIR_ENV)
    return os.path.abspath(env_dir) if env_dir else os.path.expanduser("~/.config/rine-owner")


def effective_owner_dir(owner_dir: str | None, agent_only: bool) -> str | None:
    """The owner dir a client reads, or ``None`` for an agent runtime that never reads one.

    An agent runtime never loads ``root.key``: ``agent_only`` is how a runtime
    (an adapter, a deployed agent) says so, whatever the host's owner dir holds.

    Raises:
        ConfigError: ``agent_only`` was combined with an explicit ``owner_dir``.
    """
    if not agent_only:
        return owner_dir or resolve_owner_dir()
    if owner_dir is not None:
        raise ConfigError("agent_only clients take no owner_dir.")
    return None


def _inside_git_worktree(path: str) -> bool:
    """Whether ``path`` or any ancestor holds a ``.git`` entry."""
    here = path
    while True:
        if os.path.lexists(os.path.join(here, ".git")):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def _is_or_inside(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent + os.sep)


def assert_owner_dir_allowed(owner_dir: str, config_dir: str | None = None) -> None:
    """Refuse a dir where the root would be committed or read by a project runtime.

    Every comparison is made on the resolved path, so a symlink into a repository
    or a ``..`` alias of the project ``.rine`` does not get past it.

    Args:
        owner_dir: The directory that would hold ``root.key``.
        config_dir: The runtime config dir the agents read, when it is known.

    Raises:
        ConfigError: ``owner_dir`` is inside a git worktree or a project ``.rine``,
            or is the runtime config dir, inside it, or holds it.
    """
    path = os.path.realpath(owner_dir)
    if _inside_git_worktree(path):
        raise ConfigError(
            f"Refusing to keep the org root inside a git worktree ({path}). "
            f"Set {OWNER_DIR_ENV} to a directory outside any repository."
        )
    if _is_or_inside(path, os.path.realpath(os.path.join(os.getcwd(), ".rine"))):
        raise ConfigError(
            f"Refusing to keep the org root in a project .rine directory ({path}). "
            f"Set {OWNER_DIR_ENV} to a private directory."
        )
    if config_dir is not None:
        runtime = os.path.realpath(config_dir)
        if _is_or_inside(path, runtime) or _is_or_inside(runtime, path):
            raise ConfigError(
                f"Refusing to keep the org root in or around the runtime config directory "
                f"({runtime}): agents read that directory. "
                f"Set {OWNER_DIR_ENV} to a separate private directory."
            )


def _root_taken_error(owner_dir: str) -> ConfigError:
    return ConfigError(f"{ROOT_KEY_FILE} already exists in {owner_dir}: one org per owner dir.")


def assert_fresh_owner_dir(owner_dir: str, config_dir: str | None = None) -> None:
    """Refuse a dir that is unsafe (see :func:`assert_owner_dir_allowed`) or holds a root.

    Raises:
        ConfigError: The dir is unsafe, or already holds an org (one org per dir).
    """
    assert_owner_dir_allowed(owner_dir, config_dir)
    if has_root(owner_dir):
        raise _root_taken_error(owner_dir)


def has_root(owner_dir: str) -> bool:
    """Whether the owner dir holds a ``root.key``."""
    return os.path.isfile(os.path.join(owner_dir, ROOT_KEY_FILE))


def load_root(owner_dir: str) -> bytes | None:
    """The org root, or ``None`` when the dir holds none.

    Raises:
        ConfigError: The file is present but is not 32 bytes of base64url.
    """
    path = os.path.join(owner_dir, ROOT_KEY_FILE)
    try:
        with open(path) as f:
            text = f.read().strip()
    except FileNotFoundError:
        return None
    try:
        root = from_base64url(text)
    except ValueError:
        root = b""
    if len(root) != ROOT_SIZE:
        raise ConfigError(f"Corrupt {ROOT_KEY_FILE} in {owner_dir}: expected {ROOT_SIZE} bytes.")
    return root


def save_root(owner_dir: str, root: bytes) -> None:
    """Write ``root.key`` and ``recovery-phrase.txt`` (0600, dir 0700).

    ``root.key`` is created exclusively, so a root another process wrote after the
    freshness check is never replaced; the phrase follows only once the root is this one.

    Raises:
        ConfigError: The dir is unsafe, or already holds a root (one org per dir).
    """
    assert_fresh_owner_dir(owner_dir)
    _ensure_dir(owner_dir)
    os.chmod(owner_dir, 0o700)
    root_line = f"{to_base64url(root)}\n".encode()
    if not create_atomic_exclusive(os.path.join(owner_dir, ROOT_KEY_FILE), root_line):
        raise _root_taken_error(owner_dir)
    _write_atomic(os.path.join(owner_dir, PHRASE_FILE), f"{phrase_from_entropy(root)}\n")


def remove_root(owner_dir: str) -> None:
    """Remove what :func:`save_root` wrote: a registration the server refused."""
    for name in (ROOT_KEY_FILE, PHRASE_FILE):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(os.path.join(owner_dir, name))
