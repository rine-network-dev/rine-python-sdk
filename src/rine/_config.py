"""Configuration directory resolution and the token cache.

Priority: ``RINE_CONFIG_DIR`` env > ``~/.config/rine`` > ``.rine/`` in cwd. A
directory is discovered by its ``profiles.json`` (see :mod:`rine._profiles`).
"""

from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING, Any

from rine._atomic_file import write_via_temp
from rine._constants import DEFAULT_API_URL, TOKEN_REFRESH_MARGIN
from rine.errors import ConfigError

if TYPE_CHECKING:
    from rine._types import CachedToken

PROFILES_FILE = "profiles.json"
RETIRED_SIGN_IN_FILE = "credentials.json"

UPGRADE_DETAIL = (
    "This rine account uses the retired client_secret sign-in. rine now derives every key "
    "from an org root with a recovery phrase. Upgrade your rine package to the latest "
    "version and run onboarding again; your previous org and its messages are not carried over."
)


def refuse_retired_sign_in(config_dir: str) -> None:
    """Stop at a dir that holds only the retired sign-in file, with the upgrade text.

    Raises:
        ConfigError: ``config_dir`` has ``credentials.json`` and no ``profiles.json``.
    """
    if os.path.isfile(os.path.join(config_dir, RETIRED_SIGN_IN_FILE)) and not os.path.isfile(
        os.path.join(config_dir, PROFILES_FILE)
    ):
        raise ConfigError(UPGRADE_DETAIL)


def resolve_config_dir() -> str:
    """Resolve the Rine runtime config directory.

    Priority:
        1. ``RINE_CONFIG_DIR`` environment variable
        2. ``~/.config/rine`` (if it contains ``profiles.json``)
        3. ``.rine/`` in current working directory (if it contains ``profiles.json``)

    A candidate that holds the retired ``credentials.json`` and no
    ``profiles.json`` stops discovery with the upgrade text; it is never
    silently skipped.

    Returns:
        Absolute path to the config directory.

    Raises:
        ConfigError: A candidate holds only the retired sign-in file.
    """
    env_dir = os.environ.get("RINE_CONFIG_DIR")
    if env_dir:
        refuse_retired_sign_in(env_dir)
        return os.path.abspath(env_dir)

    xdg_dir = os.path.expanduser("~/.config/rine")
    cwd_dir = os.path.join(os.getcwd(), ".rine")
    for d in (xdg_dir, cwd_dir):
        refuse_retired_sign_in(d)
        if os.path.isfile(os.path.join(d, PROFILES_FILE)):
            return d

    # Return first writable candidate
    for d in (xdg_dir, cwd_dir):
        parent = os.path.dirname(d)
        if os.path.isdir(parent) and os.access(parent, os.W_OK):
            return d

    return cwd_dir


def resolve_api_url() -> str:
    """Resolve the Rine API URL.

    Returns:
        API base URL (no trailing slash).
    """
    url = os.environ.get("RINE_API_URL", DEFAULT_API_URL)
    return url.rstrip("/")


def _ensure_dir(path: str) -> None:
    """Create directory with 0o700 permissions if it doesn't exist."""
    os.makedirs(path, mode=0o700, exist_ok=True)


def _write_atomic(path: str, content: str) -> None:
    """Write content atomically: a 0o600 temp file, fsynced, then renamed over ``path``.

    The fsync puts the bytes on disk before the rename, so a crash never leaves the
    target empty; any failure removes the temp file.
    """
    _ensure_dir(os.path.dirname(path))
    write_via_temp(path, lambda handle: handle.write(content.encode("utf-8")))


def load_token_cache(config_dir: str) -> dict[str, CachedToken]:
    """Load token_cache.json from a directory.

    Args:
        config_dir: Path to the directory holding the cache.

    Returns:
        Dict of principal string to cached token. Empty dict on missing/malformed file.
    """
    path = os.path.join(config_dir, "token_cache.json")
    try:
        with open(path) as f:
            data: Any = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_token_cache(config_dir: str, cache: dict[str, CachedToken]) -> None:
    """Save token_cache.json atomically.

    Args:
        config_dir: Path to the directory holding the cache.
        cache: Dict of principal string to cached token.
    """
    path = os.path.join(config_dir, "token_cache.json")
    _write_atomic(path, json.dumps(cache, indent=2))


def cache_token(config_dir: str, principal: str, token: str, expires_in: float) -> None:
    """Cache an OAuth token with computed expiration.

    Args:
        config_dir: Path to the directory holding the cache.
        principal: Principal string the token was issued to (the cache key).
        token: Access token string.
        expires_in: Token lifetime in seconds. Typed ``float`` because it arrives
            from a JSON response body, where a conforming server may legally send
            a non-integer, and the only arithmetic done with it is float-safe.
    """
    cache = load_token_cache(config_dir)
    cache[principal] = {
        "access_token": token,
        "expires_at": time.time() + expires_in,
    }
    save_token_cache(config_dir, cache)


def token_is_fresh(expires_at: float, margin: float, now: float) -> bool:
    """Whether a token with this expiry is still usable, given the refresh margin.

    The one place the comparison lives, because it has to hold identically for
    the on-disk cache and for each client's in-memory token — and for both the
    sync and the async client. Skipping it on the in-memory path is what cost an
    always-on agent one rejected request per token lifetime, forever: the token
    expired, nothing noticed, and a 401 was the only thing that ever said so.

    Args:
        expires_at: Absolute expiry of the token, as a Unix timestamp.
        margin: Seconds before expiry at which the token is considered stale.
        now: Current time as a Unix timestamp (injected so callers that mock
            their clock compare against the same one).

    Returns:
        ``True`` if the token can still be used without refreshing.
    """
    return expires_at - now > margin


def get_cached_token_entry(
    config_dir: str,
    principal: str,
    margin: float = TOKEN_REFRESH_MARGIN,
    now: float | None = None,
) -> CachedToken | None:
    """Get a cached token entry if it's still valid (with refresh margin).

    Returns the whole entry, not just the token string: a caller that warm-starts
    from this cache needs the expiry too, or its own in-memory copy of the token
    is blind to the expiry this function just checked.

    Args:
        config_dir: Path to the directory holding the cache.
        principal: Principal string the token was issued to.
        margin: Seconds before expiry at which the token is considered stale.
            Defaults to the flat base; callers pass a per-client jittered value
            so co-located clients desynchronize their refreshes.
        now: Current time as a Unix timestamp. Defaults to the wall clock.

    Returns:
        The cached token entry, or ``None`` if expired or missing.
    """
    cache = load_token_cache(config_dir)
    entry = cache.get(principal)
    if entry and token_is_fresh(
        entry["expires_at"], margin, now if now is not None else time.time()
    ):
        return entry
    return None


def keys_dir(config_dir: str, agent_id: str) -> str:
    """Return the keys directory path for an agent.

    Args:
        config_dir: Path to config directory.
        agent_id: Agent UUID string.

    Returns:
        Path to ``keys/{agent_id}/`` directory.
    """
    return os.path.join(config_dir, "keys", agent_id)


def mls_store_dir(config_dir: str, agent_id: str) -> str:
    """Return the MLS state store root for an agent.

    Args:
        config_dir: Path to config directory.
        agent_id: Agent UUID string.

    Returns:
        Path to ``keys/{agent_id}/mls2/``. The ``mls2`` name is what keeps state
        written by the previous MLS core, under ``mls/``, from colliding with
        this one's — nothing ever reads those blobs again.
    """
    return os.path.join(config_dir, "keys", agent_id, "mls2")


def sender_keys_dir(config_dir: str, agent_id: str) -> str:
    """Return the sender keys directory path for an agent.

    Args:
        config_dir: Path to config directory.
        agent_id: Agent UUID string.

    Returns:
        Path to ``keys/{agent_id}/sender_keys/`` directory.
    """
    return os.path.join(config_dir, "keys", agent_id, "sender_keys")
