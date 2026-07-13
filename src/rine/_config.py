"""Configuration directory resolution, credentials, and token cache management.

Priority: ``RINE_CONFIG_DIR`` env > ``~/.config/rine`` > ``.rine/`` in cwd.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any

from rine._constants import DEFAULT_API_URL, TOKEN_REFRESH_MARGIN
from rine._types import CachedToken, CredentialEntry
from rine.errors import ConfigError


def resolve_config_dir() -> str:
    """Resolve the Rine config directory.

    Priority:
        1. ``RINE_CONFIG_DIR`` environment variable
        2. ``~/.config/rine`` (if it contains ``credentials.json``)
        3. ``.rine/`` in current working directory

    Returns:
        Absolute path to the config directory.

    Raises:
        ConfigError: If no valid config directory can be resolved.
    """
    env_dir = os.environ.get("RINE_CONFIG_DIR")
    if env_dir:
        return os.path.abspath(env_dir)

    xdg_dir = os.path.expanduser("~/.config/rine")
    if os.path.isfile(os.path.join(xdg_dir, "credentials.json")):
        return xdg_dir

    cwd_dir = os.path.join(os.getcwd(), ".rine")
    if os.path.isfile(os.path.join(cwd_dir, "credentials.json")):
        return cwd_dir

    # Return first writable candidate
    for d in [xdg_dir, cwd_dir]:
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
    """Write content atomically: write to temp file, then rename. 0o600 perms."""
    _ensure_dir(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_credentials(config_dir: str) -> dict[str, CredentialEntry]:
    """Load credentials.json from the config directory.

    Args:
        config_dir: Path to config directory.

    Returns:
        Dict of profile name to credential entry. Empty dict on missing/malformed file.
    """
    path = os.path.join(config_dir, "credentials.json")
    try:
        with open(path) as f:
            data: Any = json.load(f)
        if isinstance(data, dict):
            return data  # type: ignore[return-value]
        return {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except PermissionError:
        raise ConfigError(
            f"Permission denied reading {path}. Check file permissions (should be 0o600)."
        )


def save_credentials(config_dir: str, credentials: dict[str, CredentialEntry]) -> None:
    """Save credentials.json atomically with 0o600 permissions.

    Args:
        config_dir: Path to config directory.
        credentials: Dict of profile name to credential entry.
    """
    path = os.path.join(config_dir, "credentials.json")
    _write_atomic(path, json.dumps(credentials, indent=2))


def get_credential_entry(config_dir: str, profile: str = "default") -> CredentialEntry | None:
    """Get a credential entry, preferring env vars over file.

    Priority: ``RINE_CLIENT_ID`` + ``RINE_CLIENT_SECRET`` env vars > profile in file.

    Args:
        config_dir: Path to config directory.
        profile: Profile name in credentials.json.

    Returns:
        Credential entry, or ``None`` if not found.
    """
    client_id = os.environ.get("RINE_CLIENT_ID")
    client_secret = os.environ.get("RINE_CLIENT_SECRET")
    if client_id and client_secret:
        return {"client_id": client_id, "client_secret": client_secret}

    creds = load_credentials(config_dir)
    return creds.get(profile)


def load_token_cache(config_dir: str) -> dict[str, CachedToken]:
    """Load token_cache.json from the config directory.

    Args:
        config_dir: Path to config directory.

    Returns:
        Dict of profile name to cached token. Empty dict on missing/malformed file.
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
        config_dir: Path to config directory.
        cache: Dict of profile name to cached token.
    """
    path = os.path.join(config_dir, "token_cache.json")
    _write_atomic(path, json.dumps(cache, indent=2))


def cache_token(config_dir: str, profile: str, token: str, expires_in: int) -> None:
    """Cache an OAuth token with computed expiration.

    Args:
        config_dir: Path to config directory.
        profile: Profile name.
        token: Access token string.
        expires_in: Token lifetime in seconds.
    """
    cache = load_token_cache(config_dir)
    cache[profile] = {
        "access_token": token,
        "expires_at": time.time() + expires_in,
    }
    save_token_cache(config_dir, cache)


def get_cached_token(
    config_dir: str, profile: str = "default", margin: float = TOKEN_REFRESH_MARGIN
) -> str | None:
    """Get a cached token if it's still valid (with refresh margin).

    Args:
        config_dir: Path to config directory.
        profile: Profile name.
        margin: Seconds before expiry at which the token is considered stale.
            Defaults to the flat base; callers pass a per-client jittered value
            so co-located clients desynchronize their refreshes.

    Returns:
        Access token string, or ``None`` if expired or missing.
    """
    cache = load_token_cache(config_dir)
    entry = cache.get(profile)
    if entry and entry["expires_at"] - time.time() > margin:
        return entry["access_token"]
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


def sender_keys_dir(config_dir: str, agent_id: str) -> str:
    """Return the sender keys directory path for an agent.

    Args:
        config_dir: Path to config directory.
        agent_id: Agent UUID string.

    Returns:
        Path to ``keys/{agent_id}/sender_keys/`` directory.
    """
    return os.path.join(config_dir, "keys", agent_id, "sender_keys")
