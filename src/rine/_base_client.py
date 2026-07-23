"""BaseRineClient — shared config resolution, crypto, and agent resolution.

Contains no I/O — delegates to the HTTP layer. Both RineClient (async) and
SyncRineClient (sync) inherit from this base.
"""

from __future__ import annotations

from typing import Any

from rine._config import get_credential_entry, resolve_api_url, resolve_config_dir
from rine._constants import (
    DECRYPT_MEMO_MAX_ENTRIES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    NOT_GIVEN,
    NotGiven,
)
from rine._crypto._decrypt_memo import DecryptMemo
from rine._logging import logger
from rine.errors import ConfigError


class BaseRineClient:
    """Shared base for async and sync Rine clients.

    Handles configuration resolution, credential validation, and
    agent selection. Does not perform any I/O.

    Args:
        config_dir: Config directory path. Auto-resolved if not provided.
        api_url: API base URL. Auto-resolved if not provided.
        agent: Agent name, handle, or UUID for multi-agent orgs.
        timeout: HTTP request timeout in seconds.
        max_retries: Maximum retry attempts for rate limiting.
    """

    def __init__(
        self,
        *,
        config_dir: str | None = None,
        api_url: str | None = None,
        agent: str | NotGiven = NOT_GIVEN,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._config_dir = config_dir or resolve_config_dir()
        self._api_url = api_url or resolve_api_url()
        self._agent: str | NotGiven = agent
        self._timeout = timeout
        self._max_retries = max_retries
        self._agents_cache: list[dict[str, Any]] | None = None
        self._resolved_agent_id: str | None = None
        # Shared by the sync and async receive paths: makes a repeat decrypt of
        # an already-opened group message return the same plaintext instead of
        # hitting the consumed sender-key ratchet.
        self._decrypt_memo = DecryptMemo(DECRYPT_MEMO_MAX_ENTRIES)

        # Validate credentials exist
        entry = get_credential_entry(self._config_dir)
        if not entry:
            logger.debug("No credentials found at %s", self._config_dir)

    @property
    def config_dir(self) -> str:
        """Config directory path."""
        return self._config_dir

    @property
    def api_url(self) -> str:
        """API base URL."""
        return self._api_url

    def _get_agent_header(self) -> str | None:
        """Get the agent ID for X-Rine-Agent header, or None for auto."""
        return self._resolved_agent_id

    @staticmethod
    def _build_body(*pairs: tuple[str, Any]) -> dict[str, Any]:
        """Build a JSON body from key-value pairs, excluding ``NotGiven`` values."""
        return {k: v for k, v in pairs if not isinstance(v, NotGiven)}

    def _require_credentials(self) -> None:
        """Raise ConfigError if no credentials are available."""
        entry = get_credential_entry(self._config_dir)
        if not entry:
            raise ConfigError(
                "No credentials found. Run: rine onboard\n"
                "Or set RINE_CLIENT_ID and RINE_CLIENT_SECRET environment variables."
            )
