"""The agent an MLS operation acts as, and the client it acts through."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MlsActor:
    """The agent an MLS operation acts as, and the client it acts through."""

    client: Any
    """Sync HTTP client."""

    config_dir: str
    """Config directory path."""

    agent_id: str
    """The acting agent's UUID."""
