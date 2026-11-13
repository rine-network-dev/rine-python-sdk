"""A real sealed, signed console message and its real decrypt, for the operator tests.

The key that verified the signature comes from the same verification a surface runs, not
from a hand-built result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from rine import (
    OperatorContext,
    OperatorPin,
    OperatorRowInput,
)
from rine._constants import EncryptionVersion
from rine._crypto.keys import save_agent_keys
from rine._crypto.message import decrypt_message_sync, encrypt_message
from rine._utils import to_base64url
from rine.testing import WORLD
from tests.conftest import recipient_view
from tests.test_crypto.world import KeyServer

SEAT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SELF_ID = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
STRANGER_ID = "c3d4e5f6-a7b8-9012-cdef-123456789013"
NOW_DT = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)
NOW_MS = int(NOW_DT.timestamp() * 1000)


def instant(offset: timedelta) -> str:
    """An RFC 3339 instant ``offset`` from the reader's clock."""
    return (NOW_DT + offset).isoformat().replace("+00:00", "Z")


def minutes_ago(n: int) -> str:
    """Minutes ago."""
    return instant(-timedelta(minutes=n))


def hours_ago(n: int) -> str:
    """Hours ago."""
    return instant(-timedelta(hours=n))


def minutes_ahead(n: int) -> str:
    """Minutes ahead."""
    return instant(timedelta(minutes=n))


def statement(**over: Any) -> dict[str, Any]:
    """A valid statement addressed to the agent, ``over`` changing fields of it."""
    return {
        "v": 1,
        "purpose": "operator.command",
        "agent": SELF_ID,
        "nonce": "nonce-1",
        "issued_at": minutes_ago(1),
        **over,
    }


def pin_for(agent_id: str) -> OperatorPin:
    """The pin that names ``agent_id`` and its full signing key."""
    return OperatorPin(agent_id, to_base64url(WORLD.keys(agent_id).signing.public_key))


@dataclass
class OperatorWorld:
    """The seat, the agent and a stranger, with their keys written to one config dir."""

    config_dir: str
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for agent_id in (SEAT_ID, SELF_ID, STRANGER_ID):
            save_agent_keys(self.config_dir, agent_id, WORLD.keys(agent_id))

    def context(self, **over: Any) -> OperatorContext:
        """The classifier context for the agent, ``over`` changing fields of it."""
        fields: dict[str, Any] = {
            "pin": pin_for(SEAT_ID),
            "self_agent_id": SELF_ID,
            "config_dir": self.config_dir,
            "now": lambda: NOW_MS,
            "warn": self.warnings.append,
        }
        return OperatorContext(**{**fields, **over})

    def row(self, payload: object, signer: str = SEAT_ID, **over: Any) -> OperatorRowInput:
        """``signer`` seals ``payload`` to the agent and the agent opens it, as a surface does."""
        sealed = encrypt_message(
            self.config_dir, signer, recipient_view(WORLD.keys(SELF_ID), SELF_ID), payload
        )
        result = decrypt_message_sync(
            self.config_dir, SELF_ID, sealed.encrypted_payload, KeyServer(), signer
        )
        fields: dict[str, Any] = {
            "row_id": "row-1",
            "from_agent_id": signer,
            "encryption_version": EncryptionVersion.HPKE_HYBRID_V2,
            "encrypted_payload": sealed.encrypted_payload,
            "result": result,
            "renders_text": True,
        }
        return OperatorRowInput(**{**fields, **over})

    def console_row(
        self, signer: str = SEAT_ID, row_over: dict[str, Any] | None = None, **over: Any
    ) -> OperatorRowInput:
        """A console message: text plus a statement, ``over`` changing one field of it."""
        payload = {"text": "pause the crawl", "rine.operator": statement(**over)}
        return self.row(payload, signer, **(row_over or {}))
