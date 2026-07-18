"""Build and parse the three x402 message payloads (Python half of REQ-M04/M01).

Each payload is the verbatim x402 V2 object (``PaymentRequired`` /
``PaymentPayload`` / ``SettlementResponse``) — unknown keys are preserved. These
builders produce the *payload dict* plus the send fields (message type,
``content_type``, and the optional cleartext marker) that a caller passes to
``client.send(...)`` / ``client.reply(...)``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rine._constants import MessageType
from rine.x402.marker import marker_metadata
from rine.x402.types import (
    X402_VERSION,
    PaymentRequired,
    PaymentRequirements,
    SettlementResponse,
)

_CONTENT_TYPE = "application/json"


@dataclass
class X402Message:
    """A ready-to-send x402 message: payload + type + content_type + marker.

    ``payload`` is the verbatim x402 object (encrypted by ``send``/``reply``).
    ``metadata`` carries the optional cleartext marker (empty when ``add_marker``
    is ``False``). Spread the fields into the client call::

        msg = build_payment_required(accepts=[...])
        client.send(to, msg.payload, message_type=msg.message_type,
                    content_type=msg.content_type, metadata=msg.metadata)
    """

    payload: dict[str, Any]
    message_type: str
    content_type: str = _CONTENT_TYPE
    metadata: dict[str, Any] = field(default_factory=dict)


def _finish(
    payload: dict[str, Any], message_type: str, add_marker: bool, success: bool
) -> X402Message:
    metadata = marker_metadata(message_type, success=success) if add_marker else {}
    return X402Message(payload=payload, message_type=message_type, metadata=metadata)


def build_payment_required(
    accepts: list[PaymentRequirements],
    *,
    resource: dict[str, Any] | None = None,
    error: str | None = None,
    extensions: dict[str, Any] | None = None,
    add_marker: bool = True,
) -> X402Message:
    """Payee quote: build a ``PaymentRequired`` (the 402 challenge, ``accepts[]``)."""
    payload: PaymentRequired = {"x402Version": X402_VERSION, "accepts": accepts}
    if error is not None:
        payload["error"] = error
    if resource is not None:
        payload["resource"] = resource
    payload["extensions"] = extensions if extensions is not None else {}
    return _finish(payload, MessageType.X402_PAYMENT_REQUIRED, add_marker, True)


def payment_message(payment_payload: dict[str, Any], *, add_marker: bool = True) -> X402Message:
    """Payer: wrap a signed ``PaymentPayload`` (from ``build_payment_payload``)."""
    return _finish(payment_payload, MessageType.X402_PAYMENT, add_marker, True)


def build_receipt(
    *,
    success: bool,
    transaction: str,
    network: str,
    payer: str,
    error_reason: str | None = None,
    amount: str | None = None,
    extensions: dict[str, Any] | None = None,
    add_marker: bool = True,
) -> X402Message:
    """Payee receipt: build a ``SettlementResponse`` (marker completed/failed)."""
    payload: SettlementResponse = {
        "success": success,
        "transaction": transaction,
        "network": network,
        "payer": payer,
    }
    if error_reason is not None:
        payload["errorReason"] = error_reason
    if amount is not None:
        payload["amount"] = amount
    if extensions is not None:
        payload["extensions"] = extensions
    return _finish(payload, MessageType.X402_RECEIPT, add_marker, success)


def receipt_from_settlement(
    settlement: SettlementResponse, *, add_marker: bool = True
) -> X402Message:
    """Wrap a facilitator ``SettlementResponse`` verbatim as a receipt message.

    Preferred over :func:`build_receipt` when relaying a facilitator's ``/settle``
    result — it preserves unknown keys (``extensions`` etc.) byte-for-byte.
    """
    success = bool(settlement.get("success"))
    return _finish(dict(settlement), MessageType.X402_RECEIPT, add_marker, success)


def parse_x402_payload(plaintext: str | dict[str, Any]) -> dict[str, Any]:
    """Parse a decrypted x402 message plaintext into its verbatim object dict.

    Accepts the raw decrypted JSON string (as the inbox stores it) or an already
    parsed mapping. Raises ``ValueError`` if the plaintext is not a JSON object.
    """
    obj = json.loads(plaintext) if isinstance(plaintext, str) else plaintext
    if not isinstance(obj, dict):
        raise ValueError("x402 payload is not a JSON object")
    return obj
