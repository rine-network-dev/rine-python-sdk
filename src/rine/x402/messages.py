"""Build and parse the three x402 message payloads.

Each payload is the verbatim x402 V2 object (``PaymentRequired`` /
``PaymentPayload`` / ``SettlementResponse``) — unknown keys are preserved. These
builders produce the *payload dict* plus the send fields (message type,
``content_type``, and the optional cleartext marker) that a caller passes to
``client.send(...)`` / ``client.reply(...)``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, TypeGuard

from rine._constants import MessageType
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.marker import marker_metadata
from rine.x402.types import (
    X402_VERSION,
    PaymentRequired,
    PaymentRequirements,
    SettlementResponse,
)

_CONTENT_TYPE = "application/json"


def _is_object(value: Any) -> TypeGuard[dict[str, Any]]:
    """A non-null mapping — the shape every x402 sub-object must be."""
    return isinstance(value, dict)


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
    parsed mapping, and returns the object UNCHANGED (unknown keys preserved) so
    ``parse(build(x)) == x`` byte-for-byte. A body that is not a JSON object raises
    a typed ``X402Error(MALFORMED_PAYLOAD)`` — never a bare ``ValueError`` — so
    callers get a structured, catchable refusal.

    Parser-parity note: the TS ``parseX402Payload(type, plaintext)``
    takes the message type and folds the per-type structural checks inline. The
    Python parser is intentionally single-argument (type-agnostic JSON-object
    validation only); the equivalent per-type checks live at the type-aware call
    sites — a payment's ``accepted``/``authorization`` in
    :func:`rine.x402.extract.extract_payment_payload`, a quote's ``accepts[]`` in
    :func:`rine.x402.quote_ref.load_referenced_quote`. This split is deliberate and
    consistent (it keeps this function's single-argument public contract) — the same
    malformed body is a typed refusal on both SDKs, only the check's location differs.

    Raises:
        X402Error: ``malformed-payload`` when the body is not a JSON object.
    """
    if isinstance(plaintext, str):
        try:
            obj = json.loads(plaintext)
        except (ValueError, TypeError) as exc:
            raise X402Error(
                X402ErrorCode.MALFORMED_PAYLOAD, "x402 payload is not valid JSON"
            ) from exc
    else:
        obj = plaintext
    if not _is_object(obj):
        raise X402Error(X402ErrorCode.MALFORMED_PAYLOAD, "x402 payload is not a JSON object")
    return obj
