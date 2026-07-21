"""Extract + structurally validate a received x402 ``PaymentPayload`` (TS parity).

Python mirror of ``rine-ts-sdk/src/resources/x402-extract.ts``: pull the verbatim
x402 ``PaymentPayload`` out of a decrypted ``rine.v1.x402_payment`` message and
refuse — with a typed :class:`X402Error`, never a deref crash — anything that is the
wrong type, undecryptable, or structurally malformed. Keeping this off the
orchestrator keeps :mod:`rine.x402.payee` focused on the verify/settle flow.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._constants import MessageType
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.messages import parse_x402_payload

if TYPE_CHECKING:
    from rine.types import DecryptedMessage
    from rine.x402.types import PaymentPayload


def extract_payment_payload(msg: DecryptedMessage) -> PaymentPayload:
    """Pull the verbatim x402 ``PaymentPayload`` out of a received payment message.

    Guards wrong type / decrypt failure / missing plaintext (mirroring TS
    ``extractPaymentPayload``) then delegates JSON parsing to
    :func:`parse_x402_payload` and per-type structure to
    :func:`_require_payment_structure`.

    Raises:
        X402Error: ``invalid-requirement`` on a wrong type / decrypt failure /
            missing plaintext; ``malformed-payload`` when the body lacks the
            ``accepted`` or ``payload.authorization`` objects.
    """
    if msg.type != MessageType.X402_PAYMENT:
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"expected a {MessageType.X402_PAYMENT} message, got {msg.type}",
        )
    if msg.decrypt_error is not None:
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"cannot read x402 payload: message {msg.id} failed to decrypt ({msg.decrypt_error})",
        )
    if msg.plaintext is None:
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"cannot read x402 payload: message {msg.id} has no plaintext",
        )
    pp = parse_x402_payload(msg.plaintext)
    _require_payment_structure(pp)
    return pp


def _require_payment_structure(pp: PaymentPayload) -> None:
    """Validate a payment carries ``accepted`` + ``payload.authorization``.

    Mirrors the TS ``parseX402Payload`` PAYMENT-type checks so a hostile
    ``{"payload":{}}`` body is a typed ``malformed-payload`` refusal here, not a
    downstream ``KeyError``/``TypeError`` deref crash. The fulfil flow turns this
    into a graceful failure receipt.
    """
    if not isinstance(pp.get("accepted"), dict):
        raise X402Error(
            X402ErrorCode.MALFORMED_PAYLOAD, "payment has no `accepted` requirement object"
        )
    payload = pp.get("payload")
    if not isinstance(payload, dict):
        raise X402Error(X402ErrorCode.MALFORMED_PAYLOAD, "payment has no signed payload")
    if not isinstance(payload.get("authorization"), dict):
        raise X402Error(
            X402ErrorCode.MALFORMED_PAYLOAD, "payment payload has no `authorization` object"
        )
