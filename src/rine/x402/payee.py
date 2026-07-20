"""Payee-side x402 orchestrator: verify → settle → receipt (Python parity of TS).

This is the Python mirror of the TS-SDK payee ``fulfill``
(``rine-ts-sdk/src/resources/x402-payee.ts:87-141``). It stops the per-integration
payee tools (hermes/crewai/langchain) from hand-composing verify→settle→receipt,
so the orchestration — and its invariants — live in exactly one place.

Contract kept identical to TS, field-for-field:

* **Settle-first.** ``verify`` runs before ``settle``; ``settle`` is skipped
  entirely on a failed verification.
* **Failed verification is a business outcome, not an exception** — a
  ``success=False`` receipt is threaded back so the payer's thread reaches a
  terminal ``payment-failed`` state.
* **Synthetic-failure attribution reads the SIGNED payload, never the facilitator
  response**: ``payer`` from ``payload.authorization.from`` and the default reason
  ``"verification_failed"`` (matching ``x402-payee.ts:110-115``).

verify/settle are plain external HTTP through the caller-owned
:class:`~rine.x402.facilitator.FacilitatorClient` — never a rine endpoint (the
pure-metadata-relay posture). The cleartext receipt marker stays ``{status, rail}``
only; it is built by the message builders, never widened here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine._constants import MessageType
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.messages import build_receipt, parse_x402_payload, receipt_from_settlement

if TYPE_CHECKING:
    from rine._client import RineClient
    from rine.types import DecryptedMessage, MessageRead
    from rine.x402.facilitator import FacilitatorClient
    from rine.x402.messages import X402Message
    from rine.x402.types import PaymentPayload, SettlementResponse


@dataclass
class FulfillResult:
    """Outcome of a payee :func:`fulfill`.

    ``settlement`` is ``None`` on the failed-verification branch (settle was
    skipped); ``receipt`` is the sent ``rine.v1.x402_receipt`` message. Mirrors
    the TS ``FulfillResult`` (``x402-shared.ts:83-87``).
    """

    verification: dict[str, Any]
    settlement: SettlementResponse | None
    receipt: MessageRead


def extract_payment_payload(msg: DecryptedMessage) -> PaymentPayload:
    """Pull the verbatim x402 ``PaymentPayload`` out of a received payment message.

    Guards ``msg.type == rine.v1.x402_payment``, a decrypt failure, and a missing
    plaintext, mirroring TS ``extractPaymentPayload`` (``x402-extract.ts:45-52``)
    so a wrong-type or undecryptable message raises a structured refusal BEFORE any
    facilitator work runs. Structural parsing reuses :func:`parse_x402_payload`.

    Raises:
        X402Error: With code ``invalid-requirement`` on a wrong message type, a
            decrypt failure, or a missing plaintext.
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
    return parse_x402_payload(msg.plaintext)


async def fulfill(
    client: RineClient,
    payment: DecryptedMessage,
    *,
    facilitator: FacilitatorClient,
    agent: str | None = None,
    add_marker: bool = True,
) -> FulfillResult:
    """Settle-first payee flow: verify → settle → send ``receipt`` in-thread.

    On a valid verification the facilitator ``/settle`` response becomes the
    receipt body verbatim. On a failed verification, ``/settle`` is SKIPPED and a
    ``success=False`` receipt is threaded back (a business outcome, not an
    exception) — its ``payer``/``network`` are read off the SIGNED payload and the
    reason defaults to ``"verification_failed"``, matching the TS contract exactly.

    Args:
        client: The async :class:`~rine.RineClient` used to thread the receipt.
        payment: The decrypted ``rine.v1.x402_payment`` message to fulfil.
        facilitator: A caller-constructed, caller-owned ``FacilitatorClient``
            (``async with FacilitatorClient(...) as fac``). verify/settle are plain
            external HTTP, never a rine route.
        agent: The acting agent (handle/UUID) for multi-agent orgs.
        add_marker: Emit the ``{status, rail}`` cleartext marker (default ``True``).

    Raises:
        X402Error: If ``payment`` is the wrong type or cannot be decrypted.
    """
    pp = extract_payment_payload(payment)
    requirement = pp["accepted"]
    verification = await facilitator.verify(pp, requirement)

    settlement: SettlementResponse | None = None
    if verification.get("isValid"):
        settlement = await facilitator.settle(pp, requirement)
        receipt_msg = receipt_from_settlement(settlement, add_marker=add_marker)
    else:
        auth = pp.get("payload", {}).get("authorization", {})
        receipt_msg = build_receipt(
            success=False,
            transaction="",
            network=str(requirement.get("network", "")),
            payer=str(auth.get("from", "")),
            error_reason=str(verification.get("invalidReason") or "verification_failed"),
            add_marker=add_marker,
        )

    receipt = await _reply_receipt(client, payment, receipt_msg, agent)
    return FulfillResult(verification=verification, settlement=settlement, receipt=receipt)


async def send_receipt(
    client: RineClient,
    payment: DecryptedMessage,
    settlement: SettlementResponse,
    *,
    agent: str | None = None,
    add_marker: bool = True,
) -> MessageRead:
    """Thread a ``receipt`` (a facilitator ``SettlementResponse``) to the payer.

    Parity with TS ``sendReceipt`` (``x402-payee.ts:127-143``): wraps the
    settlement verbatim via :func:`receipt_from_settlement` (unknown keys
    preserved) and replies in the payment's thread. Use this for the
    ``settle-after-delivery`` flow where verify/settle already ran separately.
    """
    receipt_msg = receipt_from_settlement(settlement, add_marker=add_marker)
    return await _reply_receipt(client, payment, receipt_msg, agent)


async def _reply_receipt(
    client: RineClient,
    payment: DecryptedMessage,
    receipt_msg: X402Message,
    agent: str | None,
) -> MessageRead:
    """Thread a built receipt message back to the payer's payment (shared path)."""
    return await client.reply(
        str(payment.id),
        receipt_msg.payload,
        message_type=receipt_msg.message_type,
        metadata=receipt_msg.metadata,
        content_type=receipt_msg.content_type,
        agent=agent,
    )
