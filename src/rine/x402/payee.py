"""Payee-side x402 orchestrator: reconcile → verify → settle → receipt (TS parity).

The Python mirror of the TS-SDK payee ``fulfill`` — the single place the
per-integration payee tools (hermes/crewai/langchain) delegate to, so the
invariants live once. Contract kept field-for-field with TS:

* **Reconcile-first.** The payee settles against the quote IT issued,
  bound to the ONE quote the payment answers via the signed
  ``extensions[X402_QUOTE_REF_KEY]`` (see :func:`fulfill`), never the payer's echoed
  ``accepted``. Resolution lives in :mod:`rine.x402.payee_settle`; a missing/forged
  ref fails closed.
* **Settle-first.** ``verify`` runs before ``settle``; ``settle`` is skipped on a
  failed verification/reconciliation, and a ``success=False`` receipt is threaded
  back (a business outcome, not an exception) so the payer's thread reaches a
  terminal ``payment-failed`` state. The failure ``payer`` is read off the SIGNED
  payload's ``authorization.from`` (never the facilitator body).

Facilitator verify/settle is plain external HTTP (never a rine endpoint); the
cleartext marker stays ``{status, rail}``-only, built by the message builders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.extract import extract_payment_payload
from rine.x402.messages import build_receipt, receipt_from_settlement
from rine.x402.payee_settle import MatchedQuote, resolve_payee_requirement

if TYPE_CHECKING:
    from rine._client import RineClient
    from rine.types import DecryptedMessage, MessageRead
    from rine.x402.facilitator import FacilitatorClient
    from rine.x402.messages import X402Message
    from rine.x402.types import PaymentRequirements, SettlementResponse


@dataclass
class FulfillResult:
    """Outcome of a payee :func:`fulfill`.

    ``settlement`` is ``None`` on the failed-verification/refusal branch (settle was
    skipped); ``receipt`` is the sent ``rine.v1.x402_receipt`` message.
    ``matched_quote`` reports which payee-issued quote the settled payment
    answered — its id + reconciled amount/asset/network — so an integration can
    confirm the paid quote corresponds to the good it delivers; it is ``None`` on a
    refusal (no quote was matched). Mirrors the TS ``FulfillResult``.
    """

    verification: dict[str, Any]
    settlement: SettlementResponse | None
    receipt: MessageRead
    matched_quote: MatchedQuote | None = None


async def fulfill(
    client: RineClient,
    payment: DecryptedMessage,
    *,
    facilitator: FacilitatorClient,
    agent: str | None = None,
    add_marker: bool = True,
    expected: PaymentRequirements | None = None,
) -> FulfillResult:
    """Reconcile-first payee flow: reconcile → verify → settle → ``receipt``.

    **Quote binding (fail closed).** Before contacting the facilitator the payee
    binds the payment to the ONE quote it answers (:func:`resolve_payee_requirement`):
    the payer stamped that quote's id into the signed ``extensions[X402_QUOTE_REF_KEY]``
    and the payee re-loads THAT message (proving it is a payee-issued quote in this
    conversation), then reconciles ``pp['accepted']`` against its ``accepts[]``. That
    RECONCILED payee-owned requirement (never ``pp['accepted']``) is forwarded to
    ``/verify`` + ``/settle``. A no/forged/cross-quote ref — or a malformed payload
    — is REFUSED with a ``success=False`` receipt and no settle; pass ``expected``
    to authorise an out-of-band quote (it wins over the ref). On a valid verification
    ``/settle`` runs and its response is the receipt verbatim; otherwise ``/settle`` is
    skipped and a failure receipt (``payer``/``network`` off the SIGNED payload) threads.

    Args:
        client: Async :class:`~rine.RineClient` used to load the quote + reply.
        payment: The decrypted ``rine.v1.x402_payment`` message to fulfil.
        facilitator: Caller-owned ``FacilitatorClient`` (external HTTP, never rine).
        agent: The acting payee agent (handle/UUID) for multi-agent orgs.
        add_marker: Emit the ``{status, rail}`` cleartext marker (default ``True``).
        expected: Explicit expected terms for an out-of-band quote; the authoritative
            single-entry quote when supplied. Absent both a ref and ``expected``,
            fulfil fails closed.

    Raises:
        X402Error: If ``payment`` is the wrong type or cannot be decrypted (a
            malformed body or a reconciliation mismatch are graceful receipts).
    """
    try:
        pp = extract_payment_payload(payment)
    except X402Error as exc:
        if exc.code == X402ErrorCode.MALFORMED_PAYLOAD:
            return await _refuse(client, payment, agent, add_marker, exc, network="", payer="")
        raise

    try:
        requirement, matched = await resolve_payee_requirement(
            client,
            pp,
            str(payment.conversation_id),
            expected=expected,
            agent=agent,
        )
    except X402Error as exc:
        auth = pp.get("payload", {}).get("authorization", {})
        return await _refuse(
            client,
            payment,
            agent,
            add_marker,
            exc,
            network=str(pp.get("accepted", {}).get("network", "")),
            payer=str(auth.get("from", "")),
        )

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
    return FulfillResult(
        verification=verification,
        settlement=settlement,
        receipt=receipt,
        matched_quote=matched,
    )


async def _refuse(
    client: RineClient,
    payment: DecryptedMessage,
    agent: str | None,
    add_marker: bool,
    error: X402Error,
    *,
    network: str,
    payer: str,
) -> FulfillResult:
    """Fail closed: thread a ``success=False`` receipt (no settle) for a refusal.

    Used for a malformed payload and a reconciliation mismatch / missing or
    forged quote-ref — the facilitator is never contacted, no funds move,
    and the typed error ``code`` becomes the receipt's ``errorReason`` (terminal
    ``payment-failed``, no stack trace). ``matched_quote`` stays ``None``.
    """
    receipt_msg = build_receipt(
        success=False,
        transaction="",
        network=network,
        payer=payer,
        error_reason=error.code,
        add_marker=add_marker,
    )
    receipt = await _reply_receipt(client, payment, receipt_msg, agent)
    return FulfillResult(
        verification={"isValid": False, "invalidReason": error.code},
        settlement=None,
        receipt=receipt,
        matched_quote=None,
    )


async def send_receipt(
    client: RineClient,
    payment: DecryptedMessage,
    settlement: SettlementResponse,
    *,
    agent: str | None = None,
    add_marker: bool = True,
) -> MessageRead:
    """Thread a ``receipt`` (a facilitator ``SettlementResponse``) to the payer.

    Parity with TS ``sendReceipt``: wraps the settlement verbatim via
    :func:`receipt_from_settlement` (unknown keys preserved) and replies in the
    payment's thread — the ``settle-after-delivery`` flow where verify/settle already
    ran separately.
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
