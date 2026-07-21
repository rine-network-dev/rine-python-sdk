"""Payee-side requirement resolution + reconciling verify/settle.

Python mirror of the resolution/settle half of ``rine-core/src/x402/payee-settle.ts``
and the TS-SDK ``resolveRequirement``. Binds an incoming payment to the payee's OWN
quote BEFORE any facilitator contact: an explicit operator override wins, else the
payment's signed quote-ref (``extensions[X402_QUOTE_REF_KEY]``) is loaded and
reconciled. Every unresolved path raises a typed ``NO_QUOTE`` (fail closed) — the
payer's echoed ``accepted`` block is never forwarded to the facilitator.

The verify → settle → receipt ladder + receipt threading stay in :mod:`rine.x402.payee`
(the Python SDK threads its own receipt, mirroring the TS-SDK payee); this module is
resolution + the standalone ``settle-after-delivery`` primitives only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine.types import DecryptedMessage
from rine.x402.assets import requirement_amount
from rine.x402.extract import extract_payment_payload
from rine.x402.quote_ref import load_referenced_quote
from rine.x402.reconcile import reconcile_payment

if TYPE_CHECKING:
    from rine._client import RineClient
    from rine.x402.facilitator import FacilitatorClient
    from rine.x402.types import PaymentPayload, PaymentRequirements, SettlementResponse


@dataclass(frozen=True)
class MatchedQuote:
    """Provenance of the reconciled quote so an integration binds good⇄quote.

    ``quote_message_id`` is the referenced ``x402_payment_required`` id the payment
    answered, or ``None`` for an operator ``expected``-terms override. ``amount`` is
    the reconciled requirement's atomic amount. Mirrors the TS ``MatchedQuote``.
    """

    quote_message_id: str | None
    amount: str
    asset: str
    network: str


def _to_match(req: PaymentRequirements, quote_message_id: str | None) -> MatchedQuote:
    """Reduce a reconciled payee-owned requirement to its match provenance."""
    return MatchedQuote(
        quote_message_id=quote_message_id,
        amount=requirement_amount(req),
        asset=str(req.get("asset", "")),
        network=str(req.get("network", "")),
    )


def to_payment_payload(payment: DecryptedMessage | PaymentPayload) -> PaymentPayload:
    """Accept either a decrypted ``payment`` message or a raw ``PaymentPayload``.

    A message is structurally validated + unwrapped via
    :func:`rine.x402.extract.extract_payment_payload`; a bare payload
    is returned as-is. Mirrors the TS-SDK ``toPaymentPayload``.
    """
    if isinstance(payment, DecryptedMessage):
        return extract_payment_payload(payment)
    return payment


def resolve_requirement(
    pp: PaymentPayload, expected: PaymentRequirements | None
) -> PaymentRequirements:
    """Resolve the payee-owned requirement with NO thread context (standalone path).

    Reconciles the payment against the operator's ``expected`` terms ONLY; without
    them it fails closed with ``NO_QUOTE`` rather than trusting the payer's echoed
    ``accepted``. Mirrors the TS-SDK ``resolveRequirement(pp, [], expected)`` used by
    the ``settle-after-delivery`` verify/settle primitives.
    """
    return reconcile_payment(pp, [expected] if expected is not None else [])


async def resolve_payee_requirement(
    client: RineClient,
    pp: PaymentPayload,
    conversation_id: str,
    *,
    expected: PaymentRequirements | None,
    agent: str | None,
) -> tuple[PaymentRequirements, MatchedQuote]:
    """Resolve the payee-owned requirement to settle against + its provenance.

    An explicit ``expected`` override wins (operator intent, no ref needed); else the
    payment's referenced quote is loaded via :func:`load_referenced_quote` and
    reconciled. Returns the matched payee-authored requirement (forwarded to the
    facilitator, never ``pp['accepted']``) and its :class:`MatchedQuote`, or raises a
    typed :class:`X402Error` (``no-quote`` / ``requirement-mismatch``) — fail closed.
    """
    if expected is not None:
        requirement = reconcile_payment(pp, [expected])
        return requirement, _to_match(requirement, None)
    ref = await load_referenced_quote(client, pp, conversation_id, agent)
    requirement = reconcile_payment(pp, ref.accepts)
    return requirement, _to_match(requirement, ref.message_id)


async def verify(
    payment: DecryptedMessage | PaymentPayload,
    *,
    facilitator: FacilitatorClient,
    expected: PaymentRequirements | None = None,
) -> dict[str, object]:
    """Reconciling standalone verify (no broadcast) — ``settle-after-delivery``.

    Binds the payment to the payee-owned ``expected`` terms FIRST; with no
    ``expected`` (no thread context here) it fails closed with ``NO_QUOTE`` rather
    than trusting the payer's echoed ``accepted``. The RECONCILED requirement — never
    ``pp['accepted']`` — is what reaches the facilitator, so a raw ``FacilitatorClient``
    caller still settles only payee-authored terms. Mirrors the TS-SDK payee ``verify``.
    """
    pp = to_payment_payload(payment)
    requirement = resolve_requirement(pp, expected)
    return await facilitator.verify(pp, requirement)


async def settle(
    payment: DecryptedMessage | PaymentPayload,
    *,
    facilitator: FacilitatorClient,
    expected: PaymentRequirements | None = None,
) -> SettlementResponse:
    """Reconciling standalone settle (broadcast). See :func:`verify` — same binding."""
    pp = to_payment_payload(payment)
    requirement = resolve_requirement(pp, expected)
    return await facilitator.settle(pp, requirement)
