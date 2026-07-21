"""Payee-side reconciliation — the canonical x402 resource-server invariant.

Python mirror of ``rine-core/src/x402/reconcile.ts``, field-for-field. A payee
settles a payment ONLY against terms IT authored (the quote it issued), never
against the payer's echoed ``accepted`` block: a mismatched ``payTo``, amount,
asset, or network yields a ``success=False`` receipt and no settle.

This module is PURE — zero I/O. A payment is bound to the ONE quote it answers (via
the signed ``extensions[X402_QUOTE_REF_KEY]``); the payee loads that single quote
(``rine.x402.quote_ref.load_referenced_quote``) and passes its ``accepts[]`` here.
Binding to that single quote — not a conversation-wide union of every quote — keeps
a payment from settling against any quote other than the one it answers. The
I/O-shaped ref loading lives in :mod:`rine.x402.payee_settle`, shared by every payee
surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine.x402.assets import parse_atomic_amount, parse_atomic_units
from rine.x402.errors import X402Error, X402ErrorCode

if TYPE_CHECKING:
    from collections.abc import Sequence

    from rine.x402.types import PaymentPayload, PaymentRequirements


def _eq_ci(a: object, b: object) -> bool:
    """Case-insensitive equality for hex addresses / CAIP ids (never loose ==).

    Absent values coerce to ``""`` so a malformed payer ``accepted`` that omits
    ``asset`` or ``payTo`` yields a clean non-match instead of an ``AttributeError``
    — field-for-field with the TS ``eqCi`` (``String(a ?? "")``). Keeps the failure
    as a typed ``X402Error(REQUIREMENT_MISMATCH)`` so every surface threads a
    graceful receipt rather than an uncaught throw.
    """
    return str(a if a is not None else "").lower() == str(b if b is not None else "").lower()


def reconcile_payment(
    payment: PaymentPayload,
    quote_accepts: Sequence[PaymentRequirements],
) -> PaymentRequirements:
    """Return the payee-authored requirement the payment legitimately answers, or raise.

    A quote entry matches iff ALL hold: same ``scheme``; same ``network``; same
    ``asset`` (case-insensitive); same ``payTo`` (case-insensitive); and the tier the
    payer's OWN ``accepted`` block NAMES (its exact atomic amount) equals the quote
    entry's atomic amount.

    Matching on the EXACT named amount (not the first tier the amount happens to
    satisfy) is load-bearing: a multi-tier same-asset quote — ``accepts=[{1.0},{5.0}]``
    on one asset/network/payTo — must return the tier the 5.0 payer selected, never
    the cheaper ``1.0`` entry a ``>=`` first-match would pick. Binding to the NAMED
    tier keeps the settled amount and ``matchedQuote`` aligned with the quote the
    payer answered.

    Defense-in-depth: the SIGNED EIP-3009 ``payload.authorization.value`` — not the
    payer-controlled echoed ``accepted.amount`` — must cover the quoted atomic amount,
    so a payment whose signed value underfunds the tier it names is refused LOCALLY
    even if a non-conformant facilitator would settle it. Overpayment (a signed value
    above the tier) is still allowed. Amounts compare in the token's own atomic units
    — asset+network already match, so no decimal scaling is needed and unknown-decimal
    assets don't spuriously block here.

    The RETURNED value is the payee's own requirement; callers forward THAT to the
    facilitator, never ``payment['accepted']``.

    Raises:
        X402Error: ``no-quote`` when ``quote_accepts`` is empty (fail closed);
            ``requirement-mismatch`` when no entry matches or the signed value
            underfunds the named tier; ``invalid-requirement`` when the signed
            value is missing / non-integer.
    """
    if len(quote_accepts) == 0:
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            "No payee-issued quote to reconcile against — refusing to settle "
            "payer-authored terms (fail closed)",
        )
    accepted: PaymentRequirements = payment.get("accepted") or {}
    # The tier the payer's echoed ``accepted`` names, and the value it actually SIGNED.
    named = parse_atomic_amount(accepted)
    authorization = (payment.get("payload") or {}).get("authorization") or {}
    signed = parse_atomic_units(
        str(authorization.get("value") if authorization.get("value") is not None else ""),
        "Signed authorization value",
    )
    for quote in quote_accepts:
        if accepted.get("scheme") != quote.get("scheme"):
            continue
        if accepted.get("network") != quote.get("network"):
            continue
        if not _eq_ci(accepted.get("asset"), quote.get("asset")):
            continue
        if not _eq_ci(accepted.get("payTo"), quote.get("payTo")):
            continue
        quoted = parse_atomic_amount(quote)
        if named != quoted:
            continue  # bind to the NAMED tier, not first-satisfied
        if signed < quoted:
            raise X402Error(
                X402ErrorCode.REQUIREMENT_MISMATCH,
                "Signed authorization value underfunds the quoted requirement — "
                "refusing to settle (local underpayment guard)",
                {"signed": str(signed), "required": str(quoted)},
            )
        return quote
    raise X402Error(
        X402ErrorCode.REQUIREMENT_MISMATCH,
        "Payment matches no payee-issued quote (scheme/network/asset/payTo/amount) "
        "— refusing to settle",
        {
            "scheme": accepted.get("scheme"),
            "network": accepted.get("network"),
            "asset": accepted.get("asset"),
            "payTo": accepted.get("payTo"),
        },
    )
