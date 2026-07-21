"""F-1 reconciliation: the pure payee-quote-binding invariant (mirror of TS tests).

``reconcile_payment`` returns the payee-authored requirement a payment satisfies, or
raises a typed refusal on every mismatch axis (payTo redirect, underpay, wrong asset,
wrong network, wrong scheme, worthless token). R-1 binds a payment to the ONE quote it
answers, so the reconciler is always handed a single quote's ``accepts[]`` (the
conversation-wide union is dissolved).

The reconciler now takes the FULL ``PaymentPayload`` (findings #3/#4): it binds to the
tier the payer's own ``accepted`` block NAMES (exact atomic amount) — not the first tier
a ``>=`` check happens to satisfy — and enforces a local defense-in-depth check that the
SIGNED EIP-3009 ``payload.authorization.value`` covers that tier, never the payer-echoed
``accepted.amount``.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.reconcile import reconcile_payment

QUOTE = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "150000",
    "asset": "0xEURC",
    "payTo": "0xMerchant",
}


def _payment(*, signed: str | None = None, **overrides: object) -> dict[str, Any]:
    """A signed ``PaymentPayload``. ``accepted`` names a tier; ``signed`` is the
    EIP-3009 ``authorization.value`` (defaults to the named amount = honest payer)."""
    accepted = {**QUOTE, **overrides}
    value = signed if signed is not None else accepted["amount"]
    return {
        "x402Version": 2,
        "accepted": accepted,
        "payload": {"authorization": {"from": "0xPayer", "to": "0xMerchant", "value": value}},
    }


def test_reconcile_returns_quote_on_exact_match() -> None:
    """An exact match returns the PAYEE quote entry (not the payment's echo)."""
    quote_entry = dict(QUOTE)
    assert reconcile_payment(_payment(), [quote_entry]) is quote_entry


def test_reconcile_allows_overpayment_via_signed_value() -> None:
    """Overpayment rides the SIGNED value (> quoted); ``accepted`` still names the tier."""
    assert reconcile_payment(_payment(signed="200000"), [QUOTE]) == QUOTE


def test_reconcile_matches_asset_and_payto_case_insensitively() -> None:
    """asset/payTo compare case-insensitively (hex address casing is irrelevant)."""
    payment = _payment(asset="0xeurc", payTo="0xmerchant")
    assert reconcile_payment(payment, [QUOTE]) == QUOTE


def test_reconcile_refuses_underpayment() -> None:
    """A named amount matching no tier (1 atomic unit vs quoted 150000) is refused."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(amount="1"), [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_payto_redirect() -> None:
    """A redirected payTo matches no quote → refuse."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(payTo="0xMallory"), [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_wrong_asset() -> None:
    """A worthless-token asset swap matches no quote → refuse."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(asset="0xWorthless"), [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_wrong_network() -> None:
    """A different network matches no quote → refuse."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(network="eip155:1"), [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_wrong_scheme() -> None:
    """A different scheme matches no quote → refuse."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(scheme="permit2"), [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_empty_quote_fail_closed() -> None:
    """No payee quote at all is a typed no-quote refusal (fail closed)."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(), [])
    assert exc.value.code == X402ErrorCode.NO_QUOTE


def test_reconcile_picks_the_matching_entry_among_several() -> None:
    """With several quoted options, the matching entry is returned."""
    other = {**QUOTE, "asset": "0xUSDC"}
    assert reconcile_payment(_payment(), [other, QUOTE]) == QUOTE


def test_reconcile_refuses_missing_asset_without_crashing() -> None:
    """A payment whose ``accepted`` omits ``asset`` refuses gracefully, no crash.

    Parity guard with the TS suite: a malformed but well-typed envelope (valid amount,
    absent asset) must yield a typed REQUIREMENT_MISMATCH — never an AttributeError /
    TypeError — so every surface threads a graceful receipt (F-4).
    """
    payment = _payment()
    del payment["accepted"]["asset"]
    with pytest.raises(X402Error) as exc:
        reconcile_payment(payment, [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_missing_payto_without_crashing() -> None:
    """A payment whose ``accepted`` omits ``payTo`` refuses gracefully, no crash."""
    payment = _payment()
    del payment["accepted"]["payTo"]
    with pytest.raises(X402Error) as exc:
        reconcile_payment(payment, [QUOTE])
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


# --- #3/#4 parity: multi-tier same-asset selection + signed-value defense ----

TIER_LOW = {**QUOTE, "amount": "100000"}
TIER_HIGH = {**QUOTE, "amount": "500000"}
TWO_TIER = [TIER_LOW, TIER_HIGH]


def test_reconcile_two_tier_returns_payer_named_high_tier() -> None:
    """#3: a same-asset two-tier quote returns the tier the payer NAMED (5.0 → 5.0)."""
    assert reconcile_payment(_payment(amount="500000"), TWO_TIER) is TIER_HIGH


def test_reconcile_two_tier_returns_payer_named_low_tier() -> None:
    """#3: the 1.0 payer binds to the low tier, never the first-satisfied entry."""
    assert reconcile_payment(_payment(amount="100000"), TWO_TIER) is TIER_LOW


def test_reconcile_two_tier_refuses_between_tier_amount() -> None:
    """#3: a named amount that exactly matches no tier is refused (no ``>=`` slack)."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(amount="300000"), TWO_TIER)
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_signed_value_below_named_tier() -> None:
    """#4: signed value under the named tier is refused LOCALLY (underpayment guard)."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(amount="500000", signed="400000"), TWO_TIER)
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH
    assert exc.value.details == {"signed": "400000", "required": "500000"}


def test_reconcile_refuses_cross_tier_signed_below_named() -> None:
    """#4: cross-tier attack (name the 5.0 tier, sign only 1.0) is refused locally."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(amount="500000", signed="100000"), TWO_TIER)
    assert exc.value.code == X402ErrorCode.REQUIREMENT_MISMATCH


def test_reconcile_refuses_non_integer_signed_value() -> None:
    """#4: a non-integer signed value is a typed INVALID_REQUIREMENT (no crash)."""
    with pytest.raises(X402Error) as exc:
        reconcile_payment(_payment(signed="12.5"), [QUOTE])
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT


def test_reconcile_refuses_missing_signed_value() -> None:
    """#4: a payload with no ``authorization.value`` is a typed INVALID_REQUIREMENT."""
    payment = _payment()
    del payment["payload"]["authorization"]["value"]
    with pytest.raises(X402Error) as exc:
        reconcile_payment(payment, [QUOTE])
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT
