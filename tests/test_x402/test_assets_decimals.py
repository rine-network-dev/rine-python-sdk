"""Unknown-decimal assets fail closed instead of being valued as 6-decimal.

A non-registry asset has no trustworthy decimals; assuming 6 under-values a sub-6
token 10^k× and bypasses every spend cap. ``resolve_decimals`` /
``requirement_canonical_amount`` now RAISE ``unknown-asset-decimals`` for such an
asset. A registry asset is still priced normally.
"""

from __future__ import annotations

import pytest

from rine.x402.assets import (
    CANONICAL_DECIMALS,
    parse_atomic_amount,
    parse_units,
    requirement_canonical_amount,
    resolve_decimals,
)
from rine.x402.errors import X402Error, X402ErrorCode

# Registry entries (Circle deployments in the known-asset table).
BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
UNKNOWN = "0x1111111111111111111111111111111111111111"


def test_resolve_decimals_returns_registry_decimals() -> None:
    """A registry asset resolves to its declared 6 decimals."""
    assert resolve_decimals(BASE, EURC) == 6


def test_resolve_decimals_refuses_unknown_asset() -> None:
    """A non-registry asset is a typed unknown-asset-decimals refusal (fail closed)."""
    with pytest.raises(X402Error) as exc:
        resolve_decimals(BASE, UNKNOWN)
    assert exc.value.code == X402ErrorCode.UNKNOWN_ASSET_DECIMALS


def test_canonical_amount_prices_registry_asset() -> None:
    """A registry 6-decimal asset is canonicalised without scaling."""
    req = {"network": BASE, "asset": EURC, "amount": "150000"}
    assert requirement_canonical_amount(req) == 150000


def test_canonical_amount_refuses_unknown_asset() -> None:
    """The cap-accounting inherits the refusal — an unknown asset is never mis-priced."""
    req = {"network": BASE, "asset": UNKNOWN, "amount": "10000"}
    with pytest.raises(X402Error) as exc:
        requirement_canonical_amount(req)
    assert exc.value.code == X402ErrorCode.UNKNOWN_ASSET_DECIMALS


# ---------------------------------------------------------------------------
# Finding #6: ``$`` anchor accepts a trailing newline in Python but not in the
# TS SDK (``/^\d+$/`` rejects). ``\Z`` anchors close the cross-SDK divergence.
# ---------------------------------------------------------------------------

# Trailing-whitespace variants a lenient ``$`` would have parsed. The atomic
# amount is read off a facilitator/payer-supplied requirement, so a lax anchor
# means the two SDKs disagree on whether a payment string is even well-formed.
_TRAILING_ATOMIC = ("100000\n", "100000\r\n", "100000\r", "100000 ", "100000\t", "100000\n\n")
_TRAILING_DECIMAL = ("1.5\n", "1.5\r\n", "1.5 ", "1.5\t", "100000\n")


@pytest.mark.parametrize("amount", _TRAILING_ATOMIC)
def test_parse_atomic_amount_rejects_trailing_whitespace(amount: str) -> None:
    """A requirement whose atomic amount has trailing whitespace is a typed refusal.

    Mirrors the TS SDK's ``/^\\d+$/`` — no trailing ``\\n`` sneaks through as 100000.
    """
    with pytest.raises(X402Error) as exc:
        parse_atomic_amount({"amount": amount})
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT


@pytest.mark.parametrize("value", _TRAILING_DECIMAL)
def test_parse_units_rejects_trailing_whitespace(value: str) -> None:
    """A major-unit string with trailing whitespace is an invalid-amount refusal."""
    with pytest.raises(X402Error) as exc:
        parse_units(value, CANONICAL_DECIMALS)
    assert exc.value.code == X402ErrorCode.INVALID_AMOUNT


def test_parse_atomic_amount_accepts_clean_integer() -> None:
    """A clean atomic integer string still parses — the fix rejects only trailing junk."""
    assert parse_atomic_amount({"amount": "100000"}) == 100000


def test_parse_units_accepts_clean_decimal() -> None:
    """A clean decimal major-unit string still scales into atomic units."""
    assert parse_units("1.5", CANONICAL_DECIMALS) == 1_500_000
