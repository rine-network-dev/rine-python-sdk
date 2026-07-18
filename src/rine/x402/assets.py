"""Lane-C asset registry and canonical amount math (mirror of ``x402/assets.ts``).

All v1.0 ``exact``-scheme assets are 6-decimal stablecoins (EURC/USDC on Base).
Caps and daily-spend are tracked in canonical micro-units; per-asset amounts are
scaled into them for comparison.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine.x402.errors import X402Error, X402ErrorCode

if TYPE_CHECKING:
    from rine.x402.types import PaymentRequirements

CANONICAL_DECIMALS = 6
"""Canonical accounting precision (6-decimal stablecoins)."""

DEFAULT_STABLECOIN_DECIMALS = 6
"""Fallback decimals for an unrecognised ``exact``-scheme stablecoin.

Chosen as the low end so an unknown asset is never treated as *more* valuable
than it is (an over-estimate of decimals would silently relax the caps).
"""


@dataclass(frozen=True)
class KnownAsset:
    """A registry entry: symbol, CAIP-2 network, lowercased contract, decimals."""

    symbol: str
    network: str
    address: str
    decimals: int


# Addresses are the canonical Circle deployments; verify at the live-testnet
# proof gate before publish. Matching is by (network, address) — a wrong entry
# only prevents a symbol from resolving (fail-closed), never redirects a payment.
KNOWN_ASSETS: tuple[KnownAsset, ...] = (
    KnownAsset("USDC", "eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
    KnownAsset("EURC", "eip155:8453", "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42", 6),
    KnownAsset("USDC", "eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e", 6),
    KnownAsset("EURC", "eip155:84532", "0x808456652fdb597867f38412077a9182bf77359f", 6),
)

_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$", re.I)
_DECIMAL_RE = re.compile(r"^\d+(\.\d+)?$")
_CAIP2_RE = re.compile(r"^eip155:(\d+)$")
_ATOMIC_RE = re.compile(r"^\d+$")


def chain_id_from_caip2(network: str) -> int:
    """Extract the numeric EVM chain id from a CAIP-2 ``eip155:<n>`` network."""
    m = _CAIP2_RE.match(network)
    if not m:
        raise X402Error(
            X402ErrorCode.INVALID_NETWORK,
            f"Unsupported network (v1.0 signs eip155 chains only): {network}",
            {"network": network},
        )
    return int(m.group(1))


def lookup_asset(network: str, address: str) -> KnownAsset | None:
    """Find a registry entry by CAIP-2 network + contract address."""
    addr = address.lower()
    for a in KNOWN_ASSETS:
        if a.network == network and a.address == addr:
            return a
    return None


def resolve_decimals(network: str, address: str) -> int:
    """Decimals for an asset: registry hit, else the safe stablecoin default."""
    known = lookup_asset(network, address)
    return known.decimals if known else DEFAULT_STABLECOIN_DECIMALS


def parse_units(value: str, decimals: int) -> int:
    """Parse a decimal major-unit string into atomic units at ``decimals``."""
    if not _DECIMAL_RE.match(value):
        raise X402Error(X402ErrorCode.INVALID_AMOUNT, f"Invalid amount: {value}", {"value": value})
    int_part, _, frac_part = value.partition(".")
    if len(frac_part) > decimals:
        raise X402Error(
            X402ErrorCode.INVALID_AMOUNT,
            f"Amount {value} exceeds {decimals}-decimal precision",
            {"value": value, "decimals": decimals},
        )
    frac = frac_part.ljust(decimals, "0")
    return int(int(int_part or "0") * 10**decimals + int(frac or "0"))


def scale_to_decimals(atomic: int, from_dec: int, to_dec: int) -> int:
    """Rescale an atomic value between two precisions (floor on downscale)."""
    if to_dec >= from_dec:
        return int(atomic * 10 ** (to_dec - from_dec))
    return int(atomic // 10 ** (from_dec - to_dec))


def requirement_amount(req: PaymentRequirements) -> str:
    """A requirement's atomic amount string, tolerant of x402 version drift.

    x402 V2 spells the field ``amount``; V1 spelled it ``maxAmountRequired``.
    Reading either (V2 preferred) keeps the payer able to consume a real inbound
    quote whichever name the payee's facilitator emits — the value is identical,
    only the key moved.
    """
    raw = req.get("amount")
    if raw is None:
        raw = req.get("maxAmountRequired")
    if not isinstance(raw, str):
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"Requirement is missing an amount (no 'amount'/'maxAmountRequired'): {raw!r}",
            {"amount": raw},
        )
    return raw


def parse_atomic_amount(req: PaymentRequirements) -> int:
    """Parse a requirement's atomic amount string into an int (typed guard)."""
    amount = requirement_amount(req)
    if not _ATOMIC_RE.match(amount):
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"Requirement amount must be atomic integer units, got: {amount!r}",
            {"amount": amount},
        )
    return int(amount)


def requirement_canonical_amount(req: PaymentRequirements) -> int:
    """A requirement's value expressed in canonical (6-decimal) micro-units."""
    decimals = resolve_decimals(str(req.get("network", "")), str(req.get("asset", "")))
    return scale_to_decimals(parse_atomic_amount(req), decimals, CANONICAL_DECIMALS)


def is_asset_allowed(req: PaymentRequirements, allowed_assets: list[str]) -> bool:
    """Whether a requirement's asset is allowed by an ``allowed_assets`` list.

    An entry matches either directly by contract address (case-insensitive) or by
    symbol resolved through the known-asset registry for the requirement's
    network. Unknown symbols fail-closed.
    """
    asset = str(req.get("asset", "")).lower()
    network = str(req.get("network", ""))
    for raw in allowed_assets:
        entry = raw.strip()
        if _ADDRESS_RE.match(entry):
            if entry.lower() == asset:
                return True
            continue
        for a in KNOWN_ASSETS:
            if a.network == network and a.symbol.upper() == entry.upper() and a.address == asset:
                return True
    return False
