"""x402 v1.0 wire types and constants (Python mirror of ``rine-core/x402/types.ts``).

Binding contract: ``phases/x402-payments/AGENT_OUT_protocol_draft.md`` §1-§4. The
decrypted plaintext of each x402 message IS the x402 V2 object byte-for-byte — no
rine wrapper, no renamed fields. The verbatim objects are carried as plain
``dict`` values (``PaymentRequired`` etc.) so unknown keys and ``extensions`` are
preserved across the wire exactly as received.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# --- Constants (typed; no scattered string literals) ---

X402_VERSION = 2
"""x402 protocol version carried in the objects."""

X402_METADATA_KEY = "rine.x402"
"""Cleartext-metadata key for the optional coarse status marker (REQ-P02)."""

X402_RAIL = "x402"
"""Settlement-rail identifier for this rail."""

X402_SUPPORTED_SCHEMES: tuple[str, ...] = ("exact",)
"""Schemes the v1.0 signer supports (EIP-3009 ``exact`` only; no Permit2/Solana)."""


class X402Status:
    """The four — and only four — coarse lifecycle states in the marker."""

    REQUIRED = "payment-required"
    SUBMITTED = "payment-submitted"
    COMPLETED = "payment-completed"
    FAILED = "payment-failed"


class X402Mode:
    """Settlement-timing modes advertised in card terms / stated in the quote."""

    SETTLE_FIRST = "settle-first"
    SETTLE_AFTER_DELIVERY = "settle-after-delivery"


# --- Verbatim x402 V2 objects (plain dicts; unknown keys preserved) ---

# One entry of ``PaymentRequired.accepts[]`` — an x402 ``PaymentRequirements``.
PaymentRequirements = dict[str, Any]
# Payload of ``rine.v1.x402_payment_required`` (the 402 quote).
PaymentRequired = dict[str, Any]
# EIP-3009 ``transferWithAuthorization`` fields (all decimal/hex strings).
Eip3009Authorization = dict[str, Any]
# Payload of ``rine.v1.x402_payment`` (the signed authorization).
PaymentPayload = dict[str, Any]
# Payload of ``rine.v1.x402_receipt`` (the settlement result).
SettlementResponse = dict[str, Any]


@dataclass(frozen=True)
class PaymentPolicy:
    """Client-side spend policy (REQ-W02), enforced at signing.

    All cap fields are decimal major-unit strings (e.g. ``"10.00"``) interpreted
    in canonical 6-decimal stablecoin units. ``allowed_assets`` entries are
    symbols (``"EURC"``) or ``0x`` contract addresses; ``allowed_networks`` are
    CAIP-2 ids. Absence of a policy is a hard deny (deny-by-default).

    On-disk JSON uses the camelCase keys of the TS reference so the file is
    interoperable across SDKs: ``perTxCap``, ``dailyCap``, ``allowedAssets``,
    ``allowedNetworks``, ``autoPayThreshold``.
    """

    per_tx_cap: str
    daily_cap: str
    allowed_assets: list[str]
    allowed_networks: list[str]
    auto_pay_threshold: str

    def to_json(self) -> dict[str, Any]:
        """Serialize to the interoperable camelCase on-disk shape."""
        return {
            "perTxCap": self.per_tx_cap,
            "dailyCap": self.daily_cap,
            "allowedAssets": list(self.allowed_assets),
            "allowedNetworks": list(self.allowed_networks),
            "autoPayThreshold": self.auto_pay_threshold,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> PaymentPolicy:
        """Parse the interoperable camelCase on-disk shape."""
        return cls(
            per_tx_cap=data["perTxCap"],
            daily_cap=data["dailyCap"],
            allowed_assets=list(data["allowedAssets"]),
            allowed_networks=list(data["allowedNetworks"]),
            auto_pay_threshold=data["autoPayThreshold"],
        )
