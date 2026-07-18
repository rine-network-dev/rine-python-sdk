"""Typed error codes for x402 policy enforcement and payload construction.

Mirrors ``rine-core/src/x402/errors.ts`` so the two SDKs raise the same codes.
"""

from __future__ import annotations


class X402ErrorCode:
    """Stable string codes carried on every :class:`X402Error`."""

    NO_POLICY = "no-policy"
    SCHEME_UNSUPPORTED = "scheme-unsupported"
    NETWORK_NOT_ALLOWED = "network-not-allowed"
    ASSET_NOT_ALLOWED = "asset-not-allowed"
    PER_TX_CAP_EXCEEDED = "per-tx-cap-exceeded"
    DAILY_CAP_EXCEEDED = "daily-cap-exceeded"
    NO_ACCEPTABLE_REQUIREMENT = "no-acceptable-requirement"
    INVALID_REQUIREMENT = "invalid-requirement"
    INVALID_NETWORK = "invalid-network"
    INVALID_POLICY = "invalid-policy"
    INVALID_AMOUNT = "invalid-amount"
    WALLET_BUSY = "wallet-busy"
    ALREADY_PAID = "already-paid"


class X402Error(Exception):
    """A structured, typed error (never a bare string) for all x402 refusals.

    Args:
        code: One of the :class:`X402ErrorCode` string constants.
        message: Human-readable explanation.
        details: Optional structured context (amounts, caps, asset ids).
    """

    def __init__(self, code: str, message: str, details: dict[str, object] | None = None) -> None:
        """Build the error, keeping ``code`` and ``details`` on the instance."""
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
