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
    NOT_X402_TYPE = "not-x402-type"
    MALFORMED_PAYLOAD = "malformed-payload"
    # The payment does not match any payee-issued quote (scheme/network/asset/
    # payTo/amount) — the payee refuses to settle payer-authored terms.
    REQUIREMENT_MISMATCH = "requirement-mismatch"
    # No decryptable payee-issued quote (and no explicit expected terms) is
    # available to reconcile the payment against — fail closed.
    NO_QUOTE = "no-quote"
    # The asset's decimals cannot be resolved from the registry (and none were
    # explicitly declared) — refuse to price it rather than assume 6.
    UNKNOWN_ASSET_DECIMALS = "unknown-asset-decimals"
    # The message's sender signature is not `verified` (re-sealed, forged, or not signed
    # by its sender at all) — nothing vouches for who authored the quote or payment.
    INAUTHENTIC_SENDER = "inauthentic-sender"
    # The sender check could not run (its signing key could not be looked up). Nothing
    # was paid or settled; the same message passes once the lookup works, so retry.
    SENDER_UNVERIFIABLE = "sender-unverifiable"


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


class CorruptSpendJournalError(Exception):
    """The spend journal exists but cannot be read as one, so today's spend is unknown.

    Reading it as empty would reset the daily cap, so every payment is refused until
    the file is repaired. A well-formed journal dated more than a day ahead passes
    ``detail`` instead: the system clock is the likelier fault. Mirrors
    ``CorruptSpendJournalError`` in ``rine-core/src/x402/spend-journal.ts``.

    Args:
        path: The journal file that failed to read.
        detail: What is wrong with it, replacing the default cause.
    """

    def __init__(
        self,
        path: str,
        detail: str = (
            "is not a valid spend journal, so today's spend is unknown; "
            "payments are refused until it is repaired"
        ),
    ) -> None:
        """Name the file in the message and keep it on the instance."""
        super().__init__(f"{path} {detail}")
        self.path = path
