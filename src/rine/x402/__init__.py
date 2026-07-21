"""x402 v1.0 payments — client-side wallet, spend policy, and payer/payee helpers.

rine carries verbatim x402 V2 objects as the E2EE payload of three message types
(``rine.v1.x402_payment_required`` / ``rine.v1.x402_payment`` /
``rine.v1.x402_receipt``). rine never runs a facilitator and never custodies funds
— settlement is peer-to-peer via the payee's configured facilitator.

Signing uses the optional ``payments`` extra (``pip install rine[payments]``); the
symbols here import cleanly without it, raising a friendly error only when a wallet
operation actually runs.
"""

from __future__ import annotations

from rine._crypto.wallet import (
    create_wallet,
    derive_evm_address,
    get_wallet_address,
    load_wallet_key,
    wallet_key_exists,
)
from rine.x402.assets import (
    CANONICAL_DECIMALS,
    KNOWN_ASSETS,
    KnownAsset,
    chain_id_from_caip2,
    is_asset_allowed,
    parse_units,
    requirement_canonical_amount,
)
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.extract import extract_payment_payload
from rine.x402.facilitator import (
    FACILITATOR_PRESETS,
    FACILITATOR_TIMEOUT_SECONDS,
    FEATURED_FACILITATOR,
    FacilitatorClient,
    FacilitatorPreset,
    assert_facilitator_transport,
    resolve_base_url,
)
from rine.x402.flow import PreparedPayment, prepare_payment
from rine.x402.journal import read_daily_spent, record_spend, reserve_spend
from rine.x402.marker import build_marker, marker_metadata, read_marker, status_for_message_type
from rine.x402.messages import (
    X402Message,
    build_payment_required,
    build_receipt,
    parse_x402_payload,
    payment_message,
    receipt_from_settlement,
)
from rine.x402.pay import build_payment_payload, select_requirement
from rine.x402.payee import (
    FulfillResult,
    fulfill,
    send_receipt,
)
from rine.x402.payee_settle import (
    MatchedQuote,
    resolve_payee_requirement,
    resolve_requirement,
    settle,
    verify,
)
from rine.x402.policy import (
    enforce_policy,
    is_auto_payable,
    load_policy,
    save_policy,
    validate_policy,
)
from rine.x402.quote_ref import ReferencedQuote, load_referenced_quote
from rine.x402.reconcile import reconcile_payment
from rine.x402.types import (
    X402_METADATA_KEY,
    X402_QUOTE_REF_KEY,
    X402_RAIL,
    X402_SUPPORTED_SCHEMES,
    X402_VERSION,
    PaymentPolicy,
    X402Mode,
    X402Status,
)

__all__ = [
    # Wallet (secp256k1 payment key)
    "create_wallet",
    "get_wallet_address",
    "wallet_key_exists",
    "load_wallet_key",
    "derive_evm_address",
    # Types & constants
    "PaymentPolicy",
    "X402Status",
    "X402Mode",
    "X402_METADATA_KEY",
    "X402_QUOTE_REF_KEY",
    "X402_RAIL",
    "X402_VERSION",
    "X402_SUPPORTED_SCHEMES",
    # Errors
    "X402Error",
    "X402ErrorCode",
    # Assets
    "KNOWN_ASSETS",
    "KnownAsset",
    "CANONICAL_DECIMALS",
    "chain_id_from_caip2",
    "is_asset_allowed",
    "parse_units",
    "requirement_canonical_amount",
    # Policy
    "enforce_policy",
    "is_auto_payable",
    "validate_policy",
    "load_policy",
    "save_policy",
    "read_daily_spent",
    "record_spend",
    "reserve_spend",
    # Pay
    "select_requirement",
    "build_payment_payload",
    # Messages & marker
    "X402Message",
    "build_payment_required",
    "payment_message",
    "build_receipt",
    "receipt_from_settlement",
    "parse_x402_payload",
    "build_marker",
    "marker_metadata",
    "read_marker",
    "status_for_message_type",
    # Flow helpers
    "PreparedPayment",
    "prepare_payment",
    # Payee orchestrator (reconcile → verify → settle → receipt)
    "extract_payment_payload",
    "fulfill",
    "send_receipt",
    "FulfillResult",
    # Reconciling standalone verify/settle (settle-after-delivery, fail-closed)
    "verify",
    "settle",
    "resolve_requirement",
    "resolve_payee_requirement",
    "MatchedQuote",
    # Reconciliation (payee binds settlement to the ONE quote it issued)
    "reconcile_payment",
    "load_referenced_quote",
    "ReferencedQuote",
    # Facilitator
    "FacilitatorClient",
    "FacilitatorPreset",
    "FACILITATOR_PRESETS",
    "FACILITATOR_TIMEOUT_SECONDS",
    "FEATURED_FACILITATOR",
    "assert_facilitator_transport",
    "resolve_base_url",
]
