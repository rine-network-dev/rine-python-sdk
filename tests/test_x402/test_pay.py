"""Requirement selection + PaymentPayload construction and signature recovery."""

from __future__ import annotations

import pytest
from eth_account import Account

from rine._crypto.wallet import derive_evm_address
from rine.x402.assets import chain_id_from_caip2
from rine.x402.eip3009 import Eip712Domain, eip3009_digest
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.pay import build_payment_payload, select_requirement
from rine.x402.types import X402_QUOTE_REF_KEY, PaymentPolicy

BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
KEY = bytes(31) + b"\x01"


def _req(amount: str, asset: str = EURC) -> dict:
    return {
        "scheme": "exact",
        "network": BASE,
        "amount": amount,
        "asset": asset,
        "payTo": "0x808456652fdb597867f38412077a9182bf77359f",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "EURC", "version": "2"},
    }


def _policy() -> PaymentPolicy:
    return PaymentPolicy(
        per_tx_cap="5.00",
        daily_cap="10.00",
        allowed_assets=["EURC", "USDC"],
        allowed_networks=[BASE],
        auto_pay_threshold="1.00",
    )


def test_select_requirement_when_first_payable_wins_payee_order() -> None:
    """Select requirement when first payable wins payee order."""
    pr = {"x402Version": 2, "accepts": [_req("1000000", EURC), _req("2000000", USDC)]}
    chosen = select_requirement(pr, _policy(), 0)
    assert chosen["asset"] == EURC  # first entry, payee's preference


def test_select_requirement_when_first_over_cap_falls_through() -> None:
    """Select requirement when first over cap falls through."""
    pr = {"x402Version": 2, "accepts": [_req("6000000", EURC), _req("2000000", USDC)]}
    chosen = select_requirement(pr, _policy(), 0)
    assert chosen["asset"] == USDC  # first exceeds per-tx cap, second is payable


def test_select_requirement_when_none_payable_raises_with_reason() -> None:
    """Select requirement when none payable raises with reason."""
    pr = {"x402Version": 2, "accepts": [_req("6000000", EURC)]}
    with pytest.raises(X402Error) as exc:
        select_requirement(pr, _policy(), 0)
    assert exc.value.code == X402ErrorCode.NO_ACCEPTABLE_REQUIREMENT
    assert exc.value.details["reason"] == X402ErrorCode.PER_TX_CAP_EXCEEDED


def test_select_requirement_when_no_policy_denies() -> None:
    """Select requirement when no policy denies."""
    pr = {"x402Version": 2, "accepts": [_req("1000000")]}
    with pytest.raises(X402Error) as exc:
        select_requirement(pr, None, 0)
    assert exc.value.code == X402ErrorCode.NO_ACCEPTABLE_REQUIREMENT


def test_build_payment_payload_when_signed_recovers_to_wallet_address() -> None:
    """Build payment payload when signed recovers to wallet address."""
    req = _req("100000")
    pr = {"x402Version": 2, "resource": {"description": "task"}, "accepts": [req]}
    payload = build_payment_payload(
        pr, req, KEY, now=1_740_672_094, nonce=bytes.fromhex("ab" * 32)
    )
    auth = payload["payload"]["authorization"]
    assert auth["from"] == derive_evm_address(KEY)
    assert auth["to"] == req["payTo"]
    assert auth["value"] == "100000"
    assert auth["validBefore"] == str(1_740_672_094 + 60)
    # The signature recovers to the wallet address over the reconstructed digest.
    domain = Eip712Domain("EURC", "2", chain_id_from_caip2(BASE), EURC)
    digest = eip3009_digest(domain, auth)
    recovered = Account._recover_hash(digest, signature=payload["payload"]["signature"])
    assert recovered == derive_evm_address(KEY)


def test_build_payment_payload_when_built_echoes_resource_and_accepted_verbatim() -> None:
    """Build payment payload when built echoes resource and accepted verbatim."""
    req = _req("100000")
    pr = {
        "x402Version": 2,
        "resource": {"description": "x", "url": "u"},
        "accepts": [req],
        "extensions": {"k": 1},
    }
    payload = build_payment_payload(pr, req, KEY, now=1_700_000_000, nonce=bytes(32))
    assert payload["accepted"] == req
    assert payload["resource"] == pr["resource"]
    assert payload["extensions"] == {"k": 1}
    assert payload["x402Version"] == 2


def test_build_payment_payload_when_quote_id_given_stamps_signed_ref() -> None:
    """The answered quote's id is stamped into extensions (payer binding)."""
    req = _req("100000")
    pr = {"x402Version": 2, "accepts": [req], "extensions": {"k": 1}}
    source_extensions = pr["extensions"]
    payload = build_payment_payload(
        pr, req, KEY, now=1_700_000_000, nonce=bytes(32), quote_message_id="quote-abc"
    )
    assert payload["extensions"][X402_QUOTE_REF_KEY] == "quote-abc"
    assert payload["extensions"]["k"] == 1  # the quote's own extensions are echoed
    # The source PaymentRequired.extensions is cloned, never mutated.
    assert source_extensions == {"k": 1}
    assert X402_QUOTE_REF_KEY not in source_extensions


def test_build_payment_payload_when_no_quote_id_omits_ref() -> None:
    """Without a quote id the payment is unbound (raw HTTP-402 flow) — no stray key."""
    req = _req("100000")
    pr = {"x402Version": 2, "accepts": [req]}
    payload = build_payment_payload(pr, req, KEY, now=1_700_000_000, nonce=bytes(32))
    assert X402_QUOTE_REF_KEY not in payload["extensions"]


def test_build_payment_payload_when_bad_nonce_length_raises() -> None:
    """Build payment payload when bad nonce length raises."""
    req = _req("100000")
    pr = {"x402Version": 2, "accepts": [req]}
    with pytest.raises(X402Error) as exc:
        build_payment_payload(pr, req, KEY, now=1, nonce=bytes(16))
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT


def test_build_payment_payload_when_max_timeout_absurd_clamps_valid_before() -> None:
    """Build payment payload clamps validBefore to the 24h ceiling."""
    req = _req("100000")
    req["maxTimeoutSeconds"] = 315_360_000  # 10 years
    pr = {"x402Version": 2, "accepts": [req]}
    payload = build_payment_payload(pr, req, KEY, now=1_700_000_000, nonce=bytes(32))
    assert payload["payload"]["authorization"]["validBefore"] == str(1_700_000_000 + 86_400)


def test_build_payment_payload_when_amount_uses_max_amount_required_spelling() -> None:
    """Build payment payload reads the V1 ``maxAmountRequired`` field when present."""
    req = _req("100000")
    del req["amount"]
    req["maxAmountRequired"] = "100000"
    pr = {"x402Version": 2, "accepts": [req]}
    payload = build_payment_payload(pr, req, KEY, now=1_700_000_000, nonce=bytes(32))
    assert payload["payload"]["authorization"]["value"] == "100000"
