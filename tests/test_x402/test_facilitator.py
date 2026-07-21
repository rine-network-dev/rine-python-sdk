"""Facilitator presets + verify/settle against a mocked x402 HTTP API."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine.x402.facilitator import (
    FACILITATOR_PRESETS,
    FEATURED_FACILITATOR,
    FacilitatorClient,
    assert_facilitator_transport,
    resolve_base_url,
)
from rine.x402.types import X402_QUOTE_REF_KEY

REQ = {
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "100000",
    "asset": "0xa",
    "payTo": "0xb",
    "maxTimeoutSeconds": 60,
    "extra": {"name": "EURC", "version": "2"},
}
PAYMENT = {"x402Version": 2, "accepted": REQ, "payload": {"signature": "0x", "authorization": {}}}


def test_presets_include_cdp_payai_and_self_hosted() -> None:
    """Presets include cdp payai and self hosted."""
    assert set(FACILITATOR_PRESETS) == {"cdp", "payai", "x402-rs"}
    assert FEATURED_FACILITATOR == "cdp"


def test_resolve_base_url_when_preset_named_returns_url() -> None:
    """Resolve base url when preset named returns url."""
    assert resolve_base_url("cdp").startswith("https://")


def test_resolve_base_url_when_self_hosted_requires_explicit_url() -> None:
    """Resolve base url when self hosted requires explicit url."""
    with pytest.raises(ValueError):
        resolve_base_url("x402-rs")
    assert resolve_base_url("x402-rs", "https://fac.local/") == "https://fac.local"


def test_resolve_base_url_when_unknown_preset_raises() -> None:
    """Resolve base url when unknown preset raises."""
    with pytest.raises(ValueError):
        resolve_base_url("nope")


@respx.mock
async def test_verify_when_facilitator_valid_returns_body() -> None:
    """Verify when facilitator valid returns body."""
    route = respx.post("https://fac.local/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True, "payer": "0xpayer"})
    )
    async with FacilitatorClient("x402-rs", base_url="https://fac.local") as fac:
        result = await fac.verify(PAYMENT, REQ)
    assert result == {"isValid": True, "payer": "0xpayer"}
    sent = route.calls.last.request
    body = sent.read()
    assert b"paymentPayload" in body and b"paymentRequirements" in body


@respx.mock
async def test_settle_when_facilitator_settles_returns_settlement_response() -> None:
    """Settle when facilitator settles returns settlement response."""
    respx.post("https://fac.local/settle").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "transaction": "0xhash",
                "network": "eip155:8453",
                "payer": "0xpayer",
            },
        )
    )
    async with FacilitatorClient("x402-rs", base_url="https://fac.local") as fac:
        settlement = await fac.settle(PAYMENT, REQ)
    assert settlement["success"] is True
    assert settlement["transaction"] == "0xhash"


@respx.mock
async def test_verify_when_payment_has_extensions_strips_them_from_the_wire_body() -> None:
    """rine-internal ``extensions`` (R-1 quote-ref) never reach a facilitator.

    The payee reads the quote-ref from its OWN decrypted payment, never the
    facilitator round-trip, and facilitators schema-validate ``extensions``
    (PayAI 403s non-object values — the live-settlement regression this guards).
    Standard top-level ``scheme``/``network`` (x402 V2 wire format) survive;
    unknown keys do not; the caller's payment dict is never mutated.
    """
    route = respx.post("https://fac.local/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True})
    )
    payment = {
        **PAYMENT,
        "scheme": "exact",
        "network": "eip155:84532",
        "extensions": {X402_QUOTE_REF_KEY: "11111111-2222-3333-4444-555555555555"},
        "rine.internal": "never-forwarded",
    }
    async with FacilitatorClient("x402-rs", base_url="https://fac.local") as fac:
        await fac.verify(payment, REQ)
    sent = json.loads(route.calls.last.request.read())
    forwarded = sent["paymentPayload"]
    assert "extensions" not in forwarded
    assert "rine.internal" not in forwarded
    assert forwarded["scheme"] == "exact"
    assert forwarded["network"] == "eip155:84532"
    assert forwarded["accepted"] == REQ
    assert forwarded["payload"] == PAYMENT["payload"]
    # The caller's payment is untouched — the payee still reads its quote-ref.
    assert payment["extensions"] == {X402_QUOTE_REF_KEY: "11111111-2222-3333-4444-555555555555"}


@respx.mock
async def test_verify_when_facilitator_errors_raises() -> None:
    """Verify when facilitator errors raises."""
    respx.post("https://fac.local/verify").mock(
        return_value=httpx.Response(400, json={"error": "bad"})
    )
    async with FacilitatorClient("x402-rs", base_url="https://fac.local") as fac:
        with pytest.raises(httpx.HTTPStatusError):
            await fac.verify(PAYMENT, REQ)


# --- F-5: transport allowlist (https, or http only to loopback) --------------


def test_transport_allows_https() -> None:
    """https:// is always allowed (no exception)."""
    assert_facilitator_transport("https://fac.example")


def test_transport_allows_loopback_http() -> None:
    """Loopback http:// is exempt (local dev/testnet)."""
    for url in ("http://localhost:8080", "http://127.0.0.1:8899", "http://[::1]:8080"):
        assert_facilitator_transport(url)


def test_transport_rejects_non_loopback_http() -> None:
    """A cleartext http:// to a remote host is refused, credentials or not (TS parity)."""
    with pytest.raises(ValueError, match="cleartext"):
        assert_facilitator_transport("http://fac.example")


def test_transport_rejects_unsupported_scheme() -> None:
    """A non-http(s) scheme is rejected outright."""
    with pytest.raises(ValueError, match="scheme"):
        assert_facilitator_transport("ftp://fac.example")


def test_client_init_rejects_non_loopback_http() -> None:
    """F-5 end-to-end: constructing a client over remote http:// is refused."""
    with pytest.raises(ValueError, match="cleartext"):
        FacilitatorClient("x402-rs", base_url="http://evil.example", api_key="secret")


def test_client_init_rejects_non_loopback_http_without_key() -> None:
    """F-5: even a no-credential remote http:// facilitator is refused (TS parity)."""
    with pytest.raises(ValueError, match="cleartext"):
        FacilitatorClient("x402-rs", base_url="http://evil.example")


def test_client_init_allows_loopback_http_with_key() -> None:
    """A local x402-rs over http://localhost with a key is fine (loopback exempt)."""
    fac = FacilitatorClient("x402-rs", base_url="http://localhost:8080", api_key="secret")
    assert fac.base_url == "http://localhost:8080"
