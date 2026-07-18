"""Facilitator presets + verify/settle against a mocked x402 HTTP API."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine.x402.facilitator import (
    FACILITATOR_PRESETS,
    FEATURED_FACILITATOR,
    FacilitatorClient,
    resolve_base_url,
)

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
async def test_verify_when_facilitator_errors_raises() -> None:
    """Verify when facilitator errors raises."""
    respx.post("https://fac.local/verify").mock(
        return_value=httpx.Response(400, json={"error": "bad"})
    )
    async with FacilitatorClient("x402-rs", base_url="https://fac.local") as fac:
        with pytest.raises(httpx.HTTPStatusError):
            await fac.verify(PAYMENT, REQ)
