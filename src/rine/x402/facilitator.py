"""Facilitator client + presets (payee verify/settle side of REQ-M04).

The facilitator is a third-party service the *payee* calls to ``/verify`` a signed
authorization and ``/settle`` it on-chain. rine never runs a facilitator and never
touches settlement (the pure-metadata-relay posture) — this client just speaks the
standard x402 facilitator HTTP API to whichever facilitator the payee configures.

Presets (D2/D5 as revised): ``cdp`` (Coinbase Developer Platform, the default),
``payai`` (keyless hosted facilitator), and self-hosted ``x402-rs`` (base URL
supplied by the caller — a first-class option, not a fallback). The presets are
convenience shortcuts only — any facilitator that implements the standard x402
``/verify`` + ``/settle`` API is natively supported via an explicit ``base_url``.
EURC and USDC on Base are both first-class assets in examples.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from rine.x402.types import X402_VERSION, PaymentPayload, PaymentRequirements, SettlementResponse


@dataclass(frozen=True)
class FacilitatorPreset:
    """A named facilitator: its base URL and whether it needs a self-hosted URL."""

    name: str
    base_url: str | None
    description: str


# Base URLs are the documented public endpoints; a self-hosted x402-rs has no
# default (the deployer supplies it). Confirm endpoints at the integration gate.
FACILITATOR_PRESETS: dict[str, FacilitatorPreset] = {
    "cdp": FacilitatorPreset(
        "cdp",
        "https://api.cdp.coinbase.com/platform/v2/x402",
        "Coinbase Developer Platform hosted facilitator (USDC/EURC on Base et al.).",
    ),
    "payai": FacilitatorPreset(
        "payai",
        "https://facilitator.payai.network",
        "Keyless hosted multi-chain facilitator; no account or API key required.",
    ),
    "x402-rs": FacilitatorPreset(
        "x402-rs",
        None,
        "Self-hosted open-source x402-rs facilitator (supply your own base URL).",
    ),
}

FEATURED_FACILITATOR = "cdp"
"""Default preset in examples; any x402-API facilitator is interchangeable."""


def resolve_base_url(facilitator: str, base_url: str | None = None) -> str:
    """Resolve a facilitator preset name (or explicit URL) to a base URL."""
    if base_url:
        return base_url.rstrip("/")
    preset = FACILITATOR_PRESETS.get(facilitator)
    if preset is None:
        raise ValueError(
            f"Unknown facilitator {facilitator!r}; presets: {sorted(FACILITATOR_PRESETS)}"
        )
    if preset.base_url is None:
        raise ValueError(f"Facilitator {facilitator!r} requires an explicit base_url")
    return preset.base_url.rstrip("/")


def _request_body(payment: PaymentPayload, requirement: PaymentRequirements) -> dict[str, Any]:
    """The standard x402 facilitator request body for /verify and /settle."""
    return {
        "x402Version": payment.get("x402Version", X402_VERSION),
        "paymentPayload": payment,
        "paymentRequirements": requirement,
    }


class FacilitatorClient:
    """Async facilitator client (verify/settle) over the x402 HTTP API."""

    def __init__(
        self,
        facilitator: str = FEATURED_FACILITATOR,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        """Configure against a preset name or an explicit facilitator base URL."""
        self.base_url = resolve_base_url(facilitator, base_url)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, headers=headers)

    async def __aenter__(self) -> FacilitatorClient:
        """Enter the async context, returning ``self``."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the underlying HTTP client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def verify(
        self, payment: PaymentPayload, requirement: PaymentRequirements
    ) -> dict[str, Any]:
        """Verify a signed authorization (signature + balance; no broadcast)."""
        resp = await self._client.post("/verify", json=_request_body(payment, requirement))
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data

    async def settle(
        self, payment: PaymentPayload, requirement: PaymentRequirements
    ) -> SettlementResponse:
        """Broadcast the authorization on-chain, returning a ``SettlementResponse``."""
        resp = await self._client.post("/settle", json=_request_body(payment, requirement))
        resp.raise_for_status()
        data: SettlementResponse = resp.json()
        return data
