"""Facilitator client + presets (payee verify/settle side).

The facilitator is a third-party service the *payee* calls to ``/verify`` a signed
authorization and ``/settle`` it on-chain. rine never runs a facilitator and never
touches settlement (the pure-metadata-relay posture) — this client just speaks the
standard x402 facilitator HTTP API to whichever facilitator the payee configures.

Presets: ``cdp`` (Coinbase Developer Platform, the default),
``payai`` (keyless hosted facilitator), and self-hosted ``x402-rs`` (base URL
supplied by the caller — a first-class option, not a fallback). The presets are
convenience shortcuts only — any facilitator that implements the standard x402
``/verify`` + ``/settle`` API is natively supported via an explicit ``base_url``.
EURC and USDC on Base are both first-class assets in examples.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from rine.x402.types import X402_VERSION, PaymentPayload, PaymentRequirements, SettlementResponse

FACILITATOR_TIMEOUT_SECONDS = 30.0
"""Default facilitator request timeout — matches the TS SDK's 30s contract."""

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


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


def assert_facilitator_transport(base_url: str) -> None:
    """Enforce the transport allowlist before any bytes leave.

    ``https:`` is always fine; ``http:`` is allowed ONLY to a loopback host
    (``127.0.0.1``/``localhost``/``::1``), credentials or not — a facilitator call
    carries the payment terms and the signed authorization, and there is no
    legitimate reason to send it in cleartext to a remote host where an on-path
    attacker could tamper with the ``/verify``+``/settle`` exchange. Any other
    scheme is rejected outright. Mirrors ``rine-core`` ``assertFacilitatorTransport``.

    Raises:
        ValueError: For a non-``https``/loopback-``http`` URL, an unsupported
            scheme, or an unparseable URL.
    """
    parts = urlsplit(base_url)
    scheme = parts.scheme.lower()
    if scheme == "https":
        return
    if scheme != "http":
        raise ValueError(
            f"unsupported facilitator URL scheme {scheme!r} (only https:, or http: to loopback)"
        )
    if (parts.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        f"refusing cleartext http:// to non-loopback facilitator host {parts.netloc} "
        f"— use https:// (loopback is exempt for dev/testnet)"
    )


_FACILITATOR_PAYLOAD_KEYS = ("x402Version", "scheme", "network", "resource", "accepted", "payload")
"""The standard x402 payload fields a facilitator needs — nothing else is forwarded.

``extensions`` is deliberately ABSENT: the quote-ref stamp
(``extensions[X402_QUOTE_REF_KEY]``) is rine-payee-internal — the payee reads it
from its OWN decrypted payment, never the facilitator round-trip — and EIP-3009
signs only the ``TransferWithAuthorization`` struct, so stripping it cannot
invalidate the signature. Facilitators schema-validate ``extensions`` (PayAI
403s any non-object value, which broke live settlement); sending none is immune
to their policies and stops leaking rine metadata to third parties. Mirrors
``rine-core`` ``FACILITATOR_PAYLOAD_KEYS``.
"""


def _request_body(payment: PaymentPayload, requirement: PaymentRequirements) -> dict[str, Any]:
    """The standard x402 facilitator request body for /verify and /settle.

    The forwarded payload is whitelisted to ``_FACILITATOR_PAYLOAD_KEYS`` —
    rine-internal ``extensions`` and unknown keys never leave for a facilitator.
    """
    forwarded: dict[str, Any] = {k: payment[k] for k in _FACILITATOR_PAYLOAD_KEYS if k in payment}
    forwarded["x402Version"] = payment.get("x402Version", X402_VERSION)
    return {
        "x402Version": forwarded["x402Version"],
        "paymentPayload": forwarded,
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
        timeout: float = FACILITATOR_TIMEOUT_SECONDS,
    ) -> None:
        """Configure against a preset name or an explicit facilitator base URL.

        Raises:
            ValueError: If the resolved base URL is a non-loopback ``http://``
                URL or an otherwise disallowed scheme (transport allowlist).
        """
        self.base_url = resolve_base_url(facilitator, base_url)
        assert_facilitator_transport(self.base_url)
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
