"""Requirement selection + PaymentPayload construction (mirror of ``x402/pay.ts``).

The payer side of REQ-W03: pick an acceptable requirement under the spend policy,
then build and sign the verbatim x402 ``PaymentPayload``. The signer pins
``to``/``value``/``asset``/``network`` inside the EIP-712 signature, so a relayer
or facilitator cannot redirect funds.
"""

from __future__ import annotations

import math
import secrets
import time
from typing import cast

from rine._crypto.wallet import derive_evm_address, sign_digest
from rine.x402.assets import chain_id_from_caip2, requirement_amount
from rine.x402.eip3009 import Eip712Domain, eip3009_digest
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.policy import enforce_policy
from rine.x402.types import (
    X402_VERSION,
    PaymentPayload,
    PaymentPolicy,
    PaymentRequired,
    PaymentRequirements,
)

_DEFAULT_SKEW_SECONDS = 60

MAX_AUTHORIZATION_TTL_SECONDS = 86_400
"""Ceiling (seconds) applied to a payee-quoted ``maxTimeoutSeconds`` before it
becomes the EIP-3009 ``validBefore``.

The payee controls that field verbatim; an absurd value (e.g. 10 years) would
keep the signed pull-authorization live far longer than intended. 24h comfortably
covers ``settle-after-delivery`` task windows while killing multi-year
authorizations. Clamping is fail-closed — it only ever shortens validity.
"""


def select_requirement(
    pr: PaymentRequired,
    policy: PaymentPolicy | None,
    daily_spent_canonical: int,
) -> PaymentRequirements:
    """Deterministically pick the first ``accepts[]`` entry that passes policy.

    Iterates in the payee's advertised order (their preference wins). Deny-by-
    default: a ``None`` policy makes every candidate fail. Raises
    :class:`X402Error` ``no-acceptable-requirement`` (carrying the last
    per-candidate rejection reason) if none pass.
    """
    accepts = pr.get("accepts")
    if not isinstance(accepts, list) or len(accepts) == 0:
        raise X402Error(X402ErrorCode.INVALID_REQUIREMENT, "PaymentRequired.accepts[] is empty")
    last_error: X402Error | None = None
    for req in accepts:
        try:
            enforce_policy(policy, req, daily_spent_canonical)
            return cast("PaymentRequirements", req)
        except X402Error as err:
            last_error = err
            continue
    reason = last_error.message if last_error else "unknown"
    raise X402Error(
        X402ErrorCode.NO_ACCEPTABLE_REQUIREMENT,
        f"No requirement in accepts[] satisfies the spend policy: {reason}",
        {"reason": last_error.code if last_error else None},
    )


def build_payment_payload(
    pr: PaymentRequired,
    requirement: PaymentRequirements,
    wallet_private_key: bytes,
    *,
    now: int | None = None,
    nonce: bytes | None = None,
    valid_after_skew_seconds: int = _DEFAULT_SKEW_SECONDS,
) -> PaymentPayload:
    """Build and sign a ``PaymentPayload`` for a chosen requirement (REQ-W03).

    Echoes ``resource``/``extensions`` and the chosen requirement (``accepted``)
    verbatim per the x402 contract. ``now``/``nonce`` are injectable for tests.
    """
    ts = now if now is not None else math.floor(time.time())
    nonce_bytes = nonce if nonce is not None else secrets.token_bytes(32)
    if len(nonce_bytes) != 32:
        raise X402Error(
            X402ErrorCode.INVALID_REQUIREMENT,
            f"Nonce must be 32 bytes, got {len(nonce_bytes)}",
        )
    ttl = min(int(requirement["maxTimeoutSeconds"]), MAX_AUTHORIZATION_TTL_SECONDS)
    authorization = {
        "from": derive_evm_address(wallet_private_key),
        "to": requirement["payTo"],
        "value": requirement_amount(requirement),
        "validAfter": str(ts - valid_after_skew_seconds),
        "validBefore": str(ts + ttl),
        "nonce": "0x" + nonce_bytes.hex(),
    }
    extra = requirement["extra"]
    domain = Eip712Domain(
        name=str(extra["name"]),
        version=str(extra["version"]),
        chain_id=chain_id_from_caip2(str(requirement["network"])),
        verifying_contract=str(requirement["asset"]),
    )
    digest = eip3009_digest(domain, authorization)
    signature = sign_digest(wallet_private_key, digest)
    return {
        "x402Version": pr.get("x402Version", X402_VERSION),
        "resource": pr.get("resource"),
        "accepted": requirement,
        "payload": {"signature": signature, "authorization": authorization},
        "extensions": pr.get("extensions", {}),
    }
