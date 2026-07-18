"""Spend policy enforcement (mirror of ``x402/policy.ts``).

Deny-by-default: a missing policy always refuses. The policy lives at
``keys/{agent_id}/payments.json`` (the camelCase :class:`PaymentPolicy` shape),
interoperable with the TypeScript wallet. The daily-spend journal and the
atomic :func:`rine.x402.journal.reserve_spend` writer live in ``journal.py``.
"""

from __future__ import annotations

import json
import os

from rine._config import _ensure_dir, _write_atomic, keys_dir
from rine._crypto.keys import _validate_path_id
from rine.x402.assets import (
    CANONICAL_DECIMALS,
    is_asset_allowed,
    parse_units,
    requirement_canonical_amount,
)
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.types import X402_SUPPORTED_SCHEMES, PaymentPolicy, PaymentRequirements


def enforce_policy(
    policy: PaymentPolicy | None,
    req: PaymentRequirements,
    daily_spent_canonical: int,
) -> None:
    """Enforce the spend policy for a single requirement.

    Deny-by-default: a ``None`` policy always raises. Raises a typed
    :class:`X402Error` on any violation; returns silently when payable.

    Args:
        policy: The active policy, or ``None`` (hard deny).
        req: The candidate ``PaymentRequirements``.
        daily_spent_canonical: Already-spent amount today, in canonical micro-units.
    """
    if policy is None:
        raise X402Error(
            X402ErrorCode.NO_POLICY,
            "No spend policy configured — payments are denied by default",
        )
    scheme = str(req.get("scheme", ""))
    if scheme not in X402_SUPPORTED_SCHEMES:
        raise X402Error(
            X402ErrorCode.SCHEME_UNSUPPORTED,
            f"Unsupported scheme: {scheme} (v1.0 supports 'exact')",
            {"scheme": scheme},
        )
    network = str(req.get("network", ""))
    if network not in policy.allowed_networks:
        raise X402Error(
            X402ErrorCode.NETWORK_NOT_ALLOWED,
            f"Network not allowed by policy: {network}",
            {"network": network},
        )
    if not is_asset_allowed(req, policy.allowed_assets):
        raise X402Error(
            X402ErrorCode.ASSET_NOT_ALLOWED,
            f"Asset not allowed by policy: {req.get('asset')} on {network}",
            {"asset": req.get("asset"), "network": network},
        )
    value = requirement_canonical_amount(req)
    per_tx = parse_units(policy.per_tx_cap, CANONICAL_DECIMALS)
    if value > per_tx:
        raise X402Error(
            X402ErrorCode.PER_TX_CAP_EXCEEDED,
            f"Payment exceeds per-transaction cap ({policy.per_tx_cap})",
            {"value": str(value), "cap": str(per_tx)},
        )
    daily = parse_units(policy.daily_cap, CANONICAL_DECIMALS)
    if daily_spent_canonical + value > daily:
        raise X402Error(
            X402ErrorCode.DAILY_CAP_EXCEEDED,
            f"Payment would exceed daily cap ({policy.daily_cap})",
            {"value": str(value), "spent": str(daily_spent_canonical), "cap": str(daily)},
        )


def is_auto_payable(policy: PaymentPolicy, req: PaymentRequirements) -> bool:
    """Whether a requirement is at/below the auto-pay threshold."""
    threshold = parse_units(policy.auto_pay_threshold, CANONICAL_DECIMALS)
    return requirement_canonical_amount(req) <= threshold


def validate_policy(policy: PaymentPolicy) -> None:
    """Structurally validate a policy before persisting it."""
    for field, raw in (
        ("perTxCap", policy.per_tx_cap),
        ("dailyCap", policy.daily_cap),
        ("autoPayThreshold", policy.auto_pay_threshold),
    ):
        if not isinstance(raw, str):
            raise X402Error(
                X402ErrorCode.INVALID_POLICY, f"Policy field '{field}' must be a decimal string"
            )
        parse_units(raw, CANONICAL_DECIMALS)  # validation side-effect
    for field, arr in (
        ("allowedAssets", policy.allowed_assets),
        ("allowedNetworks", policy.allowed_networks),
    ):
        if not isinstance(arr, list) or any(not isinstance(v, str) for v in arr):
            raise X402Error(
                X402ErrorCode.INVALID_POLICY, f"Policy field '{field}' must be a string array"
            )


def _policy_path(config_dir: str, agent_id: str) -> str:
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(keys_dir(config_dir, agent_id), "payments.json")


def load_policy(config_dir: str, agent_id: str) -> PaymentPolicy | None:
    """Load the agent's policy, or ``None`` if unset/unreadable (deny-by-default)."""
    try:
        with open(_policy_path(config_dir, agent_id)) as f:
            return PaymentPolicy.from_json(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError):
        return None


def save_policy(config_dir: str, agent_id: str, policy: PaymentPolicy) -> None:
    """Validate and persist the agent's policy atomically (0o600)."""
    validate_policy(policy)
    path = _policy_path(config_dir, agent_id)
    _ensure_dir(os.path.dirname(path))
    _write_atomic(path, json.dumps(policy.to_json(), indent=2))
