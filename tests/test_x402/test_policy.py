"""Spend-policy enforcement: caps, deny-by-default, rollover, disk interop."""

from __future__ import annotations

from uuid import uuid4

import pytest

from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.journal import read_daily_spent, record_spend
from rine.x402.policy import (
    enforce_policy,
    is_auto_payable,
    load_policy,
    save_policy,
)
from rine.x402.types import PaymentPolicy

# 1 EURC = 1_000_000 atomic units (6 decimals).
BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"


def _req(amount: str, *, network: str = BASE, asset: str = EURC, scheme: str = "exact") -> dict:
    return {
        "scheme": scheme,
        "network": network,
        "amount": amount,
        "asset": asset,
        "payTo": "0xpayee",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "EURC", "version": "2"},
    }


def _policy(**overrides) -> PaymentPolicy:
    base = dict(
        per_tx_cap="5.00",
        daily_cap="10.00",
        allowed_assets=["EURC"],
        allowed_networks=[BASE],
        auto_pay_threshold="1.00",
    )
    base.update(overrides)
    return PaymentPolicy(**base)  # type: ignore[arg-type]


def test_enforce_policy_when_no_policy_denies_by_default() -> None:
    """Enforce policy when no policy denies by default."""
    with pytest.raises(X402Error) as exc:
        enforce_policy(None, _req("100000"), 0)
    assert exc.value.code == X402ErrorCode.NO_POLICY


def test_enforce_policy_when_within_caps_returns_silently() -> None:
    """Enforce policy when within caps returns silently."""
    enforce_policy(_policy(), _req("1000000"), 0)  # 1.00 EURC, under 5.00


def test_enforce_policy_when_over_per_tx_cap_raises() -> None:
    """Enforce policy when over per tx cap raises."""
    with pytest.raises(X402Error) as exc:
        enforce_policy(_policy(), _req("6000000"), 0)  # 6.00 > 5.00
    assert exc.value.code == X402ErrorCode.PER_TX_CAP_EXCEEDED


def test_enforce_policy_when_daily_accumulation_over_cap_raises() -> None:
    """Enforce policy when daily accumulation over cap raises."""
    # 4.00 already spent today, a 4.00 charge would reach 8.00 (ok) but 7.00 → 11.00 fails.
    with pytest.raises(X402Error) as exc:
        enforce_policy(_policy(), _req("5000000"), 6_000_000)  # 6.00 spent + 5.00 = 11.00 > 10.00
    assert exc.value.code == X402ErrorCode.DAILY_CAP_EXCEEDED


def test_enforce_policy_when_scheme_unsupported_raises() -> None:
    """Enforce policy when scheme unsupported raises."""
    with pytest.raises(X402Error) as exc:
        enforce_policy(_policy(), _req("100000", scheme="upto"), 0)
    assert exc.value.code == X402ErrorCode.SCHEME_UNSUPPORTED


def test_enforce_policy_when_network_not_allowed_raises() -> None:
    """Enforce policy when network not allowed raises."""
    with pytest.raises(X402Error) as exc:
        enforce_policy(_policy(), _req("100000", network="eip155:84532"), 0)
    assert exc.value.code == X402ErrorCode.NETWORK_NOT_ALLOWED


def test_enforce_policy_when_asset_not_allowed_raises() -> None:
    """Enforce policy when asset not allowed raises."""
    with pytest.raises(X402Error) as exc:
        enforce_policy(_policy(), _req("100000", asset="0x" + "de" * 20), 0)
    assert exc.value.code == X402ErrorCode.ASSET_NOT_ALLOWED


def test_enforce_policy_when_asset_matched_by_address_passes() -> None:
    """Enforce policy when asset matched by address passes."""
    enforce_policy(_policy(allowed_assets=[EURC]), _req("100000"), 0)


def test_is_auto_payable_reflects_threshold() -> None:
    """Is auto payable reflects threshold."""
    p = _policy(auto_pay_threshold="1.00")
    assert is_auto_payable(p, _req("1000000")) is True  # exactly 1.00
    assert is_auto_payable(p, _req("1000001")) is False


def test_save_load_policy_when_roundtripped_preserves_camelcase(tmp_path) -> None:
    """Save load policy when roundtripped preserves camelcase."""
    agent_id = str(uuid4())
    save_policy(str(tmp_path), agent_id, _policy())
    on_disk = (tmp_path / "keys" / agent_id / "payments.json").read_text()
    assert "perTxCap" in on_disk and "allowedNetworks" in on_disk
    loaded = load_policy(str(tmp_path), agent_id)
    assert loaded == _policy()


def test_load_policy_when_absent_returns_none(tmp_path) -> None:
    """Load policy when absent returns none."""
    assert load_policy(str(tmp_path), str(uuid4())) is None


def test_record_spend_when_same_day_accumulates(tmp_path) -> None:
    """Record spend when same day accumulates."""
    agent_id = str(uuid4())
    t = 1_740_000_000  # a fixed instant
    record_spend(str(tmp_path), agent_id, 1_000_000, t)
    record_spend(str(tmp_path), agent_id, 2_000_000, t + 10)
    assert read_daily_spent(str(tmp_path), agent_id, t + 20) == 3_000_000


def test_read_daily_spent_when_next_utc_day_resets(tmp_path) -> None:
    """Read daily spent when next utc day resets."""
    agent_id = str(uuid4())
    t = 1_740_000_000
    record_spend(str(tmp_path), agent_id, 3_000_000, t)
    assert read_daily_spent(str(tmp_path), agent_id, t + 86_400) == 0
