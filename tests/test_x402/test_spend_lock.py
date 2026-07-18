"""Cross-process spend lock: acquire, rename-steal, staleness, WALLET_BUSY timeout.

In-process unit coverage (fast) for the lock primitive; ``test_spend_contention``
exercises the real multi-process cap invariant.
"""

from __future__ import annotations

import json
import os
import time
from uuid import uuid4

import pytest

from rine.x402 import _spend_lock as sl
from rine.x402.errors import X402Error, X402ErrorCode


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _plant_lock(
    config_dir: str, agent_id: str, acquired_at_ms: int, *, body: str | None = None
) -> str:
    """Write a lock file directly so a test can simulate a fresh/stale/garbage holder."""
    path = sl._lock_path(config_dir, agent_id)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    raw = body if body is not None else json.dumps({"pid": 999999, "acquired_at": acquired_at_ms})
    with open(path, "w") as f:
        f.write(raw)
    return path


def test_spend_lock_when_uncontended_acquires_and_releases(tmp_path) -> None:
    """Uncontended lock acquires, writes a byte-compatible body, releases on exit."""
    agent_id = str(uuid4())
    path = sl._lock_path(str(tmp_path), agent_id)
    with sl.spend_lock(str(tmp_path), agent_id):
        raw = _read(path)
        assert raw.endswith("\n")
        assert '"pid":' in raw and '"acquired_at":' in raw  # compact, no spaces (TS interop)
        body = json.loads(raw)
        assert body["pid"] == os.getpid()
    assert not os.path.exists(path)  # released in finally


def test_spend_lock_when_fresh_lock_held_times_out_wallet_busy(tmp_path, monkeypatch) -> None:
    """A fresh sibling lock blocks; the acquire deadline surfaces WALLET_BUSY."""
    monkeypatch.setattr(sl, "ACQUIRE_TIMEOUT_MS", 80)  # keep the test sub-second
    agent_id = str(uuid4())
    _plant_lock(str(tmp_path), agent_id, int(time.time() * 1000))  # fresh
    with pytest.raises(X402Error) as exc, sl.spend_lock(str(tmp_path), agent_id):
        pass
    assert exc.value.code == X402ErrorCode.WALLET_BUSY


def test_spend_lock_when_stale_lock_is_rename_stolen(tmp_path) -> None:
    """A lock older than STALE_MS is stolen and the caller takes ownership."""
    agent_id = str(uuid4())
    stale_at = int(time.time() * 1000) - sl.STALE_MS - 1000
    path = _plant_lock(str(tmp_path), agent_id, stale_at)
    with sl.spend_lock(str(tmp_path), agent_id):
        assert json.loads(_read(path))["pid"] == os.getpid()  # we own it now


def test_spend_lock_when_unparseable_lock_treated_as_stale(tmp_path) -> None:
    """A garbage lock body is unparseable → treated as stale → stolen."""
    agent_id = str(uuid4())
    path = _plant_lock(str(tmp_path), agent_id, 0, body="{not json")
    with sl.spend_lock(str(tmp_path), agent_id):
        assert json.loads(_read(path))["pid"] == os.getpid()
