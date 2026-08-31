"""Real multi-process contention: N processes race one agent's dailyCap.

The lock serializes the read→enforce→write across OS processes, so exactly the
reservations that fit under the cap succeed and the journal never overshoots — the
TOCTOU invariant. Uses ``spawn`` for true process isolation (distinct pids).
"""

from __future__ import annotations

import multiprocessing as mp
from uuid import uuid4

from rine.x402.journal import read_daily_spent
from rine.x402.policy import save_policy
from rine.x402.types import PaymentPolicy

BASE = "eip155:8453"
EURC = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42"
T = 1_740_000_000
AMOUNT = "300000"  # 0.30 EURC — three fit under a 1.00 dailyCap, the fourth breaches


def _worker(config_dir: str, agent_id: str, idx: int, q) -> None:
    """Reserve once against the shared journal; report ('ok', value) or ('err', code)."""
    from rine.x402.errors import X402Error
    from rine.x402.journal import reserve_spend
    from rine.x402.policy import load_policy

    req = {
        "scheme": "exact",
        "network": BASE,
        "amount": AMOUNT,
        "asset": EURC,
        "payTo": "0xpayee",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "EURC", "version": "2"},
    }
    try:
        value = reserve_spend(
            config_dir,
            agent_id,
            load_policy(config_dir, agent_id),
            req,
            message_id=f"m{idx}",
            now_seconds=T,
        )
        q.put(("ok", value))
    except X402Error as err:
        q.put(("err", err.code))


def test_reserve_spend_under_process_contention_never_overshoots_cap(tmp_path) -> None:
    """16 processes reserve 0.30 each against a 1.50 cap → exactly 5 succeed, 11 refused.

    16-way contention exercises the lock's release/steal race window; the invariant
    (Σ reservations ≤ cap, no lost writes) is exact and must hold every run.
    """
    agent_id = str(uuid4())
    save_policy(
        str(tmp_path),
        agent_id,
        PaymentPolicy(
            per_tx_cap="1.00",
            daily_cap="1.50",
            allowed_assets=["EURC"],
            allowed_networks=[BASE],
            auto_pay_threshold="1.00",
        ),
    )

    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), agent_id, i, q)) for i in range(16)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)

    results = [q.get() for _ in procs]
    oks = [v for tag, v in results if tag == "ok"]
    errs = [v for tag, v in results if tag == "err"]
    assert sum(oks) == 1_500_000  # five 0.30 reservations fit exactly
    assert len(oks) == 5 and all(c == "daily-cap-exceeded" for c in errs)
    # No lost writes: the journal equals the sum of granted reservations, never over.
    assert read_daily_spent(str(tmp_path), agent_id, T) == 1_500_000
