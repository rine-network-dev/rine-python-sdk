"""A distribution row that never opens must not keep the negative cache off for good.

The listing is every distribution ever sent to the agent, so a garbled one stays in it. Once
any failed row made a scan incomplete, one such row meant a missed key was never
remembered: every read of a post without its key rescanned. The probes drive the real
``_scan_pending_sk_distributions`` of both clients with only the network mocked.
"""

from __future__ import annotations

import respx

from rine._sk_negative_cache import ROW_FAILURE_LIMIT, RowFailureLedger
from rine._utils import to_base64url
from tests.test_sender_key_ingest_guards import (
    ATTACKER_ID,
    _forged,
    _register,
    _stand_up,
)


def _poisoned(foreign_config_dir, tmp_config_dir, agent_id):
    """The attacker's genuinely signed DM whose chain key the ingest refuses."""
    published, _ = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
    poison = _forged(
        foreign_config_dir,
        tmp_config_dir,
        agent_id,
        ATTACKER_ID,
        chain_key=to_base64url(b"short"),
    )
    _register(agent_id, [poison], published)


class TestSettle:
    def test_settle_when_one_row_fails_the_limit_in_a_row_then_it_stops_counting(self) -> None:
        ledger = RowFailureLedger()
        for _ in range(ROW_FAILURE_LIMIT):
            assert ledger.settle("a", ["m"], ["m"]) == 1
        assert ledger.settle("a", ["m"], ["m"]) == 0

    def test_settle_when_the_row_opens_between_failures_then_the_streak_restarts(self) -> None:
        ledger = RowFailureLedger()
        for _ in range(ROW_FAILURE_LIMIT):
            ledger.settle("a", ["m"], ["m"])
        assert ledger.settle("a", ["m"], []) == 0
        assert ledger.settle("a", ["m"], ["m"]) == 1

    def test_settle_when_the_row_was_not_opened_then_its_streak_is_kept(self) -> None:
        ledger = RowFailureLedger()
        for _ in range(ROW_FAILURE_LIMIT):
            ledger.settle("a", ["m"], ["m"])
        assert ledger.settle("a", [], []) == 0
        assert ledger.settle("a", ["m"], ["m"]) == 0


class TestAPoisonRowAtScanLevel:
    @respx.mock
    def test_sync_scan_when_a_row_always_fails_then_it_blocks_only_the_limit_in_a_row(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        _poisoned(foreign_config_dir, tmp_config_dir, agent_id)

        for _ in range(ROW_FAILURE_LIMIT):
            scan = sync_client._scan_pending_sk_distributions(agent_id)
            assert (scan.failed, scan.complete) == (1, False)

        scan = sync_client._scan_pending_sk_distributions(agent_id)
        assert (scan.failed, scan.complete) == (0, True)

    @respx.mock
    async def test_async_scan_when_a_row_always_fails_then_it_blocks_only_the_limit_in_a_row(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        _poisoned(foreign_config_dir, tmp_config_dir, agent_id)

        for _ in range(ROW_FAILURE_LIMIT):
            scan = await async_client._scan_pending_sk_distributions(agent_id)
            assert (scan.failed, scan.complete) == (1, False)

        scan = await async_client._scan_pending_sk_distributions(agent_id)
        assert (scan.failed, scan.complete) == (0, True)
