"""An empty scan for a sender's key is the answer for every post that needs it, for 15 minutes.

An agent reading twenty posts whose sender key never arrived used to list the distribution inbox
twenty times. The tests drive ``_self_heal_group_decrypt`` of both clients with the scan counted
at the method that does it, and the cache with a clock a test can move.
"""

from __future__ import annotations

import threading
from typing import Any
from uuid import NAMESPACE_OID, uuid5

import pytest
import respx

from rine._sk_negative_cache import (
    NEGATIVE_MAX_ENTRIES,
    NEGATIVE_TTL_SECONDS,
    SENDER_KEY_NEGATIVE_CACHE,
    MissingSenderKey,
    SenderKeyNegativeCache,
    missing_sender_key,
)
from rine._group_recovery import SenderKeyScan
from rine._resources.group_sync import sync_group_state
from rine.errors import CryptoError, NoSenderKeyStateError
from rine.types import DecryptedMessage

AGENT = "00000000-1111-2222-3333-444444444444"
GROUP = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
SENDER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KEY_ID = "11111111-2222-3333-4444-555555555555"


class FakeClock:
    """A monotonic clock a test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _row(
    message_id: str, *, sender: str | None = SENDER, version: str = "sender-key-v1"
) -> DecryptedMessage:
    return DecryptedMessage(
        id=uuid5(NAMESPACE_OID, message_id),
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="opaque",
        encryption_version=version,
        created_at="2024-01-01T00:00:00Z",
        direction="received",
        group_id=GROUP,
        from_agent_id=sender,
    )


def _missing(key_id: str = KEY_ID) -> NoSenderKeyStateError:
    return NoSenderKeyStateError("no sender key state", key_id)


def _entry(**overrides: str) -> MissingSenderKey:
    return MissingSenderKey(
        **{
            "agent_id": AGENT,
            "group_id": GROUP,
            "sender_agent_id": SENDER,
            "key_id": KEY_ID,
            **overrides,
        }
    )


class TestTheCacheItself:
    def test_is_cached_when_an_empty_scan_was_recorded_then_true_until_the_ttl(self) -> None:
        clock = FakeClock()
        cache = SenderKeyNegativeCache(clock)
        cache.record_missing(_entry())

        assert cache.is_cached(_entry())
        clock.now += NEGATIVE_TTL_SECONDS - 1
        assert cache.is_cached(_entry())
        clock.now += 1
        assert not cache.is_cached(_entry())

    def test_is_cached_when_the_ids_differ_in_case_then_they_are_the_same_entry(self) -> None:
        cache = SenderKeyNegativeCache(FakeClock())
        cache.record_missing(_entry())

        assert cache.is_cached(_entry(sender_agent_id=SENDER.upper(), group_id=GROUP.upper()))

    @pytest.mark.parametrize(
        "other",
        [
            {"agent_id": "99999999-1111-2222-3333-444444444444"},
            {"group_id": "99999999-cccc-dddd-eeee-ffffffffffff"},
            {"sender_agent_id": "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"},
            {"key_id": "99999999-2222-3333-4444-555555555555"},
        ],
    )
    def test_is_cached_when_any_part_of_the_key_differs_then_false(
        self, other: dict[str, str]
    ) -> None:
        cache = SenderKeyNegativeCache(FakeClock())
        cache.record_missing(_entry())

        assert not cache.is_cached(_entry(**other))

    def test_record_missing_when_full_then_the_oldest_entry_goes(self) -> None:
        cache = SenderKeyNegativeCache(FakeClock())
        keys = [_entry(key_id=f"key-{n}") for n in range(NEGATIVE_MAX_ENTRIES + 1)]
        for key in keys:
            cache.record_missing(key)

        assert not cache.is_cached(keys[0])
        assert cache.is_cached(keys[1])
        assert cache.is_cached(keys[-1])

    def test_clear_sender_when_called_then_only_that_sender_of_that_agent_is_forgotten(
        self,
    ) -> None:
        cache = SenderKeyNegativeCache(FakeClock())
        other_sender = _entry(sender_agent_id="99999999-bbbb-cccc-dddd-eeeeeeeeeeee")
        other_agent = _entry(agent_id="99999999-1111-2222-3333-444444444444")
        for key in (_entry(), other_sender, other_agent):
            cache.record_missing(key)

        cache.clear_sender(AGENT.upper(), SENDER.upper())

        assert not cache.is_cached(_entry())
        assert cache.is_cached(other_sender)
        assert cache.is_cached(other_agent)

    def test_the_cache_when_hammered_from_threads_then_it_stays_consistent(self) -> None:
        cache = SenderKeyNegativeCache(FakeClock())
        failures: list[BaseException] = []

        def work(worker: int) -> None:
            try:
                for n in range(300):
                    key = _entry(key_id=f"{worker}-{n % 40}")
                    cache.record_missing(key)
                    cache.is_cached(key)
                    if n % 25 == 0:
                        cache.clear_sender(AGENT, SENDER)
            except BaseException as exc:  # noqa: BLE001 - the test reports whatever a thread hit
                failures.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert failures == []
        assert len(cache._expiries) <= NEGATIVE_MAX_ENTRIES


class TestWhichFailuresTheCacheSpeaksFor:
    def test_missing_sender_key_when_the_decrypt_named_an_absent_key_then_names_it(self) -> None:
        assert missing_sender_key(AGENT, _row("m1"), _missing()) == _entry()

    def test_missing_sender_key_when_the_error_is_another_crypto_failure_then_none(self) -> None:
        assert missing_sender_key(AGENT, _row("m1"), CryptoError("bad tag")) is None

    def test_missing_sender_key_when_the_row_names_no_sender_then_none(self) -> None:
        assert missing_sender_key(AGENT, _row("m1", sender=None), _missing()) is None


def _wire_sync(
    client: Any, scans: list[str], ingested: int = 0, unscanned: int = 0, failed: int = 0
) -> None:
    client._retirement_blocks_read = lambda agent_id, group_id: False
    client._scan_pending_sk_distributions = lambda agent_id: (
        scans.append(agent_id) or SenderKeyScan(ingested, unscanned, failed)
    )

    def fail_decrypt(agent_id: str, msg: DecryptedMessage) -> DecryptedMessage:
        raise _missing()

    client._decrypt_message = fail_decrypt


def _wire_async(
    client: Any, scans: list[str], ingested: int = 0, unscanned: int = 0, failed: int = 0
) -> None:
    async def not_blocked(agent_id: str, group_id: Any) -> bool:
        return False

    async def scan(agent_id: str) -> SenderKeyScan:
        scans.append(agent_id)
        return SenderKeyScan(ingested, unscanned, failed)

    async def fail_decrypt(agent_id: str, msg: DecryptedMessage) -> DecryptedMessage:
        raise _missing()

    client._retirement_blocks_read = not_blocked
    client._scan_pending_sk_distributions = scan
    client._decrypt_message = fail_decrypt


class TestTwentyUnopenablePostsCostOneScan:
    def test_self_heal_group_decrypt_sync_when_twenty_posts_lack_the_key_then_one_scan(
        self, sync_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans)

        rows = [
            sync_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), _missing())
            for n in range(20)
        ]

        assert len(scans) == 1
        assert all(row.decrypt_error for row in rows)

    async def test_self_heal_group_decrypt_async_when_twenty_posts_lack_the_key_then_one_scan(
        self, async_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_async(async_client, scans)

        rows = [
            await async_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), _missing())
            for n in range(20)
        ]

        assert len(scans) == 1
        assert all(row.decrypt_error for row in rows)

    def test_self_heal_group_decrypt_sync_when_a_scan_ingested_something_then_it_is_not_cached(
        self, sync_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans, ingested=1)

        for n in range(3):
            sync_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), _missing())

        assert len(scans) == 3

    @pytest.mark.parametrize(("unscanned", "failed"), [(36, 0), (0, 1)])
    def test_self_heal_group_decrypt_sync_when_the_scan_was_incomplete_then_it_is_not_cached(
        self, sync_client, agent_id, unscanned: int, failed: int
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans, unscanned=unscanned, failed=failed)

        for n in range(3):
            sync_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), _missing())

        assert len(scans) == 3

    @pytest.mark.parametrize(("unscanned", "failed"), [(36, 0), (0, 1)])
    async def test_self_heal_group_decrypt_async_when_the_scan_was_incomplete_then_it_is_not_cached(
        self, async_client, agent_id, unscanned: int, failed: int
    ) -> None:
        scans: list[str] = []
        _wire_async(async_client, scans, unscanned=unscanned, failed=failed)

        for n in range(3):
            await async_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), _missing())

        assert len(scans) == 3

    def test_self_heal_group_decrypt_sync_when_the_sender_differs_then_each_is_scanned_once(
        self, sync_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans)
        other = "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"

        for n in range(4):
            sync_client._self_heal_group_decrypt(agent_id, _row(f"a{n}"), _missing())
            sync_client._self_heal_group_decrypt(agent_id, _row(f"b{n}", sender=other), _missing())

        assert len(scans) == 2

    def test_self_heal_group_decrypt_sync_when_another_crypto_error_then_it_is_never_cached(
        self, sync_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans)

        for n in range(3):
            sync_client._self_heal_group_decrypt(agent_id, _row(f"m{n}"), CryptoError("bad tag"))

        assert len(scans) == 3


class TestTheEntryEndsWhenSomethingCouldHaveChanged:
    def test_self_heal_group_decrypt_sync_when_the_ttl_passes_then_it_scans_again(
        self, sync_client, agent_id, monkeypatch
    ) -> None:
        clock = FakeClock()
        monkeypatch.setattr(SENDER_KEY_NEGATIVE_CACHE, "_clock", clock)
        scans: list[str] = []
        _wire_sync(sync_client, scans)

        sync_client._self_heal_group_decrypt(agent_id, _row("m1"), _missing())
        sync_client._self_heal_group_decrypt(agent_id, _row("m2"), _missing())
        clock.now += NEGATIVE_TTL_SECONDS
        sync_client._self_heal_group_decrypt(agent_id, _row("m3"), _missing())

        assert len(scans) == 2

    def test_clear_sender_when_a_distribution_from_them_lands_then_the_next_read_scans(
        self, sync_client, agent_id
    ) -> None:
        scans: list[str] = []
        _wire_sync(sync_client, scans)
        sync_client._self_heal_group_decrypt(agent_id, _row("m1"), _missing())

        SENDER_KEY_NEGATIVE_CACHE.clear_sender(agent_id, SENDER)
        sync_client._self_heal_group_decrypt(agent_id, _row("m2"), _missing())

        assert len(scans) == 2

    def test_group_sync_when_the_key_is_cached_missing_then_it_still_scans(
        self, sync_client, agent_id
    ) -> None:
        """The explicit sync is the caller asking for a scan, so the cache never answers it."""
        scans: list[str] = []
        sync_client._resolve_group_sync = lambda handle_or_id, agent: GROUP
        sync_client._resolve_agent_id = lambda agent: agent_id
        sync_client._agent_header = lambda agent: None
        sync_client._retirement_blocks_read = lambda acting, group_id: False
        sync_client._http.get = lambda path, **kwargs: {
            "id": GROUP,
            "name": "billboard",
            "handle": "#billboard@acme.rine.network",
            "created_at": "2024-01-01T00:00:00Z",
        }

        def scan(acting: str) -> SenderKeyScan:
            scans.append(acting)
            return SenderKeyScan(ingested=0, unscanned=0)

        sync_client._scan_pending_sk_distributions = scan
        SENDER_KEY_NEGATIVE_CACHE.record_missing(_entry(agent_id=agent_id))

        result = sync_group_state(sync_client, GROUP, agent=None)

        assert scans == [agent_id]
        assert result.ingested == 0


class TestADistributionFromThemLiftsTheEntry:
    @respx.mock
    def test_scan_pending_sk_distributions_when_it_ingests_from_a_sender_then_their_entries_clear(
        self, sync_client, agent_id, group_message_fixture, mock_group_message_routes
    ) -> None:
        theirs = MissingSenderKey(
            agent_id, group_message_fixture.group_id, group_message_fixture.sender_id, KEY_ID
        )
        bystander = MissingSenderKey(
            agent_id, GROUP, "99999999-bbbb-cccc-dddd-eeeeeeeeeeee", KEY_ID
        )
        SENDER_KEY_NEGATIVE_CACHE.record_missing(theirs)
        SENDER_KEY_NEGATIVE_CACHE.record_missing(bystander)
        mock_group_message_routes()

        scan = sync_client._scan_pending_sk_distributions(agent_id)

        assert scan.ingested == 1
        assert not SENDER_KEY_NEGATIVE_CACHE.is_cached(theirs)
        assert SENDER_KEY_NEGATIVE_CACHE.is_cached(bystander)
