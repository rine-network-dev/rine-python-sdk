"""MLS join: installing a Welcome, and self-joining by external commit.

These tests drive the real ``rine-mls`` core — only the server is mocked — so a
Welcome processed here is one a real founder produced, and a commit asserted here
is the one the server would receive.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import TYPE_CHECKING

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._mls import (
    DEFAULT_CIPHER_SUITE,
    KEY_PACKAGE_TARGET,
    ExternalJoin,
    external_join_mls_group,
    load_mls_group,
    mls_group_id_bytes,
    open_mls_client,
    process_mls_welcomes,
    publish_mls_key_packages,
)
from rine._mls import external_join as external_join_module
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.binding import EpochConflictError
from rine._mls.escrow_store import list_pending
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcome_spool import (
    SPOOL_MAX_ENTRIES,
    WelcomeSpool,
    is_spoolable_id,
    welcome_spool_dir,
)
from rine.errors import CryptoError, RineApiError
from rine.testing import WORLD
from rine.types import JoinedResult, PendingJoinResult
from tests.escrow_outcomes import DEFERRED, DEFERRED_REPORT

if TYPE_CHECKING:
    from rine._mls.external_join import ExternalJoinResult

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
WELCOME_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": "99999999-0000-1111-2222-333333333333",
    "mls_pending": False,
    "mls_cipher_suite": DEFAULT_CIPHER_SUITE,
}

_MEMBER_PAYLOAD = {
    "agent_id": "00000000-1111-2222-3333-444444444444",
    "group_id": GROUP_ID,
    "role": "member",
    "joined_at": "2024-01-01T00:00:00Z",
}


def _ignore(_welcome: bytes) -> None:
    """A release for a test that is not about it."""


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _mock_agents(agent_id: str) -> None:
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": agent_id,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _mock_upload(agent_id: str) -> respx.Route:
    return respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(201, json={"stored": 10})
    )


def _mock_welcomes(agent_id: str, *welcomes: tuple[str, str, bytes]) -> respx.Route:
    """Serve a one-shot welcome list: the first call carries them, later ones do not."""
    payloads = [
        {
            "id": wid,
            "group_id": group_id,
            "blob": base64.b64encode(blob).decode("ascii"),
            "created_at": "2024-01-01T00:00:00Z",
        }
        for wid, group_id, blob in welcomes
    ]
    return respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
        side_effect=[
            httpx.Response(200, json={"welcomes": payloads}),
            *[httpx.Response(200, json={"welcomes": []}) for _ in range(9)],
        ]
    )


def _peer_client(tmp_path, agent_id: str, other_agent_id: str):
    peer_dir = str(tmp_path / "peer")
    save_agent_keys(peer_dir, other_agent_id, WORLD.keys(other_agent_id))
    save_agent_keys(peer_dir, agent_id, WORLD.keys(agent_id))
    return open_mls_client(peer_dir, other_agent_id)


def _found_group(
    sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, *, with_us=True, pool=10
):
    """Found a real group on a peer, optionally admitting the agent under test."""
    _mock_token()
    route = _mock_upload(agent_id)
    publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id, count=pool)
    our_key_package = base64.b64decode(
        json.loads(route.calls[0].request.content)["packages"][0], validate=True
    )
    peer = _peer_client(tmp_path, agent_id, other_agent_id)
    save_agent_keys(tmp_config_dir, other_agent_id, WORLD.keys(other_agent_id))
    group = peer.create_group_with_members(
        mls_group_id_bytes(GROUP_ID), [our_key_package] if with_us else []
    )
    group.save()
    return group


def _local_group(tmp_config_dir, agent_id, group_id: str = GROUP_ID):
    return load_mls_group(open_mls_client(tmp_config_dir, agent_id), group_id)


class TestWelcomeInstall:
    @respx.mock
    def test_a_welcome_installs_state_keyed_by_the_rine_group_id(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        other_agent_id,
        tmp_path,
        mls_escrow_stub,
        escrow_calls,
    ):
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        welcome = group.last_commit().welcomes[0]
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, welcome))

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert outcome.discarded == 0
        joined = _local_group(tmp_config_dir, agent_id)
        assert joined is not None
        assert joined.epoch() == group.epoch()
        assert joined.cipher_suite() == DEFAULT_CIPHER_SUITE
        assert mls_escrow_stub == [(GROUP_ID, group.epoch())]
        assert escrow_calls == [("settle", GROUP_ID), ("drain", GROUP_ID)]

    @respx.mock
    def test_a_welcome_survives_a_crash_before_it_is_processed(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, monkeypatch
    ):
        """The server's fetch is one-shot, so the blob is on disk before it is used."""
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        welcome = group.last_commit().welcomes[0]
        route = _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, welcome))

        from rine._mls import welcomes as welcomes_module

        def _crash(*_args, **_kwargs):
            raise OSError("process died before the welcome was processed")

        monkeypatch.setattr(welcomes_module, "open_mls_client", _crash)
        with pytest.raises(OSError):
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert _local_group(tmp_config_dir, agent_id) is None
        assert len(WelcomeSpool(tmp_config_dir, agent_id).pending()) == 1

        monkeypatch.undo()
        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        # The server has nothing left to hand out: the replay came off disk.
        assert route.call_count == 2
        assert outcome.group_ids == (GROUP_ID,)
        assert _local_group(tmp_config_dir, agent_id) is not None

    @respx.mock
    def test_an_installed_welcome_leaves_nothing_spooled(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]))

        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
        again = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert again.group_ids == ()
        assert os.listdir(welcome_spool_dir(tmp_config_dir, agent_id)) == []

    @respx.mock
    def test_a_replayed_welcome_whose_join_already_landed_is_not_a_failure(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A crash between ``save()`` and dropping the spool entry must not warn."""
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        welcome = group.last_commit().welcomes[0]
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, welcome))
        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        spool = WelcomeSpool(tmp_config_dir, agent_id)
        spool.store(MlsWelcomeDelivery(id=WELCOME_ID, group_id=GROUP_ID, welcome=welcome))
        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert outcome.discarded == 0

    @respx.mock
    def test_an_unusable_welcome_is_dropped_without_blocking_a_good_one(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, caplog
    ):
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_welcomes(
            agent_id,
            ("00000000-0000-0000-0000-000000000001", GROUP_ID, b"\x00\x01not a welcome"),
            (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]),
        )

        with caplog.at_level("WARNING"):
            outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert outcome.discarded == 1
        assert any("unusable MLS welcome" in r.getMessage() for r in caplog.records)
        assert os.listdir(welcome_spool_dir(tmp_config_dir, agent_id)) == []

    @respx.mock
    def test_a_welcome_delivered_under_the_wrong_group_is_refused(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """State keyed by the wrong group is unrecoverable; raising is not.

        It raises rather than logging because both stacks must be loud and
        must agree: a refusal that is loud on one and a warning on the
        other is a defect a user only ever meets on the quiet one.
        """
        other_group = "cccccccc-dddd-eeee-ffff-000000000000"
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_welcomes(agent_id, (WELCOME_ID, other_group, group.last_commit().welcomes[0]))

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert excinfo.value.reason == "group_id_mismatch"
        assert _local_group(tmp_config_dir, agent_id, other_group) is None
        # Dropped from the spool too: one left there would raise on every later
        # pass and block every legitimate Welcome behind it.
        assert os.listdir(welcome_spool_dir(tmp_config_dir, agent_id)) == []

    @respx.mock
    def test_installing_a_welcome_tops_the_key_package_pool_back_up(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The join consumed one of ours — the only path our own pool shrinks on."""
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, pool=3
        )
        upload = respx.post(f"{API}/agents/{agent_id}/mls/key-packages")
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]))

        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        # 3 published, 1 spent joining, 2 left — below the core's low-water mark,
        # so the install topped the pool back up to its target.
        assert upload.call_count == 2
        assert open_mls_client(tmp_config_dir, agent_id).key_package_count() == KEY_PACKAGE_TARGET


def _mock_group_info(group, *, epoch: int = 1) -> respx.Route:
    return respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
        return_value=httpx.Response(
            200,
            json={
                "group_info": base64.b64encode(group.group_info()).decode("ascii"),
                "epoch": epoch,
            },
        )
    )


def _external_join(sync_client, tmp_config_dir, agent_id) -> ExternalJoinResult:
    return external_join_mls_group(
        ExternalJoin(
            client=sync_client._http,
            config_dir=tmp_config_dir,
            agent_id=agent_id,
            group_id=GROUP_ID,
            extra_headers={"X-Rine-Agent": agent_id},
        )
    )


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch):
    monkeypatch.setattr(external_join_module, "PENDING_RETRY_DELAY_S", 0)


class TestTheNameAWelcomeIsFiledUnder:
    """The delivery id becomes the file NAME, and the server chooses it.

    MEASURED before the check existed: an id of
    ``../../../../elsewhere/poison`` wrote outside the spool dir entirely, and
    on this stack it did not even raise — ``_write_atomic`` calls ``_ensure_dir``,
    so it creates the traversed directories on the way. The TypeScript twin
    overwrote ``<configDir>/profiles.json``, which is both the profile store
    and the file the config dir is located by.
    """

    def test_an_id_that_is_not_a_plain_file_name_is_refused(self):
        assert is_spoolable_id(WELCOME_ID)
        # The fixtures both stacks ship use ids like this, and an honest server
        # is free to reformat its own column, so the rule is "can be a file
        # name", not "is a UUID".
        assert is_spoolable_id("welcome-0")

        assert not is_spoolable_id("../../../credentials")
        assert not is_spoolable_id("a/b")
        assert not is_spoolable_id("a\\b")
        assert not is_spoolable_id("..")
        assert not is_spoolable_id(".hidden")
        assert not is_spoolable_id("")
        assert not is_spoolable_id("a" * 129)

    def test_storing_an_escaping_id_writes_nothing(self, tmp_config_dir, agent_id):
        outside = os.path.join(tmp_config_dir, "poison.json")
        spool = WelcomeSpool(tmp_config_dir, agent_id)

        with pytest.raises(ValueError, match="plain file name"):
            spool.store(
                MlsWelcomeDelivery(id="../../../poison", group_id=GROUP_ID, welcome=b"\x01")
            )

        assert not os.path.exists(outside)

    @respx.mock
    def test_a_welcome_named_a_path_is_dropped_and_the_batch_survives(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, caplog
    ):
        # The loss half of the same defect: the TypeScript twin threw out of the
        # fetch loop, so every Welcome behind the poisoned one was never written
        # — and the server had already marked them all consumed.
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_welcomes(
            agent_id,
            ("../../../poison", GROUP_ID, b"\x00\x01not a welcome"),
            (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]),
        )

        with caplog.at_level("WARNING"):
            outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert outcome.discarded == 1
        assert not os.path.exists(os.path.join(tmp_config_dir, "poison.json"))
        assert "plain file name" in caplog.text


class TestWhatTheSpoolKeeps:
    """Retention is right; unbounded retention is a tax the server chooses.

    A ``roster_uncorroborated`` refusal for a genuinely substituted Welcome can
    never clear, so a retained entry can be permanent — and each one costs a
    real join plus a full roster read on every later pass, on a path that runs
    on every MLS group send and every failed-decrypt recovery.

    🔴 What the bound costs, stated here rather than buried: an honest Welcome
    whose refusal has not cleared in a week, or which is the oldest of more than
    a commit's worth of simultaneously retained refusals, is dropped and only a
    re-invitation replaces it — which is the remedy the refusal messages name.
    """

    @staticmethod
    def _fill(tmp_config_dir, agent_id, ids: list[str], age_seconds: float = 0.0) -> None:
        """Spool one RETAINED REFUSAL per id, oldest first.

        The mark is what puts an entry in the population the count bound holds.
        A spooled Welcome no pass has tried yet is deliberately not in it —
        ``test_mls_welcome_spool.py`` covers that half.
        """
        spool = WelcomeSpool(tmp_config_dir, agent_id)
        now = time.time()
        for offset, spool_id in enumerate(ids):
            spool.store(MlsWelcomeDelivery(id=spool_id, group_id=GROUP_ID, welcome=b"\x01"))
            path = os.path.join(welcome_spool_dir(tmp_config_dir, agent_id), f"{spool_id}.json")
            spool.mark_refused(path)
            when = now - age_seconds - (len(ids) - offset)
            os.utime(path, (when, when))

    def test_more_than_the_cap_drops_the_oldest(self, tmp_config_dir, agent_id):
        names = [f"w{index:03d}" for index in range(SPOOL_MAX_ENTRIES + 4)]
        self._fill(tmp_config_dir, agent_id, names)

        assert WelcomeSpool(tmp_config_dir, agent_id).prune(_ignore) == 4

        # The newest survive: their refusal is the one most likely still to clear.
        kept = [d.id for _p, d in WelcomeSpool(tmp_config_dir, agent_id).pending()]
        assert kept == names[4:]

    def test_a_retained_welcome_older_than_the_bound_is_dropped(self, tmp_config_dir, agent_id):
        self._fill(tmp_config_dir, agent_id, ["old-0", "old-1"], age_seconds=8 * 24 * 60 * 60)
        self._fill(tmp_config_dir, agent_id, ["new-0"])

        assert WelcomeSpool(tmp_config_dir, agent_id).prune(_ignore) == 2
        assert len(WelcomeSpool(tmp_config_dir, agent_id).pending()) == 1

    def test_nothing_past_the_bound_keeps_everything(self, tmp_config_dir, agent_id):
        self._fill(tmp_config_dir, agent_id, [f"w{index}" for index in range(5)])

        assert WelcomeSpool(tmp_config_dir, agent_id).prune(_ignore) == 0
        assert len(WelcomeSpool(tmp_config_dir, agent_id).pending()) == 5

    def test_the_queue_is_ordered_by_write_time_not_by_the_servers_names(
        self, tmp_config_dir, agent_id
    ):
        spool = WelcomeSpool(tmp_config_dir, agent_id)
        spool.store(MlsWelcomeDelivery(id="zzz", group_id=GROUP_ID, welcome=b"\x01"))
        spool.store(MlsWelcomeDelivery(id="aaa", group_id=GROUP_ID, welcome=b"\x01"))
        older = time.time() - 60
        os.utime(
            os.path.join(welcome_spool_dir(tmp_config_dir, agent_id), "zzz.json"), (older, older)
        )

        # The name is the server-chosen delivery id, so a name-ordered queue lets
        # the server decide which Welcome is processed first.
        assert [d.id for _p, d in spool.pending()] == ["zzz", "aaa"]


class TestExternalJoin:
    @respx.mock
    def test_self_join_commits_at_the_next_epoch_and_keeps_the_state(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        other_agent_id,
        tmp_path,
        mls_escrow_stub,
        escrow_calls,
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )

        epoch = _external_join(sync_client, tmp_config_dir, agent_id).epoch

        body = json.loads(commit.calls[0].request.content)
        assert epoch == 2
        assert body["epoch"] == group.epoch() + 1
        assert body["cipher_suite"] == DEFAULT_CIPHER_SUITE
        assert body["welcomes"] == []
        assert base64.b64decode(body["commit"], validate=True)
        joined = _local_group(tmp_config_dir, agent_id)
        assert joined is not None
        assert joined.epoch() == 2
        assert mls_escrow_stub == [(GROUP_ID, 2)]
        assert escrow_calls == [("settle", GROUP_ID), ("drain", GROUP_ID)]

    @respx.mock
    def test_self_join_when_the_escrow_drain_defers_then_the_result_carries_the_report(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        other_agent_id,
        tmp_path,
        mls_escrow_stub,
        monkeypatch,
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_group_info(group)
        respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )
        monkeypatch.setattr(external_join_module, "drain_escrow", lambda *_a, **_k: DEFERRED)

        result = _external_join(sync_client, tmp_config_dir, agent_id)

        assert result.epoch == 2
        assert result.escrow == DEFERRED_REPORT

    @respx.mock
    def test_a_competing_joiner_costs_one_rebuild_not_a_loop(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        info = _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            side_effect=[
                httpx.Response(
                    409,
                    json={
                        "error": "epoch_conflict",
                        "detail": "group at epoch 2, commit targets 2",
                    },
                ),
                httpx.Response(200, json={"epoch": 3, "delivered_to": 1}),
            ]
        )

        epoch = _external_join(sync_client, tmp_config_dir, agent_id).epoch

        assert epoch == 3
        assert commit.call_count == 2
        # The rebuild fetches a fresh GroupInfo: a GroupInfo is single-use per epoch.
        assert info.call_count == 2

    @respx.mock
    def test_a_local_epoch_conflict_costs_one_rebuild_like_the_servers(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, monkeypatch
    ):
        """The core's own epoch conflict is the same answer as the server's 409."""
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        info = _mock_group_info(group)
        respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )
        real_post = external_join_module.post_mls_commit
        posts = iter([EpochConflictError("built against a superseded epoch")])

        def post_once_stale(*args, **kwargs):
            for err in posts:
                raise err
            return real_post(*args, **kwargs)

        monkeypatch.setattr(external_join_module, "post_mls_commit", post_once_stale)

        epoch = _external_join(sync_client, tmp_config_dir, agent_id).epoch

        assert epoch == 2
        assert info.call_count == 2

    @respx.mock
    def test_a_second_epoch_conflict_stops_and_leaves_no_state(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, mls_escrow_stub
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(409, json={"error": "epoch_conflict", "detail": "stale"})
        )

        with pytest.raises(CryptoError, match="after one retry"):
            _external_join(sync_client, tmp_config_dir, agent_id)

        assert commit.call_count == 2
        assert _local_group(tmp_config_dir, agent_id) is None
        # A commit the server refused escrows nothing.
        assert list_pending(tmp_config_dir, agent_id, GROUP_ID) == []
        assert mls_escrow_stub == []

    @respx.mock
    def test_a_refusal_that_is_not_an_epoch_conflict_is_not_retried(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(
                403, json={"error": "mls_open_enrollment_disabled", "detail": "not allowed"}
            )
        )

        with pytest.raises(RineApiError):
            _external_join(sync_client, tmp_config_dir, agent_id)

        assert commit.call_count == 1

    @respx.mock
    def test_an_unconfirmed_group_info_is_waited_out(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        info = respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            side_effect=[
                httpx.Response(409, json={"error": "pending_confirmation", "detail": "wait"}),
                httpx.Response(
                    200,
                    json={
                        "group_info": base64.b64encode(group.group_info()).decode("ascii"),
                        "epoch": 1,
                    },
                ),
            ]
        )
        respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )

        assert _external_join(sync_client, tmp_config_dir, agent_id).epoch == 2
        assert info.call_count == 2

    @respx.mock
    def test_a_group_info_that_never_confirms_is_refused_not_looped(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        info = respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(
                409, json={"error": "pending_confirmation", "detail": "wait"}
            )
        )

        with pytest.raises(CryptoError, match="awaiting confirmation"):
            _external_join(sync_client, tmp_config_dir, agent_id)

        assert info.call_count == external_join_module.PENDING_RETRY_LIMIT

    @respx.mock
    def test_a_group_with_no_published_group_info_says_so(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
        )

        with pytest.raises(CryptoError, match="published no GroupInfo"):
            _external_join(sync_client, tmp_config_dir, agent_id)


def _mock_join(status: int = 200, payload: dict | None = None) -> respx.Route:
    return respx.post(f"{API}/groups/{GROUP_ID}/join").mock(
        return_value=httpx.Response(status, json=payload if payload else _MEMBER_PAYLOAD)
    )


def _mock_group_read(**overrides) -> respx.Route:
    return respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json={**_GROUP_PAYLOAD, **overrides})
    )


class TestGroupsJoin:
    @respx.mock
    def test_joining_an_mls_group_installs_the_pending_welcome(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_agents(agent_id)
        _mock_group_read()
        _mock_join()
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]))

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert _local_group(tmp_config_dir, agent_id) is not None

    @respx.mock
    def test_joining_with_no_welcome_self_joins_by_external_commit(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_agents(agent_id)
        _mock_group_read()
        _mock_join()
        _mock_welcomes(agent_id)
        _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )

        sync_client.groups.join(GROUP_ID)

        assert commit.call_count == 1
        assert _local_group(tmp_config_dir, agent_id) is not None

    @respx.mock
    def test_a_pending_join_touches_no_mls_state(self, sync_client, tmp_config_dir, agent_id):
        _mock_token()
        _mock_agents(agent_id)
        welcomes = _mock_welcomes(agent_id)
        _mock_join(
            202,
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "group_id": GROUP_ID,
                "agent_id": agent_id,
                "status": "pending",
                "created_at": "2024-01-01T00:00:00Z",
            },
        )

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, PendingJoinResult)
        assert welcomes.call_count == 0

    @respx.mock
    def test_joining_a_sender_key_group_does_no_mls_work(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_group_read(mls_group_id=None, mls_enabled=False)
        _mock_join()
        welcomes = _mock_welcomes(agent_id)

        sync_client.groups.join(GROUP_ID)

        assert welcomes.call_count == 0

    @respx.mock
    def test_a_failed_mls_install_still_joins_the_group(
        self, sync_client, tmp_config_dir, agent_id, caplog
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_group_read()
        _mock_join()
        respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
            return_value=httpx.Response(503, json={"detail": "down"})
        )

        with caplog.at_level("WARNING"):
            result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert any("MLS setup failed" in r.getMessage() for r in caplog.records)

    @respx.mock
    async def test_async_join_installs_the_same_welcome(
        self, async_client, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_agents(agent_id)
        _mock_group_read()
        _mock_join()
        _mock_welcomes(agent_id, (WELCOME_ID, GROUP_ID, group.last_commit().welcomes[0]))

        result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert _local_group(tmp_config_dir, agent_id) is not None
        await async_client.close()
