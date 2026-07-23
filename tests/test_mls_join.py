"""MLS join: installing a Welcome, and self-joining by external commit.

These tests drive the real ``rine-mls`` core — only the server is mocked — so a
Welcome processed here is one a real founder produced, and a commit asserted here
is the one the server would receive.
"""

from __future__ import annotations

import base64
import json
import os

import httpx
import pytest
import respx

from rine._crypto.keys import generate_agent_keys, save_agent_keys
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
from rine._mls.welcome_spool import WelcomeSpool, welcome_spool_dir
from rine.errors import CryptoError, RineApiError
from rine.types import JoinedResult, PendingJoinResult

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


def _peer_client(tmp_path, other_agent_id: str):
    peer_dir = str(tmp_path / "peer")
    save_agent_keys(peer_dir, other_agent_id, generate_agent_keys())
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
    peer = _peer_client(tmp_path, other_agent_id)
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
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
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

        from rine._mls.api import MlsWelcomeDelivery

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
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, caplog
    ):
        """State keyed by the wrong group is unrecoverable; failing loudly is not."""
        other_group = "cccccccc-dddd-eeee-ffff-000000000000"
        group = _found_group(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_welcomes(agent_id, (WELCOME_ID, other_group, group.last_commit().welcomes[0]))

        with caplog.at_level("WARNING"):
            outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == ()
        assert outcome.discarded == 1
        assert _local_group(tmp_config_dir, agent_id, other_group) is None

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


def _external_join(sync_client, tmp_config_dir, agent_id) -> int:
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


class TestExternalJoin:
    @respx.mock
    def test_self_join_commits_at_the_next_epoch_and_keeps_the_state(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_group(
            sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, with_us=False
        )
        _mock_group_info(group)
        commit = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 2, "delivered_to": 1})
        )

        epoch = _external_join(sync_client, tmp_config_dir, agent_id)

        body = json.loads(commit.calls[0].request.content)
        assert epoch == 2
        assert body["epoch"] == group.epoch() + 1
        assert body["cipher_suite"] == DEFAULT_CIPHER_SUITE
        assert body["welcomes"] == []
        assert base64.b64decode(body["commit"], validate=True)
        joined = _local_group(tmp_config_dir, agent_id)
        assert joined is not None
        assert joined.epoch() == 2

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

        epoch = _external_join(sync_client, tmp_config_dir, agent_id)

        assert epoch == 3
        assert commit.call_count == 2
        # The rebuild fetches a fresh GroupInfo: a GroupInfo is single-use per epoch.
        assert info.call_count == 2

    @respx.mock
    def test_a_second_epoch_conflict_stops_and_leaves_no_state(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
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

        assert _external_join(sync_client, tmp_config_dir, agent_id) == 2
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
