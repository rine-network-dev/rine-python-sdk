"""MLS wiring: the KeyPackage pool, and founding a group's MLS state.

These tests drive the real ``rine-mls`` core — only the server is mocked — so a
KeyPackage asserted here is the one a peer would actually claim.
"""

from __future__ import annotations

import base64
import json
import os

import httpx
import pytest
import respx

from rine._config import mls_store_dir
from rine._mls import (
    DEFAULT_CIPHER_SUITE,
    KEY_PACKAGE_TARGET,
    drain_and_republish_mls_key_packages,
    ensure_mls_key_packages,
    epoch_retention_limit,
    open_mls_client,
    publish_mls_key_packages,
    replenish_mls_key_packages,
)
from rine._mls.binding import EPOCH_RETENTION_ENV
from rine._owner import resolve_owner_dir
from rine.errors import ConfigError, RineApiError
from rine.format import group_is_mls
from rine.testing import write_owner
from tests.identity import echo_created_agent

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": None,
    "mls_pending": False,
    "mls_cipher_suite": None,
}


@pytest.fixture
def key_is_current(monkeypatch: pytest.MonkeyPatch) -> None:
    """The drain's pre-check passes: this device holds the agent's published key."""
    monkeypatch.setattr("rine._mls.key_package_cutover.disk_key_is_current", lambda _actor: True)


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


def _mock_upload(agent_id: str, stored: int = KEY_PACKAGE_TARGET) -> respx.Route:
    return respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(201, json={"stored": stored})
    )


def _uploaded_packages(route: respx.Route, call: int = 0) -> list[bytes]:
    body = json.loads(route.calls[call].request.content)
    return [base64.b64decode(p, validate=True) for p in body["packages"]]


def _mock_claim(agent_id: str, pages: list[list[bytes]] | None = None) -> respx.Route:
    """Mock the destructive claim endpoint the drain empties the pool with.

    Each entry in ``pages`` is one claim response; once they run out the endpoint
    answers 409 "No key packages available" — the drain's done signal. With no
    pages the server pool is already empty (a fresh-core agent).
    """
    responses = [
        httpx.Response(
            200,
            json={
                "agent_id": agent_id,
                "packages": [base64.b64encode(p).decode("ascii") for p in page],
            },
        )
        for page in (pages or [])
    ]
    responses.append(httpx.Response(409, json={"detail": "No key packages available"}))
    return respx.get(f"{API}/agents/{agent_id}/mls/key-packages").mock(side_effect=responses)


class TestKeyPackagePool:
    @respx.mock
    def test_publish_when_pool_is_empty_uploads_the_core_s_target_batch(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        route = _mock_upload(agent_id)

        stored = publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert stored == KEY_PACKAGE_TARGET
        assert len(_uploaded_packages(route)) == KEY_PACKAGE_TARGET

    @respx.mock
    def test_published_key_packages_are_mls_message_framed(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """Only the framed form is minted — a bare KeyPackage is unreadable.

        An ``MLSMessage`` opens with ``version(2) || wire_format(2)``; the bare
        RFC 9420 ``KeyPackage`` the previous core published opened with
        ``version(2) || cipher_suite(2)`` instead.
        """
        _mock_token()
        route = _mock_upload(agent_id)

        publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        blob = _uploaded_packages(route)[0]
        assert blob[0:2] == b"\x00\x01"  # MLS protocol version 1
        assert blob[2:4] == b"\x00\x05"  # wire_format = mls_key_package
        assert blob[4:8] == b"\x00\x01\xf0\x57"  # the KeyPackage's own suite: X-Wing

    @respx.mock
    def test_a_published_key_package_can_found_a_group_with_this_member(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The blob on the wire is the one a peer adds us with — end to end."""
        _mock_token()
        route = _mock_upload(agent_id)
        publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        peer_dir = str(tmp_path / "peer")
        from rine._crypto.keys import save_agent_keys
        from rine.testing import WORLD

        save_agent_keys(peer_dir, other_agent_id, WORLD.keys(other_agent_id))
        save_agent_keys(peer_dir, agent_id, WORLD.keys(agent_id))
        peer = open_mls_client(peer_dir, other_agent_id)

        group = peer.create_group_with_members(
            bytes.fromhex(GROUP_ID.replace("-", "")), [_uploaded_packages(route)[0]]
        )

        bundle = group.last_commit()
        assert bundle is not None
        assert len(bundle.welcomes) == 1
        assert group.cipher_suite() == DEFAULT_CIPHER_SUITE

    @respx.mock
    def test_ensure_when_pool_is_healthy_publishes_nothing(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        route = _mock_upload(agent_id)
        publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        status = ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert status.available == KEY_PACKAGE_TARGET
        assert status.published == 0
        assert status.cap_reached is False
        assert route.call_count == 1

    @respx.mock
    def test_ensure_when_pool_is_empty_tops_it_back_up(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        _mock_upload(agent_id)

        status = ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert status.available == 0
        assert status.published == KEY_PACKAGE_TARGET

    @respx.mock
    def test_ensure_when_server_inventory_is_full_is_a_no_op_success(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
            return_value=httpx.Response(422, json={"detail": "Key package inventory full"})
        )

        status = ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert status.cap_reached is True
        assert status.published == 0

    @respx.mock
    def test_ensure_when_server_answers_the_inventory_full_code_is_a_no_op_success(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """The machine code decides, whatever the detail sentence says."""
        _mock_token()
        respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
            return_value=httpx.Response(
                422, json={"error": "key_package_inventory_full", "detail": "At the cap"}
            )
        )

        status = ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert status.cap_reached is True
        assert status.published == 0

    @respx.mock
    def test_ensure_when_the_server_rejects_the_upload_raises(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
            return_value=httpx.Response(403, json={"detail": "forbidden"})
        )

        with pytest.raises(RineApiError):
            ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

    @respx.mock
    def test_replenish_when_the_server_is_unreachable_never_raises(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
            side_effect=httpx.ConnectError("down")
        )

        replenish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

    @respx.mock
    @pytest.mark.usefixtures("key_is_current")
    def test_drain_replaces_every_key_package(self, sync_client, tmp_config_dir, agent_id):
        """The cutover: the old pool goes, a fresh one is published in one step."""
        _mock_token()
        route = _mock_upload(agent_id)
        _mock_claim(agent_id)
        publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)
        old = set(_uploaded_packages(route, 0))

        result = drain_and_republish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        new = set(_uploaded_packages(route, 1))
        assert result.stored == KEY_PACKAGE_TARGET
        assert len(new) == KEY_PACKAGE_TARGET
        assert old.isdisjoint(new)
        assert open_mls_client(tmp_config_dir, agent_id).key_package_count() == KEY_PACKAGE_TARGET

    @respx.mock
    @pytest.mark.usefixtures("key_is_current")
    def test_drain_claims_the_stale_server_pool_out(self, sync_client, tmp_config_dir, agent_id):
        """The stale packages are claimed OUT of the server, not merely
        outnumbered locally. Otherwise a peer claims one, finds it unreadable, and
        the founder's group.create() fails — walking the pool one 409 at a time,
        which is exactly the shape the cutover forbids."""
        _mock_token()
        _mock_upload(agent_id)
        stale = [b"stale-old-framing-%d" % i for i in range(3)]
        claim = _mock_claim(agent_id, pages=[stale])

        result = drain_and_republish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)

        assert claim.called  # the drain must actually hit the destructive claim
        assert result.drained == len(stale)
        assert result.stored == KEY_PACKAGE_TARGET
        # And the claim must precede the upload — the server hands out oldest-first,
        # so publishing before draining would leave peers claiming stale packages.
        kp_calls = [c for c in respx.calls if c.request.url.path.endswith("/mls/key-packages")]
        assert kp_calls[0].request.method == "GET"


class TestEpochRetention:
    def test_unset_retains_the_full_backlog(self, monkeypatch):
        monkeypatch.delenv(EPOCH_RETENTION_ENV, raising=False)
        assert epoch_retention_limit() is None

    def test_a_positive_limit_is_read_back(self, monkeypatch):
        monkeypatch.setenv(EPOCH_RETENTION_ENV, "5")
        assert epoch_retention_limit() == 5

    @pytest.mark.parametrize("value", ["0", "-1", "lots"])
    def test_a_value_that_would_lose_the_backlog_is_refused(self, monkeypatch, value):
        monkeypatch.setenv(EPOCH_RETENTION_ENV, value)
        with pytest.raises(ConfigError):
            epoch_retention_limit()


#: The latch the server writes when an init commit lands. A create response is
#: minted before the init runs, so only the re-read can carry it.
MLS_LATCH = "mls-latch-abc"


def _mock_group_create(agent_id: str, *, enrollment: str = "closed") -> dict[str, respx.Route]:
    _mock_token()
    _mock_agents(agent_id)
    return {
        "create": respx.post(f"{API}/groups").mock(
            return_value=httpx.Response(
                201, json={**_GROUP_PAYLOAD, "enrollment_policy": enrollment}
            )
        ),
        "read": respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_GROUP_PAYLOAD,
                    "enrollment_policy": enrollment,
                    "mls_group_id": MLS_LATCH,
                },
            )
        ),
        "init": respx.post(f"{API}/groups/{GROUP_ID}/mls/init").mock(
            return_value=httpx.Response(
                200,
                json={
                    "mls_pending": True,
                    "members": [{"agent_id": agent_id, "has_key_package": True}],
                },
            )
        ),
        "commit": respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(200, json={"epoch": 1, "delivered_to": 0})
        ),
        "upload": _mock_upload(agent_id),
    }


class TestGroupCreate:
    @respx.mock
    def test_create_makes_a_post_quantum_mls_group(self, sync_client, tmp_config_dir, agent_id):
        routes = _mock_group_create(agent_id)

        group = sync_client.groups.create("test-group", visibility="private")

        # The default asks for nothing: MLS is the server's own default for a
        # closed group, and what proves the group is a post-quantum MLS one is
        # the founding below, not a flag echoing a default back at the server.
        assert "mls_enabled" not in json.loads(routes["create"].calls[0].request.content)
        assert routes["init"].call_count == 1
        commit = json.loads(routes["commit"].calls[0].request.content)
        assert commit["cipher_suite"] == DEFAULT_CIPHER_SUITE
        assert commit["epoch"] == 1
        assert base64.b64decode(commit["commit"], validate=True)
        assert base64.b64decode(commit["group_info"], validate=True)
        assert commit["welcomes"] == []
        assert str(group.id) == GROUP_ID

    @respx.mock
    def test_create_persists_mls_state_keyed_by_the_rine_group_id(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_group_create(agent_id)

        sync_client.groups.create("test-group", visibility="private")

        group_dir = os.path.join(
            mls_store_dir(tmp_config_dir, agent_id),
            "groups",
            GROUP_ID.replace("-", ""),
        )
        assert os.path.isfile(os.path.join(group_dir, "state.bin"))
        assert (
            open_mls_client(tmp_config_dir, agent_id)
            .load_group(bytes.fromhex(GROUP_ID.replace("-", "")))
            .epoch()
            == 1
        )

    @respx.mock
    def test_create_tops_up_the_key_package_pool_on_the_way(
        self, sync_client, tmp_config_dir, agent_id
    ):
        routes = _mock_group_create(agent_id)

        sync_client.groups.create("test-group", visibility="private")

        assert routes["upload"].call_count == 1

    @respx.mock
    def test_create_when_the_init_lands_returns_a_group_that_renders_as_mls(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """The create response predates the latch; only the re-read carries it."""
        routes = _mock_group_create(agent_id)

        group = sync_client.groups.create("test-group", visibility="private")

        assert routes["read"].call_count == 1
        assert group.mls_group_id == MLS_LATCH
        assert group_is_mls(group) is True

    @respx.mock
    async def test_async_create_when_the_init_lands_returns_a_group_that_renders_as_mls(
        self, async_client, tmp_config_dir, agent_id
    ):
        routes = _mock_group_create(agent_id)

        group = await async_client.groups.create("test-group", visibility="private")

        assert routes["read"].call_count == 1
        assert group_is_mls(group) is True
        await async_client.close()

    @respx.mock
    def test_open_enrollment_group_stays_on_sender_keys(self, sync_client, agent_id):
        routes = _mock_group_create(agent_id, enrollment="open")

        group = sync_client.groups.create("test-group", visibility="private", enrollment="open")

        assert routes["init"].call_count == 0
        # Nothing was founded, so there is nothing to re-read either.
        assert routes["read"].call_count == 0
        assert group_is_mls(group) is False

    @respx.mock
    def test_create_when_mls_init_fails_still_returns_the_group(
        self, sync_client, tmp_config_dir, agent_id, caplog
    ):
        """The group exists either way; a failed init is reported, never raised."""
        _mock_token()
        _mock_agents(agent_id)
        _mock_upload(agent_id)
        respx.post(f"{API}/groups").mock(return_value=httpx.Response(201, json=_GROUP_PAYLOAD))
        # No re-read mock: a failed init returns early (see `create_group`), so
        # the GET this test used to stub for the re-read is never reached.
        respx.post(f"{API}/groups/{GROUP_ID}/mls/init").mock(
            return_value=httpx.Response(403, json={"detail": "Only the designated admin"})
        )

        with caplog.at_level("WARNING"):
            group = sync_client.groups.create("test-group", visibility="private")

        assert str(group.id) == GROUP_ID
        assert any("MLS init failed" in r.message for r in caplog.records)

    @respx.mock
    async def test_async_create_founds_the_same_mls_group(
        self, async_client, tmp_config_dir, agent_id
    ):
        routes = _mock_group_create(agent_id)

        await async_client.groups.create("test-group", visibility="private")

        commit = json.loads(routes["commit"].calls[0].request.content)
        assert commit["cipher_suite"] == DEFAULT_CIPHER_SUITE
        assert commit["epoch"] == 1
        await async_client.close()


class TestAgentCreation:
    @respx.mock
    def test_a_new_agent_is_addable_to_groups_from_birth(self, sync_client):
        """Without a published pool the first invite fails 409 "No key packages"."""
        write_owner(resolve_owner_dir())
        _mock_token()
        created = respx.post(f"{API}/agents").mock(side_effect=echo_created_agent)
        route = respx.post(url__regex=rf"{API}/agents/[0-9a-f-]{{36}}/mls/key-packages").mock(
            return_value=httpx.Response(201, json={"stored": KEY_PACKAGE_TARGET})
        )

        sync_client.create_agent("fresh")

        new_agent_id = json.loads(created.calls.last.request.content)["id"]
        assert route.calls.last.request.url.path == f"/agents/{new_agent_id}/mls/key-packages"
        assert len(_uploaded_packages(route)) == KEY_PACKAGE_TARGET


class TestCutover:
    """An agent upgrading from the previous MLS core republishes its pool."""

    @respx.mock
    @pytest.mark.usefixtures("key_is_current")
    def test_client_republish_replaces_the_pool(self, sync_client, tmp_config_dir, agent_id):
        _mock_token()
        route = _mock_upload(agent_id)
        _mock_claim(agent_id)
        publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)
        old = set(_uploaded_packages(route, 0))

        result = sync_client.republish_mls_key_packages(agent_id)

        assert result.stored == KEY_PACKAGE_TARGET
        assert old.isdisjoint(set(_uploaded_packages(route, 1)))

    @respx.mock
    @pytest.mark.usefixtures("key_is_current")
    async def test_async_client_republish_replaces_the_pool(
        self, async_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        route = _mock_upload(agent_id)
        _mock_claim(agent_id)

        result = await async_client.republish_mls_key_packages(agent_id)

        assert result.stored == KEY_PACKAGE_TARGET
        assert len(_uploaded_packages(route, 0)) == KEY_PACKAGE_TARGET
        await async_client.close()
