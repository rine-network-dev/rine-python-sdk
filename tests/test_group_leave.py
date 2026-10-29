"""Leaving a group takes this agent's local MLS state with it.

These drive the real ``rine-mls`` core — only the server is mocked — so the
assertion is that the state is really gone from the store, not that a mock was
called. A departing member that kept its epoch secrets could still read group
traffic until an admin's next membership change lands the eviction; rine's own
clients retire the state on the way out instead.
"""

from __future__ import annotations

import os

import httpx
import pytest
import respx

from rine._config import mls_store_dir
from rine._mls import open_mls_client
from rine._mls.group_access import load_mls_group
from rine.errors import AuthorizationError

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

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


def _mock_server(agent_id: str) -> dict[str, respx.Route]:
    """Everything ``create`` then ``remove_member`` touches, with a landing init."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
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
    respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(200, json={"stored": 10})
    )
    respx.get(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(200, json={"count": 0})
    )
    respx.post(f"{API}/groups").mock(return_value=httpx.Response(201, json=_GROUP_PAYLOAD))
    # ``remove_member`` names its group by id, and the resolve matches
    # that id against the org's own roster before the delete — an id no group of
    # this org carries is refused with the list rather than reaching the wire.
    respx.get(f"{API}/groups").mock(
        return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
    )
    respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json={**_GROUP_PAYLOAD, "mls_group_id": "mls-latch"})
    )
    respx.post(f"{API}/groups/{GROUP_ID}/mls/init").mock(
        return_value=httpx.Response(
            200,
            json={
                "mls_pending": True,
                "members": [{"agent_id": agent_id, "has_key_package": True}],
            },
        )
    )
    respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
        return_value=httpx.Response(200, json={"epoch": 1, "delivered_to": 0})
    )
    return {
        "remove_self": respx.delete(f"{API}/groups/{GROUP_ID}/members/{agent_id}").mock(
            return_value=httpx.Response(204)
        ),
        "remove_other": respx.delete(f"{API}/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(204)
        ),
    }


def _has_local_state(config_dir: str, agent_id: str) -> bool:
    return load_mls_group(open_mls_client(config_dir, agent_id), GROUP_ID) is not None


def _group_dir(config_dir: str, agent_id: str) -> str:
    return os.path.join(mls_store_dir(config_dir, agent_id), "groups", GROUP_ID.replace("-", ""))


class TestLeaveWipesLocalMlsState:
    """A leave takes this agent's local keys for the group with it."""

    @respx.mock
    def test_remove_member_when_removing_self_retires_the_group_state(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")
        assert _has_local_state(tmp_config_dir, agent_id)

        sync_client.groups.remove_member(GROUP_ID, agent_id)

        assert _has_local_state(tmp_config_dir, agent_id) is False
        assert not os.path.exists(_group_dir(tmp_config_dir, agent_id))

    @respx.mock
    def test_remove_member_when_removing_self_settles_the_escrow_before_the_server_removal(
        self, sync_client, tmp_config_dir, agent_id, escrow_calls
    ):
        """The wipe discards deferred exports, so they are sealed while the leaver is a member."""
        routes = _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")

        def removal(request):
            escrow_calls.append(("remove", GROUP_ID))
            return httpx.Response(204)

        routes["remove_self"].mock(side_effect=removal)

        sync_client.groups.remove_member(GROUP_ID, agent_id)

        assert escrow_calls == [("settle", GROUP_ID), ("remove", GROUP_ID)]

    @respx.mock
    def test_remove_member_when_removing_someone_else_settles_nothing(
        self, sync_client, tmp_config_dir, agent_id, escrow_calls
    ):
        """A kick wipes nothing of this agent's, so there is nothing to settle."""
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")

        sync_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

        assert escrow_calls == []

    @respx.mock
    def test_leaving_an_mls_group_reports_the_mls_wipe_it_actually_did(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """The sentence is chosen by what was retired, not guessed."""
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")

        result = sync_client.groups.remove_member(GROUP_ID, agent_id)

        assert result.left is True
        assert result.encryption == "mls"
        assert result.local_state_retired is True
        assert result.mls_removal_epoch is None
        assert "epoch secret" in result.message
        # Accepted and stated, not softened.
        assert "including the ones that arrived before you left" in result.message

    @respx.mock
    def test_leaving_a_group_this_agent_held_nothing_for_reports_no_wipe(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """A member whose Welcome was never installed had nothing to retire."""
        _mock_server(agent_id)

        result = sync_client.groups.remove_member(GROUP_ID, agent_id)

        assert result.left is True
        assert result.encryption is None
        assert result.local_state_retired is False
        assert "nothing to retire" in result.message

    @respx.mock
    def test_remove_member_when_removing_someone_else_keeps_the_group_state(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")

        sync_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

        assert _has_local_state(tmp_config_dir, agent_id)

    @respx.mock
    def test_remove_member_when_the_server_refuses_keeps_the_group_state(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """Server first: a refused leave never leaves a member without its keys."""
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")
        respx.delete(f"{API}/groups/{GROUP_ID}/members/{agent_id}").mock(
            return_value=httpx.Response(403, json={"detail": "not a member"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.remove_member(GROUP_ID, agent_id)

        assert _has_local_state(tmp_config_dir, agent_id)

    @respx.mock
    async def test_async_remove_member_when_removing_self_retires_the_group_state(
        self, async_client, tmp_config_dir, agent_id, escrow_calls
    ):
        _mock_server(agent_id)
        await async_client.groups.create("test-group", visibility="private")
        assert _has_local_state(tmp_config_dir, agent_id)

        await async_client.groups.remove_member(GROUP_ID, agent_id)

        assert _has_local_state(tmp_config_dir, agent_id) is False
        assert escrow_calls == [("settle", GROUP_ID)]
        await async_client.close()


class TestLeaveVerb:
    """``leave()`` — a departure under its own name, and the header that makes it one.

    The server tells a leave from a kick by the acting agent alone and fails
    closed, so a DELETE with no ``X-Rine-Agent`` from a client that has not
    resolved its agent yet is read as a KICK — which an MLS group refuses until
    a Remove commit is posted that nobody can mint for their own removal. That
    is why ``leave()`` resolves the actor before the removal runs, and why the
    header is asserted here rather than assumed.
    """

    @respx.mock
    def test_leave_when_the_client_has_not_resolved_yet_then_still_names_the_agent(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """The header is what tells the server this is a leave and not a kick."""
        routes = _mock_server(agent_id)

        sync_client.groups.leave(GROUP_ID)

        assert routes["remove_self"].called
        request = routes["remove_self"].calls[0].request
        assert request.headers.get("X-Rine-Agent") == agent_id

    @respx.mock
    def test_leave_when_called_then_retires_local_state_and_reports_the_departure(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """Same removal path underneath, so the wipe still happens."""
        _mock_server(agent_id)
        sync_client.groups.create("test-group", visibility="private")
        assert _has_local_state(tmp_config_dir, agent_id)

        result = sync_client.groups.leave(GROUP_ID)

        assert result.left is True
        assert result.local_state_retired is True
        # No Remove commit: MLS gives nobody a way to commit their own removal,
        # so the leaf stays in the tree until a member reclaims it.
        assert result.mls_removal_epoch is None
        assert _has_local_state(tmp_config_dir, agent_id) is False

    @respx.mock
    def test_leave_when_the_acting_agent_is_ambiguous_then_refuses_to_kick(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """An unattributable leave IS a kick to the server, so it is refused here."""
        routes = _mock_server(agent_id)
        respx.get(f"{API}/agents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": agent_id,
                            "name": "one",
                            "handle": "one@myorg.rine.network",
                            "human_oversight": True,
                            "incoming_policy": "accept_all",
                            "outgoing_policy": "send_all",
                            "created_at": "2024-01-01T00:00:00Z",
                        },
                        {
                            "id": OTHER_AGENT_ID,
                            "name": "two",
                            "handle": "two@myorg.rine.network",
                            "human_oversight": True,
                            "incoming_policy": "accept_all",
                            "outgoing_policy": "send_all",
                            "created_at": "2024-01-01T00:00:00Z",
                        },
                    ]
                },
            )
        )

        with pytest.raises(Exception, match="(?i)agent"):
            sync_client.groups.leave(GROUP_ID)

        assert not routes["remove_self"].called
        assert not routes["remove_other"].called

    @respx.mock
    async def test_async_leave_when_called_then_retires_state_and_names_the_agent(
        self, async_client, tmp_config_dir, agent_id
    ):
        """The twin: a verb on one client and not the other is not a verb."""
        routes = _mock_server(agent_id)
        await async_client.groups.create("test-group", visibility="private")
        assert _has_local_state(tmp_config_dir, agent_id)

        result = await async_client.groups.leave(GROUP_ID)

        assert result.left is True
        assert _has_local_state(tmp_config_dir, agent_id) is False
        assert routes["remove_self"].calls[0].request.headers.get("X-Rine-Agent") == agent_id
        await async_client.close()
