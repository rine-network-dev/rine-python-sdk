"""Tests for sender key orchestration — get_or_create and distribute."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._constants import EncryptionVersion, MessageType
from rine._crypto.keys import make_kid, save_agent_keys
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._group_send import resolve_group_for_send
from rine._http import SyncHttpClient
from rine._sender_key_ops import distribute_sender_key_sync, get_or_create_sender_key_sync
from rine._crypto.sender_keys_helpers import load_sender_key_states
from rine.errors import SENDER_KEY_UNDELIVERED_CODE, NotFoundError, SenderKeyUndeliveredError
from rine.sender_key_words import SENDER_KEY_UNDELIVERED_REFUSAL
from rine.testing import WORLD, write_agent_identity

AGENT_ID = "00000000-1111-2222-3333-444444444444"
MEMBER_ID_1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MEMBER_ID_2 = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#my-group@myorg.rine.network"
#: A resolved group on Sender Keys, as ``rine._group_send`` hands it over.
_GROUP = {"id": GROUP_ID, "handle": GROUP_HANDLE, "mls_group_id": None, "mls_pending": False}

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}


def _make_http_client(tmp_config_dir: str) -> SyncHttpClient:
    write_agent_identity(tmp_config_dir, AGENT_ID)
    return SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")


def _seat_member(config_dir: str, agent_id: str) -> None:
    """Save a member's derived keys to disk, so its published body is chain-valid."""
    save_agent_keys(config_dir, agent_id, WORLD.keys(agent_id))


def _distribution_response(to_agent_id: str) -> dict[str, str]:
    """A posted distribution DM, as the server echoes it back."""
    return {
        "id": "dddddddd-eeee-ffff-0000-111111111111",
        "conversation_id": "dddddddd-eeee-ffff-0000-111111111112",
        "from_agent_id": AGENT_ID,
        "to_agent_id": to_agent_id,
        "type": MessageType.SENDER_KEY_DISTRIBUTION,
        "encrypted_payload": "abc",
        "encryption_version": EncryptionVersion.HPKE_HYBRID_V2,
        "sender_signing_kid": make_kid(AGENT_ID, 0),
        "created_at": "2024-01-01T00:00:00Z",
    }


class TestGetOrCreateSenderKeySync:
    @respx.mock
    def test_creates_new_key_when_no_state_exists(self, tmp_config_dir, saved_agent_keys):
        """When no sender key state exists, a new key is generated and distributed."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        # Group resolve
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200, json={"items": [{"id": GROUP_ID, "handle": GROUP_HANDLE}]}
            )
        )

        # Members
        _seat_member(tmp_config_dir, MEMBER_ID_1)
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {"agent_id": MEMBER_ID_1, "role": "member"},
                    ]
                },
            )
        )

        # Recipient keys fetch for distribution
        respx.get(f"https://rine.network/agents/{MEMBER_ID_1}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(MEMBER_ID_1))
        )

        # Message post for distribution
        respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json=_distribution_response(MEMBER_ID_1))
        )

        http = _make_http_client(tmp_config_dir)
        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        assert isinstance(state, SenderKeyState)
        assert state.sender_agent_id == AGENT_ID
        assert len(state.chain_key) == 32

    @respx.mock
    def test_raises_not_found_when_group_missing(self, tmp_config_dir, saved_agent_keys):
        """A send to a handle no group carries is refused before any crypto runs.

        The handle lookup belongs to the send dispatcher now — it is what decides
        MLS vs Sender Keys — so this asserts it there.
        """
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        http = _make_http_client(tmp_config_dir)
        with pytest.raises(NotFoundError, match="Group not found"):
            resolve_group_for_send(http, "#nonexistent-group@org.rine.network")
        http.close()

    @respx.mock
    def test_returns_existing_key_when_valid(self, tmp_config_dir, saved_agent_keys):
        """A valid, non-rotated sender key is returned without generating a new one."""
        import time

        from rine._crypto.sender_keys_helpers import save_sender_key_state

        # Pre-populate state
        existing_state = generate_sender_key(GROUP_ID, AGENT_ID)
        existing_state.distributed_to = [MEMBER_ID_1]
        existing_state.created_at = int(time.time() * 1000)
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [existing_state])

        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200, json={"items": [{"id": GROUP_ID, "handle": GROUP_HANDLE}]}
            )
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200, json={"items": [{"agent_id": MEMBER_ID_1, "role": "member"}]}
            )
        )

        http = _make_http_client(tmp_config_dir)
        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        assert state.sender_key_id == existing_state.sender_key_id


MEMBER_ID_3 = "11111111-2222-3333-4444-555555555555"


def _serve_group(config_dir: str, members: list[str], refused: list[str]) -> None:
    """Mock the server for a send: the roster, every member's keys, and the DM POST.

    A distribution DM addressed to an id in ``refused`` answers 503, so that member
    is reported as not reached; every other one is accepted.
    """
    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )
    respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(
            200, json={"items": [{"agent_id": m, "role": "member"} for m in members]}
        )
    )
    for member in members:
        _seat_member(config_dir, member)
        respx.get(f"https://rine.network/agents/{member}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(member))
        )

    def post(request: httpx.Request) -> httpx.Response:
        to_agent = json.loads(request.content)["to_agent_id"]
        if to_agent in refused:
            return httpx.Response(503, json={"detail": "unavailable"})
        return httpx.Response(200, json=_distribution_response(to_agent))

    respx.post("https://rine.network/messages").mock(side_effect=post)


class TestSenderKeyUndelivered:
    """A post no other member could open is refused before anything is saved."""

    @respx.mock
    def test_send_when_every_first_distribution_fails_then_it_refuses_and_saves_nothing(
        self, tmp_config_dir, saved_agent_keys
    ):
        members = [MEMBER_ID_1, MEMBER_ID_2]
        _serve_group(tmp_config_dir, members, refused=members)
        http = _make_http_client(tmp_config_dir)

        with pytest.raises(SenderKeyUndeliveredError) as refused:
            get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)

        assert str(refused.value) == SENDER_KEY_UNDELIVERED_REFUSAL
        assert refused.value.code == SENDER_KEY_UNDELIVERED_CODE
        assert refused.value.group_id == GROUP_ID
        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID) == []

        respx.reset()
        _serve_group(tmp_config_dir, members, refused=[])
        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()
        assert state.message_index == 0
        assert sorted(state.distributed_to) == sorted(members)
        assert len(load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)) == 1

    @respx.mock
    def test_send_when_every_rotation_distribution_fails_then_it_refuses_and_the_old_key_stays(
        self, tmp_config_dir, saved_agent_keys
    ):
        _serve_group(tmp_config_dir, [MEMBER_ID_1, MEMBER_ID_2], refused=[])
        http = _make_http_client(tmp_config_dir)
        original = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)

        respx.reset()
        _serve_group(tmp_config_dir, [MEMBER_ID_1], refused=[MEMBER_ID_1])
        with pytest.raises(SenderKeyUndeliveredError):
            get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        saved = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert [s.sender_key_id for s in saved] == [original.sender_key_id]
        addressed = {
            json.loads(c.request.content)["to_agent_id"]
            for c in respx.calls
            if c.request.url.path == "/messages"
        }
        assert MEMBER_ID_2 not in addressed

    @respx.mock
    def test_send_when_a_topup_has_a_holder_and_the_newcomer_fails_then_it_sends(
        self, tmp_config_dir, saved_agent_keys
    ):
        _serve_group(tmp_config_dir, [MEMBER_ID_1], refused=[])
        http = _make_http_client(tmp_config_dir)
        original = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)

        respx.reset()
        _serve_group(tmp_config_dir, [MEMBER_ID_1, MEMBER_ID_2], refused=[MEMBER_ID_2])
        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        assert state.sender_key_id == original.sender_key_id
        assert state.distributed_to == [MEMBER_ID_1]

    @respx.mock
    def test_send_when_a_topup_has_no_holder_and_the_newcomers_fail_then_it_refuses(
        self, tmp_config_dir, saved_agent_keys
    ):
        _serve_group(tmp_config_dir, [], refused=[])
        http = _make_http_client(tmp_config_dir)
        get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)

        respx.reset()
        members = [MEMBER_ID_1, MEMBER_ID_2]
        _serve_group(tmp_config_dir, members, refused=members)
        with pytest.raises(SenderKeyUndeliveredError):
            get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

    @respx.mock
    def test_send_when_one_of_three_distributions_succeeds_then_it_sends(
        self, tmp_config_dir, saved_agent_keys
    ):
        members = [MEMBER_ID_1, MEMBER_ID_2, MEMBER_ID_3]
        _serve_group(tmp_config_dir, members, refused=[MEMBER_ID_1, MEMBER_ID_2])
        http = _make_http_client(tmp_config_dir)

        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        assert state.distributed_to == [MEMBER_ID_3]

    @respx.mock
    def test_send_when_the_group_has_no_other_member_then_it_sends(
        self, tmp_config_dir, saved_agent_keys
    ):
        _serve_group(tmp_config_dir, [], refused=[])
        http = _make_http_client(tmp_config_dir)

        state = get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, _GROUP)
        http.close()

        assert state.distributed_to == []


class TestDistributeSenderKeySync:
    @respx.mock
    def test_distributes_to_multiple_recipients(self, tmp_config_dir, saved_agent_keys):
        """distribute_sender_key_sync sends a message to each recipient."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        for member_id in (MEMBER_ID_1, MEMBER_ID_2):
            _seat_member(tmp_config_dir, member_id)
            respx.get(f"https://rine.network/agents/{member_id}/keys").mock(
                return_value=httpx.Response(200, json=WORLD.keys_response(member_id))
            )

        msg_route = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json=_distribution_response(MEMBER_ID_1))
        )

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        http = _make_http_client(tmp_config_dir)
        succeeded, failed = distribute_sender_key_sync(
            http,
            tmp_config_dir,
            AGENT_ID,
            state,
            GROUP_ID,
            [MEMBER_ID_1, MEMBER_ID_2],
        )
        http.close()

        assert len(succeeded) == 2
        assert MEMBER_ID_1 in succeeded
        assert MEMBER_ID_2 in succeeded
        assert failed == []
        assert msg_route.call_count == 2
        # Names the sending agent: a multi-agent org has no default sender, and
        # the server rejects the distribution DM without it.
        assert all(c.request.headers["X-Rine-Agent"] == AGENT_ID for c in msg_route.calls)

    @respx.mock
    def test_distribution_carries_the_senders_own_copy(self, tmp_config_dir, saved_agent_keys):
        """The posted body carries a self-encrypted copy, distinct from the recipient's.

        Without it the org's reader cannot open an own agent's open-group posts:
        a sender never distributes its key to itself, so the first distribution
        the org sent is unreadable to it and no recovery path can re-ingest it.
        """
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _seat_member(tmp_config_dir, MEMBER_ID_1)
        respx.get(f"https://rine.network/agents/{MEMBER_ID_1}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(MEMBER_ID_1))
        )
        msg_route = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json=_distribution_response(MEMBER_ID_1))
        )

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        http = _make_http_client(tmp_config_dir)
        distribute_sender_key_sync(http, tmp_config_dir, AGENT_ID, state, GROUP_ID, [MEMBER_ID_1])
        http.close()

        body = json.loads(msg_route.calls[0].request.content)
        assert body["self_encrypted_payload"]
        assert body["self_encrypted_payload"] != body["encrypted_payload"]

    @respx.mock
    def test_records_failed_recipients(self, tmp_config_dir, saved_agent_keys):
        """distribute_sender_key_sync records failures without raising."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        # First member: key fetch returns 404
        respx.get(f"https://rine.network/agents/{MEMBER_ID_1}/keys").mock(
            return_value=httpx.Response(404, json={"detail": "not found"})
        )

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        http = _make_http_client(tmp_config_dir)
        succeeded, failed = distribute_sender_key_sync(
            http,
            tmp_config_dir,
            AGENT_ID,
            state,
            GROUP_ID,
            [MEMBER_ID_1],
        )
        http.close()

        assert MEMBER_ID_1 in failed
        assert succeeded == []
