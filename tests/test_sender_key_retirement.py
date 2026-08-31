"""A retired sender key stays retired.

The wipe :func:`rine._sender_key_ops.delete_sender_key` performs was
point-in-time: every peer key it removed still sat in the departed agent's inbox
as a ``rine.v1.sender_key_distribution`` DM, and the next group read that missed
its key put all of them back. These pin the marker that closes it — the unit
half here, and the end-to-end half through the real self-heal path both clients
run.
"""

from __future__ import annotations

import os

import httpx
import pytest
import respx

from rine._crypto.sender_keys import generate_sender_key
from rine._crypto.sender_keys_helpers import (
    load_sender_key_states,
    mark_sender_keys_retired,
    save_sender_key_state,
    sender_keys_retired,
    unretire_sender_keys,
)
from rine._sender_key_ops import delete_sender_key

AGENT_ID = "00000000-1111-2222-3333-444444444444"
PEER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_GROUP_ID = "dddddddd-eeee-ffff-0000-111111111111"


class TestRetirementMarker:
    def test_delete_when_the_group_held_material_then_it_is_retired(self, tmp_config_dir):
        save_sender_key_state(
            tmp_config_dir, AGENT_ID, GROUP_ID, [generate_sender_key(GROUP_ID, PEER_ID)]
        )

        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is True

    def test_delete_when_the_group_held_nothing_then_it_is_still_retired(self, tmp_config_dir):
        # A distribution DM this agent never opened is material the wipe never
        # saw, and it is in the same inbox — so the marker cannot be conditional
        # on there having been something on disk.
        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is True

    def test_delete_when_the_process_restarts_then_the_refusal_survives(self, tmp_config_dir):
        # The marker is a file, not memory: nothing holds the retirement in
        # process state, so a fresh client on the same config dir agrees.
        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert os.path.exists(
            os.path.join(
                tmp_config_dir, "keys", AGENT_ID, "sender_keys", f"{GROUP_ID}.retired.json"
            )
        )

    def test_delete_when_the_group_id_is_upper_cased_then_the_marker_still_matches(
        self, tmp_config_dir
    ):
        # Marker and reader have to agree on one spelling: the ingest path takes
        # the group id from the distribution payload, which is the server's
        # lower-case spelling, and never normalises it.
        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID.upper())

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is True

    def test_delete_when_one_group_is_retired_then_another_is_not(self, tmp_config_dir):
        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, OTHER_GROUP_ID) is False

    def test_unretire_when_lifted_then_the_group_is_live_again(self, tmp_config_dir):
        mark_sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID)

        unretire_sender_keys(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is False

    def test_unretire_when_nothing_was_retired_then_it_is_not_an_error(self, tmp_config_dir):
        unretire_sender_keys(tmp_config_dir, AGENT_ID, GROUP_ID)


def _mock_group_for_send(config_dir: str, member_ids: list[str]) -> None:
    """Register the reads ``get_or_create_sender_key_sync`` makes for one group."""
    import httpx

    from rine._crypto.keys import (
        encryption_public_key_to_jwk,
        generate_agent_keys,
        save_agent_keys,
        signing_public_key_to_jwk,
    )

    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(
            200, json={"items": [{"agent_id": mid, "role": "member"} for mid in member_ids]}
        )
    )
    for mid in member_ids:
        keys = generate_agent_keys()
        save_agent_keys(config_dir, mid, keys)
        respx.get(f"https://rine.network/agents/{mid}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": mid,
                    "encryption_public_key": encryption_public_key_to_jwk(
                        keys.encryption.public_key
                    ),
                    "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
                },
            )
        )
    respx.post("https://rine.network/messages").mock(
        return_value=httpx.Response(200, json={"id": "ignored"})
    )


class TestRejoiningLiftsTheRetirement:
    """A re-admitted member has to be able to take its new peers' keys again."""

    @respx.mock
    def test_send_when_the_server_names_this_agent_a_member_then_the_retirement_is_lifted(
        self, tmp_config_dir, saved_agent_keys
    ):
        from rine._config import save_credentials
        from rine._http import SyncHttpClient
        from rine._sender_key_ops import get_or_create_sender_key_sync

        save_credentials(tmp_config_dir, {"default": {"client_id": "c", "client_secret": "s"}})
        _mock_group_for_send(tmp_config_dir, [AGENT_ID, PEER_ID])
        mark_sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID)

        http = SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")
        get_or_create_sender_key_sync(
            http, tmp_config_dir, AGENT_ID, {"id": GROUP_ID, "handle": "#g@o.rine.network"}
        )
        http.close()

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is False

    @respx.mock
    def test_send_when_this_agent_is_not_on_the_member_list_then_the_retirement_stands(
        self, tmp_config_dir, saved_agent_keys
    ):
        # The membership test is what keeps the retirement permanent for the
        # agent it exists for: a departed agent attempting a send must not lift
        # its own marker on the way to being refused by the server.
        from rine._config import save_credentials
        from rine._http import SyncHttpClient
        from rine._sender_key_ops import get_or_create_sender_key_sync

        save_credentials(tmp_config_dir, {"default": {"client_id": "c", "client_secret": "s"}})
        _mock_group_for_send(tmp_config_dir, [PEER_ID])
        mark_sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID)

        http = SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")
        get_or_create_sender_key_sync(
            http, tmp_config_dir, AGENT_ID, {"id": GROUP_ID, "handle": "#g@o.rine.network"}
        )
        http.close()

        assert sender_keys_retired(tmp_config_dir, AGENT_ID, GROUP_ID) is True


class TestRetiredGroupRefusesSelfHeal:
    """The end-to-end half: the client's own recovery path stops restoring."""

    @respx.mock
    def test_sync_inbox_when_the_group_was_retired_then_the_pending_key_is_refused(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        mock_group_message_routes()
        mark_sender_keys_retired(tmp_config_dir, agent_id, group_message_fixture.group_id)

        page = sync_client.inbox()

        msg = page.items[0]
        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert (
            load_sender_key_states(tmp_config_dir, agent_id, group_message_fixture.group_id) == []
        )

    @respx.mock
    def test_sync_inbox_when_the_group_was_retired_then_the_error_says_how_to_get_back_in(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        """🔴 This is where an operator meets the refusal: ``msg.decrypt_error``.

        By the time the sentence is read, the client has already ingested every
        pending distribution the server holds and been refused by this agent's
        own retirement marker — so the old remedy, "fetch pending sender key
        distributions first", named the exact call that had just happened. What
        it has to say instead is the cause and a way out.
        """
        mock_group_message_routes()
        mark_sender_keys_retired(tmp_config_dir, agent_id, group_message_fixture.group_id)

        page = sync_client.inbox()

        error = page.items[0].decrypt_error or ""
        assert "holds no sender key state" in error
        assert "rejoin it" in error
        assert "no message key was consumed" in error
        assert "Fetch pending" not in error

    @respx.mock
    def test_sync_inbox_when_the_agent_is_a_member_again_then_the_retirement_lifts(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        """🔴 The marker is spent by MEMBERSHIP, never by sending.

        Lifted only inside ``get_or_create_sender_key_sync`` — reachable from a
        group send and from nothing else — a re-admitted agent that reads before
        it sends, and a read-only member that never sends at all, refused every
        distribution its new peers made it, forever.
        """
        mock_group_message_routes()
        gid = group_message_fixture.group_id
        mark_sender_keys_retired(tmp_config_dir, agent_id, gid)
        respx.get(f"https://rine.network/groups/{gid}/members").mock(
            return_value=httpx.Response(200, json={"items": [{"agent_id": agent_id}]})
        )

        page = sync_client.inbox()

        assert page.items[0].plaintext == group_message_fixture.plaintext
        assert sender_keys_retired(tmp_config_dir, agent_id, gid) is False

    @respx.mock
    def test_sync_inbox_when_membership_says_no_then_the_retirement_holds(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        mock_group_message_routes()
        gid = group_message_fixture.group_id
        mark_sender_keys_retired(tmp_config_dir, agent_id, gid)
        # A departed agent: the server names somebody else, and nothing this
        # client does locally may un-retire the material it left with.
        respx.get(f"https://rine.network/groups/{gid}/members").mock(
            return_value=httpx.Response(200, json={"items": [{"agent_id": PEER_ID}]})
        )

        page = sync_client.inbox()

        assert page.items[0].plaintext is None
        assert sender_keys_retired(tmp_config_dir, agent_id, gid) is True
        assert load_sender_key_states(tmp_config_dir, agent_id, gid) == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_inbox_when_the_agent_is_a_member_again_then_the_retirement_lifts(
        self,
        async_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        # Parity is not optional: the two clients carry separate copies of the
        # self-heal path, so a lift honoured by one and not the other wedges a
        # re-admitted agent on exactly one surface.
        mock_group_message_routes()
        gid = group_message_fixture.group_id
        mark_sender_keys_retired(tmp_config_dir, agent_id, gid)
        respx.get(f"https://rine.network/groups/{gid}/members").mock(
            return_value=httpx.Response(200, json={"items": [{"agent_id": agent_id}]})
        )

        page = await async_client.inbox()

        assert page.items[0].plaintext == group_message_fixture.plaintext
        assert sender_keys_retired(tmp_config_dir, agent_id, gid) is False
        await async_client.close()

    @respx.mock
    def test_sync_inbox_when_the_group_is_live_then_the_pending_key_is_ingested(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        # The control for the test above: same fixture, same routes, no marker.
        mock_group_message_routes()

        page = sync_client.inbox()

        assert page.items[0].plaintext == group_message_fixture.plaintext
        assert load_sender_key_states(tmp_config_dir, agent_id, group_message_fixture.group_id)

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_inbox_when_the_group_was_retired_then_the_pending_key_is_refused(
        self,
        async_client,
        tmp_config_dir,
        agent_id,
        group_message_fixture,
        mock_group_message_routes,
    ):
        # Parity is not optional: the async and sync clients carry separate
        # copies of the ingest loop, so a marker honoured by one and not the
        # other retires on one surface and un-retires on another.
        mock_group_message_routes()
        mark_sender_keys_retired(tmp_config_dir, agent_id, group_message_fixture.group_id)

        page = await async_client.inbox()

        msg = page.items[0]
        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        await async_client.close()
