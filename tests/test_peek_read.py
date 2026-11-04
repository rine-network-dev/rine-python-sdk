"""``read()`` peeks always, and marks the row delivered only once it is settled.

The server cannot tell whether a row opened: it holds no key, and a plain GET marks the
row before this client has tried. So ``read()`` always sends ``X-Rine-Peek`` and marks
the row itself, through ``mark_delivered``, when it opened, carried no ciphertext or was
refused for its sender's signature. A row it could not open stays ``new``. ``peek=True``
suppresses the mark too.

Every test here exists in a sync/async pair, deliberately: the two clients are
independent hand-kept copies, so a kwarg added to one is not added to the other,
and a header spelled two ways is this package's most-paid-for defect class. The
pairs sit next to each other rather than in two files for the reason
``test_mls_messages`` gives for the same shape — a missing twin is visible.
"""

from __future__ import annotations

import inspect
import json
import logging

import httpx
import pytest
import respx

from rine import RineClient, SyncRineClient
from rine._actor import AGENT_HEADER
from rine._constants import PEEK_HEADER, EncryptionVersion, MessageType
from rine._crypto.keys import load_agent_keys, make_kid, save_agent_keys
from rine._crypto.message import encrypt_message
from rine.testing import WORLD
from tests.conftest import recipient_view

API = "https://rine.network"
MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000201"
CONVERSATION_ID = "cccccccc-dddd-eeee-ffff-000000000202"
TYPE = "rine.v1.task_request"


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "test-token", "expires_in": 900})
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


def _row(sender_id: str, agent_id: str, *, payload: str, version: str, kid: str | None) -> dict:
    return {
        "id": MESSAGE_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": sender_id,
        "to_agent_id": agent_id,
        "type": TYPE,
        "encrypted_payload": payload,
        "encryption_version": version,
        "sender_signing_kid": kid,
        "created_at": "2024-01-01T00:00:00Z",
    }


def _mock_readable_dm(
    tmp_config_dir: str, agent_id: str, sender_id: str, payload: dict
) -> respx.Route:
    """One openable 1:1 row on ``GET /messages/{id}``, sealed to this agent.

    Sealed with :func:`encrypt_message` rather than hand-built, so the kwarg is
    exercised against a row that really decrypts — a wire-only test would pass
    on a client that sent the header and then dropped the plaintext.
    """
    save_agent_keys(tmp_config_dir, sender_id, WORLD.keys(sender_id))
    recipient = recipient_view(load_agent_keys(tmp_config_dir, agent_id), agent_id)
    sealed = encrypt_message(tmp_config_dir, sender_id, recipient, payload)

    respx.get(f"{API}/agents/{sender_id}/keys").mock(
        return_value=httpx.Response(200, json=WORLD.keys_response(sender_id))
    )
    return respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json=_row(
                sender_id,
                agent_id,
                payload=sealed.encrypted_payload,
                version=sealed.encryption_version,
                kid=sealed.sender_signing_kid,
            ),
        )
    )


def _mock_unopenable_dm(sender_id: str, agent_id: str) -> respx.Route:
    """A 1:1 row whose envelope is not an envelope: it degrades, never raises."""
    return respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json=_row(
                sender_id,
                agent_id,
                payload="bm90LWFuLWVudmVsb3Bl",
                version=EncryptionVersion.HPKE_HYBRID_V2,
                kid=make_kid(sender_id, 0),
            ),
        )
    )


def _mock_mark(agent_id: str, status: int = 200) -> respx.Route:
    return respx.post(f"{API}/agents/{agent_id}/messages/mark-delivered").mock(
        return_value=httpx.Response(status, json={"marked": 1})
    )


def _marked_ids(route: respx.Route) -> list[list[str]]:
    return [json.loads(call.request.content)["message_ids"] for call in route.calls]


def _assert_traceback_only_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    """A mark failure warns in one line; its traceback is on the debug record only."""
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    debugs = [r for r in caplog.records if r.levelno == logging.DEBUG and r.exc_info]
    assert any("could not mark it delivered" in r.getMessage() for r in warnings)
    assert all(r.exc_info is None for r in warnings)
    assert debugs


class TestReadPeeksAlwaysAndMarksWhatOpened:
    """The GET never marks; the client marks once the row is settled."""

    @respx.mock
    def test_an_opened_row_is_peeked_then_marked_once_for_the_resolved_agent(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        get = _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext == '{"text":"hi"}'
        assert get.calls[0].request.headers[PEEK_HEADER] == "1"
        assert get.calls[0].request.headers[AGENT_HEADER] == agent_id
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    async def test_an_opened_row_is_peeked_then_marked_once_for_the_resolved_agent_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        get = _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.plaintext == '{"text":"hi"}'
        assert get.calls[0].request.headers[PEEK_HEADER] == "1"
        assert get.calls[0].request.headers[AGENT_HEADER] == agent_id
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    def test_an_unopenable_row_is_peeked_and_left_new(self, sync_client, agent_id, other_agent_id):
        _mock_token()
        _mock_agents(agent_id)
        get = _mock_unopenable_dm(other_agent_id, agent_id)
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert get.calls[0].request.headers[PEEK_HEADER] == "1"
        assert get.call_count == 1
        assert mark.call_count == 0

    @respx.mock
    async def test_an_unopenable_row_is_peeked_and_left_new_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        get = _mock_unopenable_dm(other_agent_id, agent_id)
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert get.calls[0].request.headers[PEEK_HEADER] == "1"
        assert get.call_count == 1
        assert mark.call_count == 0

    @respx.mock
    def test_a_row_this_agent_holds_no_keys_for_is_left_new(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        keyless = "dddddddd-eeee-ffff-0000-111111111111"
        _mock_token()
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(keyless)

        msg = sync_client.read(MESSAGE_ID, agent=keyless)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert mark.call_count == 0

    @respx.mock
    async def test_a_row_this_agent_holds_no_keys_for_is_left_new_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        keyless = "dddddddd-eeee-ffff-0000-111111111111"
        _mock_token()
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(keyless)

        msg = await async_client.read(MESSAGE_ID, agent=keyless)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert mark.call_count == 0

    @respx.mock
    def test_a_group_row_whose_sender_key_has_not_arrived_is_left_new(
        self, sync_client, group_message_fixture, agent_id
    ):
        fx = group_message_fixture
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{API}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        mark = _mock_mark(agent_id)

        msg = sync_client.read(fx.message_id)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert mark.call_count == 0

    @respx.mock
    async def test_a_group_row_whose_sender_key_has_not_arrived_is_left_new_async(
        self, async_client, group_message_fixture, agent_id
    ):
        fx = group_message_fixture
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{API}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        mark = _mock_mark(agent_id)

        msg = await async_client.read(fx.message_id)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert mark.call_count == 0

    @respx.mock
    def test_peek_true_marks_nothing_even_when_the_row_opens(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID, peek=True)

        assert msg.plaintext == '{"text":"hi"}'
        assert mark.call_count == 0

    @respx.mock
    async def test_peek_true_marks_nothing_even_when_the_row_opens_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID, peek=True)

        assert msg.plaintext == '{"text":"hi"}'
        assert mark.call_count == 0

    @respx.mock
    def test_a_failed_mark_still_returns_the_message_and_logs_a_warning(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, caplog
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        _mock_mark(agent_id, status=500)

        with caplog.at_level(logging.WARNING, logger="rine"):
            msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext == '{"text":"hi"}'
        assert any("could not mark it delivered" in r.getMessage() for r in caplog.records)

    @respx.mock
    async def test_a_failed_mark_still_returns_the_message_and_logs_a_warning_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id, caplog
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        _mock_mark(agent_id, status=500)

        with caplog.at_level(logging.WARNING, logger="rine"):
            msg = await async_client.read(MESSAGE_ID)

        assert msg.plaintext == '{"text":"hi"}'
        assert any("could not mark it delivered" in r.getMessage() for r in caplog.records)

    @respx.mock
    def test_a_failed_mark_warns_without_a_traceback_and_keeps_it_for_debug(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, caplog
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        _mock_mark(agent_id, status=500)

        with caplog.at_level(logging.DEBUG, logger="rine"):
            sync_client.read(MESSAGE_ID)

        _assert_traceback_only_at_debug(caplog)

    @respx.mock
    async def test_a_failed_mark_warns_without_a_traceback_and_keeps_it_for_debug_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id, caplog
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "hi"})
        _mock_mark(agent_id, status=500)

        with caplog.at_level(logging.DEBUG, logger="rine"):
            await async_client.read(MESSAGE_ID)

        _assert_traceback_only_at_debug(caplog)


class TestSenderKeyScanPeeksAndMarksWhatOpened:
    """The distribution scan a cold group read triggers follows the same rule."""

    @respx.mock
    def test_an_opened_distribution_is_peeked_and_marked_with_the_message(
        self, sync_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        mock_group_message_routes()
        mark = _mock_mark(agent_id)

        msg = sync_client.read(fx.message_id)

        assert msg.plaintext == fx.plaintext
        scanned = next(
            c for c in respx.calls if c.request.url.path.endswith(fx.distribution_row["id"])
        )
        assert scanned.request.headers[PEEK_HEADER] == "1"
        assert _marked_ids(mark) == [[fx.distribution_row["id"]], [fx.message_id]]

    @respx.mock
    async def test_an_opened_distribution_is_peeked_and_marked_with_the_message_async(
        self, async_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        mock_group_message_routes()
        mark = _mock_mark(agent_id)

        msg = await async_client.read(fx.message_id)

        assert msg.plaintext == fx.plaintext
        scanned = next(
            c for c in respx.calls if c.request.url.path.endswith(fx.distribution_row["id"])
        )
        assert scanned.request.headers[PEEK_HEADER] == "1"
        assert _marked_ids(mark) == [[fx.distribution_row["id"]], [fx.message_id]]

    @respx.mock
    def test_a_distribution_that_will_not_open_is_left_new(
        self, sync_client, group_message_fixture, agent_id, other_agent_id
    ):
        fx = group_message_fixture
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{API}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": [{"id": MESSAGE_ID}]})
        )
        _mock_unopenable_dm(other_agent_id, agent_id)
        mark = _mock_mark(agent_id)

        msg = sync_client.read(fx.message_id)

        assert msg.plaintext is None
        assert mark.call_count == 0

    @respx.mock
    async def test_a_distribution_that_will_not_open_is_left_new_async(
        self, async_client, group_message_fixture, agent_id, other_agent_id
    ):
        fx = group_message_fixture
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{API}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": [{"id": MESSAGE_ID}]})
        )
        _mock_unopenable_dm(other_agent_id, agent_id)
        mark = _mock_mark(agent_id)

        msg = await async_client.read(fx.message_id)

        assert msg.plaintext is None
        assert mark.call_count == 0

    @respx.mock
    def test_a_distribution_refused_for_its_signature_is_marked_not_retried(
        self, sync_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        # A signature that does not check out never starts to verify, so the scan marks
        # the row instead of re-reading it on every group read.
        fx = group_message_fixture
        mock_group_message_routes()
        _mock_distribution_stamped_by_someone_else(fx)
        mark = _mock_mark(agent_id)

        msg = sync_client.read(fx.message_id)

        assert msg.plaintext is None  # no sender key came out of the refused row
        assert _marked_ids(mark) == [[fx.distribution_row["id"]]]

    @respx.mock
    async def test_a_distribution_refused_for_its_signature_is_marked_not_retried_async(
        self, async_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        mock_group_message_routes()
        _mock_distribution_stamped_by_someone_else(fx)
        mark = _mock_mark(agent_id)

        msg = await async_client.read(fx.message_id)

        assert msg.plaintext is None
        assert _marked_ids(mark) == [[fx.distribution_row["id"]]]

    @respx.mock
    def test_a_distribution_the_listing_shows_delivered_is_not_marked_again(
        self, sync_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        mock_group_message_routes()
        _mock_distribution_listed_as("delivered", agent_id, fx)
        mark = _mock_mark(agent_id)

        msg = sync_client.read(fx.message_id)

        assert msg.plaintext == fx.plaintext
        assert _marked_ids(mark) == [[fx.message_id]]

    @respx.mock
    async def test_a_distribution_the_listing_shows_delivered_is_not_marked_again_async(
        self, async_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        mock_group_message_routes()
        _mock_distribution_listed_as("delivered", agent_id, fx)
        mark = _mock_mark(agent_id)

        msg = await async_client.read(fx.message_id)

        assert msg.plaintext == fx.plaintext
        assert _marked_ids(mark) == [[fx.message_id]]


class TestInboxScansOncePerPage:
    """Every unreadable group row used to repeat the same distribution scan."""

    @respx.mock
    def test_several_cold_group_rows_share_one_distribution_scan(
        self, sync_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        _mock_inbox_of_copies(agent_id, fx)
        mock_group_message_routes()

        sync_client.inbox(status="new")

        assert _scan_lists(agent_id) == 1

    @respx.mock
    async def test_several_cold_group_rows_share_one_distribution_scan_async(
        self, async_client, group_message_fixture, mock_group_message_routes, agent_id
    ):
        fx = group_message_fixture
        _mock_inbox_of_copies(agent_id, fx)
        mock_group_message_routes()

        await async_client.inbox(status="new")

        assert _scan_lists(agent_id) == 1


THIRD_AGENT = "dddddddd-eeee-ffff-0000-111111111111"


def _mock_cleartext_a2a(payload: str = "e30") -> respx.Route:
    """A cleartext A2A row: never ciphertext, so readable as it arrived."""
    row = _row(
        THIRD_AGENT,
        "00000000-1111-2222-3333-444444444444",
        payload=payload,
        version="none",
        kid=None,
    )
    row["type"] = "rine.v1.a2a_message"
    return respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(200, json=row)
    )


def _mock_row_signed_by_someone_else(
    tmp_config_dir: str, agent_id: str, signer: str, claimed_sender: str
) -> None:
    """A row sealed by ``signer`` that the server stamps as sent by ``claimed_sender``."""
    save_agent_keys(tmp_config_dir, signer, WORLD.keys(signer))
    recipient = recipient_view(load_agent_keys(tmp_config_dir, agent_id), agent_id)
    sealed = encrypt_message(tmp_config_dir, signer, recipient, {"text": "forged"})
    for who in (signer, claimed_sender):
        respx.get(f"{API}/agents/{who}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(who))
        )
    respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json=_row(
                claimed_sender,
                agent_id,
                payload=sealed.encrypted_payload,
                version=sealed.encryption_version,
                kid=sealed.sender_signing_kid,
            ),
        )
    )


def _mock_distribution_stamped_by_someone_else(fx) -> None:
    """The distribution DM, listed under a sender who did not sign it."""
    respx.get(f"{API}/agents/{THIRD_AGENT}/keys").mock(
        return_value=httpx.Response(200, json=WORLD.keys_response(THIRD_AGENT))
    )
    respx.get(f"{API}/messages/{fx.distribution_row['id']}").mock(
        return_value=httpx.Response(
            200, json={**fx.distribution_row, "from_agent_id": THIRD_AGENT}
        )
    )


def _mock_distribution_listed_as(status: str, agent_id: str, fx) -> None:
    respx.get(
        f"{API}/agents/{agent_id}/messages", params={"type": MessageType.SENDER_KEY_DISTRIBUTION}
    ).mock(
        return_value=httpx.Response(
            200, json={"items": [{"id": fx.distribution_row["id"], "status": status}]}
        )
    )


def _mock_inbox_of_copies(agent_id: str, fx) -> None:
    """An inbox page of a cold group row and two that no key will open."""
    unreadable = [
        {**fx.message_row, "id": f"{fx.message_id[:-1]}{n}", "encrypted_payload": "AAAA"}
        for n in (7, 8)
    ]
    rows = [fx.message_row, *unreadable]
    respx.get(f"{API}/agents/{agent_id}/messages", params={"status": "new"}).mock(
        return_value=httpx.Response(200, json={"items": rows})
    )


def _scan_lists(agent_id: str) -> int:
    """How many times the distribution inbox was listed."""
    return sum(
        1
        for call in respx.calls
        if call.request.url.path == f"/agents/{agent_id}/messages"
        and call.request.url.params.get("type") == MessageType.SENDER_KEY_DISTRIBUTION
    )


class TestReadMarksOnlySettledRowsEndToEnd:
    """What ``read()`` does for each kind of row that does not simply open."""

    @respx.mock
    def test_a_cleartext_a2a_row_is_marked(self, sync_client, agent_id):
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a()
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.a2a_cleartext is True
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    async def test_a_cleartext_a2a_row_is_marked_async(self, async_client, agent_id):
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a()
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.a2a_cleartext is True
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    def test_a_cleartext_a2a_row_that_is_not_base64url_is_marked(self, sync_client, agent_id):
        # Its payload cannot be decoded, so ``decrypt_error`` is set; the row is still
        # settled because no key will ever change that. Pins the NONE clause of is_settled.
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a("!!not base64url!!")
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    async def test_a_cleartext_a2a_row_that_is_not_base64url_is_marked_async(
        self, async_client, agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a("!!not base64url!!")
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    def test_a_row_refused_for_its_signer_is_marked(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_row_signed_by_someone_else(tmp_config_dir, agent_id, other_agent_id, THIRD_AGENT)
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.verification_status in ("invalid", "sender-mismatch")
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    async def test_a_row_refused_for_its_signer_is_marked_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_row_signed_by_someone_else(tmp_config_dir, agent_id, other_agent_id, THIRD_AGENT)
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.verification_status in ("invalid", "sender-mismatch")
        assert _marked_ids(mark) == [[MESSAGE_ID]]

    @respx.mock
    def test_the_mark_is_made_for_the_agent_the_read_named(self, sync_client, agent_id):
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a()
        default_mark = _mock_mark(agent_id)
        named_mark = _mock_mark(THIRD_AGENT)

        sync_client.read(MESSAGE_ID, agent=THIRD_AGENT)

        assert _marked_ids(named_mark) == [[MESSAGE_ID]]
        assert default_mark.call_count == 0

    @respx.mock
    async def test_the_mark_is_made_for_the_agent_the_read_named_async(
        self, async_client, agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_cleartext_a2a()
        default_mark = _mock_mark(agent_id)
        named_mark = _mock_mark(THIRD_AGENT)

        await async_client.read(MESSAGE_ID, agent=THIRD_AGENT)

        assert _marked_ids(named_mark) == [[MESSAGE_ID]]
        assert default_mark.call_count == 0

    @respx.mock
    def test_an_envelope_this_client_does_not_know_stays_new(
        self, sync_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json=_row(other_agent_id, agent_id, payload="x", version="future-v9", kid=None),
            )
        )
        mark = _mock_mark(agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert mark.call_count == 0

    @respx.mock
    async def test_an_envelope_this_client_does_not_know_stays_new_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json=_row(other_agent_id, agent_id, payload="x", version="future-v9", kid=None),
            )
        )
        mark = _mock_mark(agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert mark.call_count == 0


class TestPeekReachesTheWire:
    @respx.mock
    def test_read_with_peek_sends_the_peek_header_and_still_names_the_actor(
        self, sync_client, agent_id, other_agent_id
    ):
        """Both halves, and the second is the load-bearing one.

        Suppressing the mark by *dropping* ``X-Rine-Agent`` was the rejected
        design: it would change which delivery row is resolved and which
        diagnostic runs, and for a one-agent org the server auto-selects and
        marks anyway. A client that dropped the actor header would satisfy the
        first assertion here and fail the second.
        """
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        sync_client.read(MESSAGE_ID, agent=agent_id, peek=True)

        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    async def test_read_with_peek_sends_the_peek_header_and_still_names_the_actor_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        await async_client.read(MESSAGE_ID, agent=agent_id, peek=True)

        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    def test_a_peek_read_still_decrypts_and_returns_the_row(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        """Peek changes what the server writes, not what the client gets back."""
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "still here"})

        msg = sync_client.read(MESSAGE_ID, peek=True)

        assert msg.decrypt_error is None
        assert msg.plaintext == '{"text":"still here"}'

    @respx.mock
    async def test_a_peek_read_still_decrypts_and_returns_the_row_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "still here"})

        msg = await async_client.read(MESSAGE_ID, peek=True)

        assert msg.decrypt_error is None
        assert msg.plaintext == '{"text":"still here"}'


class TestTheKwargContract:
    """The shape ``hermes-rine``'s retry sweep is specified against.

    🔴 A tripwire, not behavioural coverage: it introspects a signature, so it
    proves the call ``hermes-rine`` was written against still compiles and
    nothing about what ``peek=True`` does on the wire. That is the business of
    the classes above, which drive a mocked server and assert the header. Never
    count this one toward a mutation proof of the peek behaviour — it survives
    any mutation that leaves the signature alone.
    """

    @pytest.mark.parametrize("read", [SyncRineClient.read, RineClient.read])
    def test_peek_is_keyword_only_and_defaults_to_false(self, read):
        peek = inspect.signature(read).parameters["peek"]

        assert peek.kind is inspect.Parameter.KEYWORD_ONLY
        assert peek.default is False


def _mock_two_agents_and_cold_inbox(agent_id: str, other_agent_id: str, fx) -> None:
    """Two agents in the org, so nothing may be marked for "the default agent"."""
    _mock_token()
    agent = {
        "name": "test-agent",
        "human_oversight": True,
        "incoming_policy": "accept_all",
        "outgoing_policy": "send_all",
        "created_at": "2024-01-01T00:00:00Z",
    }
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {**agent, "id": other_agent_id, "handle": "first@myorg.rine.network"},
                    {**agent, "id": agent_id, "handle": "second@myorg.rine.network"},
                ]
            },
        )
    )
    respx.get(
        f"{API}/agents/{agent_id}/messages", params={"type": MessageType.SENDER_KEY_DISTRIBUTION}
    ).mock(return_value=httpx.Response(200, json={"items": [{"id": fx.distribution_row["id"]}]}))
    respx.get(f"{API}/agents/{agent_id}/messages", params={"status": "new"}).mock(
        return_value=httpx.Response(200, json={"items": [fx.message_row]})
    )
    _mock_distribution_stamped_by_someone_else(fx)


class TestTheScanMarksForTheAgentTheInboxNamed:
    """The scan runs per agent: its mark must be that agent's, not "the default" one."""

    @respx.mock
    def test_a_scan_for_a_named_agent_marks_through_that_agents_path(
        self, sync_client, group_message_fixture, agent_id, other_agent_id
    ):
        fx = group_message_fixture
        _mock_two_agents_and_cold_inbox(agent_id, other_agent_id, fx)
        named_mark = _mock_mark(agent_id)

        sync_client.inbox(status="new", agent=agent_id)

        assert _marked_ids(named_mark) == [[fx.distribution_row["id"]]]

    @respx.mock
    async def test_a_scan_for_a_named_agent_marks_through_that_agents_path_async(
        self, async_client, group_message_fixture, agent_id, other_agent_id
    ):
        fx = group_message_fixture
        _mock_two_agents_and_cold_inbox(agent_id, other_agent_id, fx)
        named_mark = _mock_mark(agent_id)

        await async_client.inbox(status="new", agent=agent_id)

        assert _marked_ids(named_mark) == [[fx.distribution_row["id"]]]
