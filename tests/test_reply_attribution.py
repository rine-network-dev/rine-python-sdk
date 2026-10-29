"""Who may answer a message, and what the refusal tells them.

A reply is filed from the agent that ACTS, and sealed with that agent's keys.
Reading the original is authorised for the whole org, so every sibling of the
addressee can reach the row — and before this guard, any of them could answer
mail it holds no key to open, producing a reply the far side cannot tie to what
it wrote.

The guard is client-side on purpose: it costs one comparison against a row the
call has already fetched, and it refuses before anything is encrypted or sent.
Only the rine HTTP boundary is mocked (respx); the SDK is real, so the sentence
asserted here is the sentence an operator reads, and "no POST" means no reply
row was ever attempted.

Both stacks are covered because the sync client is a hand-mirror of the async
one — a guard added to one and not the other is exactly the drift this pins.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine import AGENT_HEADER
from rine._actor import refuse_if_not_addressee
from rine.errors import ReplyAttributionError

API = "https://rine.network"
AGENT_ID = "00000000-1111-2222-3333-444444444444"  # matches the conftest fixtures
SIBLING_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # same org, not the addressee
PEER_ID = "99999999-8888-7777-6666-555555555555"  # the far side
MESSAGE_ID = "bbbb1111-0000-0000-0000-000000000001"
CONVERSATION_ID = "dddddddd-eeee-ffff-0000-111111111111"
TOKEN = {"access_token": "test-token", "expires_in": 900}


def _agent(agent_id: str, name: str) -> dict:
    return {
        "id": agent_id,
        "name": name,
        "handle": f"{name}@myorg.rine.network",
        "created_at": "2024-01-01T00:00:00Z",
    }


def _mock_org(agents: list[dict]) -> None:
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
    respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": agents}))


def _mock_original(from_agent_id: str, to_agent_id: str):
    """The row ``reply()`` fetches to recover the peer — and to check attribution."""
    return respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": MESSAGE_ID,
                "conversation_id": CONVERSATION_ID,
                "from_agent_id": from_agent_id,
                "to_agent_id": to_agent_id,
                "type": "rine.v1.task_request",
                "encrypted_payload": "x",
                "encryption_version": "hpke-hybrid-v2",
                "created_at": "2024-01-01T00:00:00Z",
            },
        )
    )


def _mock_reply_post():
    """Registered so the test can assert it was never called, not merely unmocked."""
    return respx.post(f"{API}/messages/{MESSAGE_ID}/reply").mock(
        return_value=httpx.Response(200, json={})
    )


class TestTheComparisonItself:
    """The guard as a function, with no client around it."""

    def test_a_group_post_has_no_addressee_to_compare_against(self):
        # ``to_agent_id`` is null on a group post: there is no one agent the post
        # was addressed to, and the server refuses a reply to one anyway. Refusing
        # here as well would put a second, differently-worded no in front of the
        # server's.
        refuse_if_not_addressee(AGENT_ID, MESSAGE_ID, None)
        refuse_if_not_addressee(AGENT_ID, MESSAGE_ID, "")

    def test_the_addressee_may_answer_however_its_id_was_spelled(self):
        # Both sides are server-issued UUIDs. A caller that carried one through a
        # surface which upper-cased or padded it must not be refused over
        # spelling — the refusal is about identity, not about text.
        refuse_if_not_addressee(AGENT_ID.upper(), MESSAGE_ID, f"  {AGENT_ID}  ")

    def test_a_sibling_of_the_addressee_is_refused_and_told_who_to_be(self):
        with pytest.raises(ReplyAttributionError) as excinfo:
            refuse_if_not_addressee(SIBLING_ID, MESSAGE_ID, AGENT_ID, PEER_ID)

        refusal = excinfo.value
        assert refusal.message_id == MESSAGE_ID
        assert refusal.acting_agent_id == SIBLING_ID
        assert refusal.addressee_agent_id == AGENT_ID
        # The remedy is the whole point: the addressee is a sibling in this same
        # org, so acting as it is a change the caller can actually make.
        assert f"Reply as {AGENT_ID}." in str(refusal)

    def test_the_original_sender_is_refused_without_impossible_advice(self):
        # Answering your OWN sent message is refused too — it is not the
        # addressee — but here the addressee is the FAR SIDE's agent, in another
        # org, which this caller can never act as. "Reply as {peer}" would be
        # advice it is unable to take.
        with pytest.raises(ReplyAttributionError) as excinfo:
            refuse_if_not_addressee(AGENT_ID, MESSAGE_ID, PEER_ID, AGENT_ID)

        refusal = excinfo.value
        assert refusal.addressee_agent_id == PEER_ID
        assert f"Reply as {PEER_ID}." not in str(refusal)
        assert f"You sent {MESSAGE_ID}" in str(refusal)

    def test_without_the_originals_sender_the_refusal_names_the_addressee(self):
        # The sender argument is optional, and a caller that omits it gets the
        # sibling wording. Pinned so the fallback stays the safe one: naming the
        # addressee is wrong only for the sender, and a caller that cannot say
        # who sent the original cannot know it is that case.
        with pytest.raises(ReplyAttributionError, match=f"Reply as {PEER_ID}."):
            refuse_if_not_addressee(AGENT_ID, MESSAGE_ID, PEER_ID)


class TestTheClientsRefuseBeforeSending:
    @respx.mock
    async def test_a_sibling_cannot_answer_mail_it_cannot_open(self, async_client):
        _mock_org([_agent(AGENT_ID, "me"), _agent(SIBLING_ID, "sibling")])
        original = _mock_original(from_agent_id=PEER_ID, to_agent_id=SIBLING_ID)
        post = _mock_reply_post()

        with pytest.raises(ReplyAttributionError) as excinfo:
            await async_client.reply(MESSAGE_ID, {"text": "not mine to answer"}, agent=AGENT_ID)

        assert str(SIBLING_ID) in str(excinfo.value)
        assert not post.called
        # The read that fed the guard was NAMED: the row is authorised for the
        # org, so the header is what decides whose delivery mark it moves.
        assert original.calls[0].request.headers[AGENT_HEADER] == AGENT_ID

    def test_the_sync_client_refuses_the_same_sibling(self, sync_client):
        # The twin, asserted separately rather than parametrised: they are two
        # hand-written call sites and only a second assertion catches one of them
        # losing the guard.
        with respx.mock:
            _mock_org([_agent(AGENT_ID, "me"), _agent(SIBLING_ID, "sibling")])
            original = _mock_original(from_agent_id=PEER_ID, to_agent_id=SIBLING_ID)
            post = _mock_reply_post()

            with pytest.raises(ReplyAttributionError):
                sync_client.reply(MESSAGE_ID, {"text": "not mine to answer"}, agent=AGENT_ID)

            assert not post.called
            assert original.calls[0].request.headers[AGENT_HEADER] == AGENT_ID

    @respx.mock
    async def test_answering_your_own_message_is_refused_with_advice_you_can_take(
        self, async_client
    ):
        _mock_org([_agent(AGENT_ID, "me")])
        _mock_original(from_agent_id=AGENT_ID, to_agent_id=PEER_ID)
        post = _mock_reply_post()

        with pytest.raises(ReplyAttributionError) as excinfo:
            await async_client.reply(MESSAGE_ID, {"text": "following up"})

        assert f"You sent {MESSAGE_ID}" in str(excinfo.value)
        assert not post.called
