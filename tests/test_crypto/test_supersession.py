"""A signature under a superseded key generation holds only for rows stamped before it."""

from __future__ import annotations

from datetime import timedelta

import pytest

from rine._crypto._agent_keys import get_agent_keys_async, get_agent_keys_sync
from rine._crypto._sender_verify import verify_envelope_sender_async, verify_envelope_sender_sync
from rine._crypto.certs import ChainError, verify_agent_chain
from rine._crypto.keys import make_kid
from rine._crypto.sign import MessageSig, sign_message
from rine.testing import WORLD
from tests.test_crypto.world import SUPERSEDED_AT, AsyncKeyServer, KeyServer

AGENT = "00000000-1111-2222-3333-444444444444"
RECIPIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SCOPE = MessageSig(RECIPIENT)
PAYLOAD = b"signed under generation zero"
BEFORE = SUPERSEDED_AT - timedelta(seconds=1)
AFTER = SUPERSEDED_AT + timedelta(microseconds=1)


def _signature(gen: int = 0) -> bytes:
    return sign_message(WORLD.keys(AGENT, gen).signing.private_key, SCOPE, PAYLOAD)


def _verify(server: KeyServer, created_at, gen: int = 0):  # type: ignore[no-untyped-def]
    return verify_envelope_sender_sync(
        make_kid(AGENT, gen),
        PAYLOAD,
        _signature(gen),
        SCOPE,
        server,  # type: ignore[arg-type]
        AGENT,
        created_at,
    )


def _server(current: int = 1) -> KeyServer:
    server = KeyServer()
    server.publish(AGENT, current)
    return server


@pytest.mark.parametrize("created_at", [BEFORE, SUPERSEDED_AT])
def test_verify_when_the_row_predates_the_supersession_then_verified(created_at) -> None:  # type: ignore[no-untyped-def]
    assert _verify(_server(), created_at).verification_status == "verified"


@pytest.mark.parametrize(
    "created_at",
    [AFTER, None, BEFORE.replace(tzinfo=None)],
    ids=["after", "missing", "naive"],
)
def test_verify_when_the_row_does_not_predate_the_supersession_then_invalid(created_at) -> None:  # type: ignore[no-untyped-def]
    verdict = _verify(_server(), created_at)
    assert (verdict.verified, verdict.verification_status) == (False, "invalid")


def test_verify_when_a_history_read_omits_superseded_at_then_invalid() -> None:
    server = _server()
    server.superseded_at = None
    assert _verify(server, BEFORE).verification_status == "invalid"


def test_verify_when_the_generation_is_current_then_no_created_at_is_needed() -> None:
    assert _verify(_server(current=0), None).verification_status == "verified"


async def test_verify_async_when_the_row_postdates_the_supersession_then_invalid() -> None:
    server = AsyncKeyServer()
    server.publish(AGENT, 1)
    for created_at, expected in ((BEFORE, "verified"), (AFTER, "invalid"), (None, "invalid")):
        verdict = await verify_envelope_sender_async(
            make_kid(AGENT, 0),
            PAYLOAD,
            _signature(),
            SCOPE,
            server,  # type: ignore[arg-type]
            AGENT,
            created_at,
        )
        assert verdict.verification_status == expected


@pytest.mark.parametrize("stamp", ["not a time", "2026-01-01T00:00:00"])
def test_a_key_response_with_an_unreadable_or_naive_superseded_at_is_refused(stamp: str) -> None:
    body = WORLD.keys_response(AGENT, 0)
    body["superseded_at"] = stamp
    with pytest.raises(ChainError):
        verify_agent_chain(body, AGENT)


def test_verify_when_many_prior_epoch_messages_share_a_sender_then_history_is_read_once() -> None:
    server = _server()
    verdicts = [_verify(server, BEFORE) for _ in range(5)]
    assert [v.verification_status for v in verdicts] == ["verified"] * 5
    assert server.reads == 2  # the current generation once, the old generation once


def test_verify_when_a_cached_history_generation_fails_its_chain_then_still_refused() -> None:
    server = _server()
    server.tamper = lambda body: {**body, "key_gen": 7} if body["key_gen"] == 0 else body
    verdict = _verify(server, BEFORE)
    assert (verdict.verified, verdict.verification_status) != (True, "verified")


async def test_verify_async_when_prior_epoch_messages_share_a_sender_then_history_read_once() -> (
    None
):
    server = AsyncKeyServer()
    server.publish(AGENT, 1)
    for _ in range(5):
        verdict = await verify_envelope_sender_async(
            make_kid(AGENT, 0),
            PAYLOAD,
            _signature(),
            SCOPE,
            server,  # type: ignore[arg-type]
            AGENT,
            BEFORE,
        )
        assert verdict.verification_status == "verified"
    assert server.reads == 2  # the current generation once, the old generation once


def _another_genuine_generation(body: dict[str, object]) -> dict[str, object]:
    """Answer a generation-0 request with generation 1's genuine, chain-valid response."""
    return WORLD.keys_response(AGENT, 1) if body["key_gen"] == 0 else body


def test_a_history_read_answered_with_another_genuine_generation_is_refused() -> None:
    server = _server()
    server.tamper = _another_genuine_generation
    with pytest.raises(ChainError):
        get_agent_keys_sync(server, AGENT, gen=0)  # type: ignore[arg-type]


async def test_an_async_history_read_answered_with_another_genuine_generation_is_refused() -> None:
    server = AsyncKeyServer()
    server.publish(AGENT, 1)
    server.tamper = _another_genuine_generation
    with pytest.raises(ChainError):
        await get_agent_keys_async(server, AGENT, gen=0)  # type: ignore[arg-type]
