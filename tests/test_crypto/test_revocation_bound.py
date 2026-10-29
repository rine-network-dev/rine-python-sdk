"""A revoked agent's signature holds only for rows the server stamped before the revocation."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from rine._crypto._sender_verify import verify_envelope_sender_async, verify_envelope_sender_sync
from rine._crypto.certs import ChainError, verify_agent_chain
from rine._crypto.keys import make_kid
from rine._crypto.sign import MessageSig, sign_message
from rine.testing import WORLD
from tests.test_crypto.world import SUPERSEDED_AT, AsyncKeyServer, KeyServer

AGENT = "00000000-1111-2222-3333-444444444444"
SCOPE = MessageSig("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
PAYLOAD = b"signed by an agent that was later revoked"
REVOKED_AT = SUPERSEDED_AT + timedelta(days=10)
ONE_SECOND = timedelta(seconds=1)


def _server(current: int, revoked_at: datetime | None = REVOKED_AT) -> KeyServer:
    server = KeyServer()
    server.publish(AGENT, current)
    server.revoked_at = revoked_at
    return server


def _verify(server: KeyServer, created_at: datetime | None, gen: int):  # type: ignore[no-untyped-def]
    return verify_envelope_sender_sync(
        make_kid(AGENT, gen),
        PAYLOAD,
        sign_message(WORLD.keys(AGENT, gen).signing.private_key, SCOPE, PAYLOAD),
        SCOPE,
        server,  # type: ignore[arg-type]
        AGENT,
        created_at,
    )


def test_verify_when_the_row_is_stamped_at_the_revocation_then_verified() -> None:
    assert _verify(_server(0), REVOKED_AT, 0).verification_status == "verified"


def test_verify_when_the_row_is_stamped_one_second_after_the_revocation_then_invalid() -> None:
    verdict = _verify(_server(0), REVOKED_AT + ONE_SECOND, 0)
    assert (verdict.verified, verdict.verification_status) == (False, "invalid")


@pytest.mark.parametrize(
    "created_at", [None, REVOKED_AT.replace(tzinfo=None)], ids=["none", "naive"]
)
def test_verify_when_a_revoked_generation_has_no_usable_created_at_then_invalid(
    created_at,  # type: ignore[no-untyped-def]
) -> None:
    assert _verify(_server(0), created_at, 0).verification_status == "invalid"


def test_verify_when_the_agent_is_not_revoked_then_no_created_at_is_needed() -> None:
    assert _verify(_server(0, revoked_at=None), None, 0).verification_status == "verified"


def test_verify_when_revoked_before_superseded_then_the_revocation_bounds_it() -> None:
    server = _server(1, revoked_at=SUPERSEDED_AT - ONE_SECOND)
    assert _verify(server, SUPERSEDED_AT - ONE_SECOND, 0).verification_status == "verified"
    assert _verify(server, SUPERSEDED_AT, 0).verification_status == "invalid"


def test_verify_when_superseded_before_revoked_then_the_supersession_bounds_it() -> None:
    server = _server(1)
    assert _verify(server, SUPERSEDED_AT, 0).verification_status == "verified"
    assert _verify(server, SUPERSEDED_AT + ONE_SECOND, 0).verification_status == "invalid"


def test_verify_when_a_history_read_carries_only_revoked_at_then_invalid() -> None:
    """A rotated-away generation needs its own supersession stamp; the revocation alone is no bound."""
    server = _server(1)
    server.superseded_at = None
    assert _verify(server, REVOKED_AT - ONE_SECOND, 0).verification_status == "invalid"


async def test_verify_async_when_the_row_postdates_the_revocation_then_invalid() -> None:
    server = AsyncKeyServer()
    server.publish(AGENT, 0)
    server.revoked_at = REVOKED_AT
    signature = sign_message(WORLD.keys(AGENT, 0).signing.private_key, SCOPE, PAYLOAD)
    for created_at, expected in (
        (REVOKED_AT, "verified"),
        (REVOKED_AT + ONE_SECOND, "invalid"),
        (None, "invalid"),
    ):
        verdict = await verify_envelope_sender_async(
            make_kid(AGENT, 0),
            PAYLOAD,
            signature,
            SCOPE,
            server,
            AGENT,
            created_at,  # type: ignore[arg-type]
        )
        assert verdict.verification_status == expected


@pytest.mark.parametrize("stamp", ["not a time", "2026-01-01T00:00:00"])
def test_a_key_response_with_an_unreadable_or_naive_revoked_at_is_refused(stamp: str) -> None:
    body = WORLD.keys_response(AGENT, 0)
    body["revoked_at"] = stamp
    with pytest.raises(ChainError):
        verify_agent_chain(body, AGENT)
