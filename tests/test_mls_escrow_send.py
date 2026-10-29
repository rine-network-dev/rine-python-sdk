"""The one retry a group post gets on 409 ``escrow_missing``."""

from __future__ import annotations

import json
from typing import Any

import pytest

from rine._mls.escrow_keys import drop_escrow_keys
from rine._mls.escrow_send import (
    async_post_with_escrow_retry,
    is_escrow_missing,
    post_with_escrow_retry,
)
from rine._mls.escrow_store import PendingEscrow, list_pending, write_pending
from rine._mls.heartbeat import MlsActor
from rine.errors import RineApiError
from rine.testing import WORLD, write_agent_identity
from tests.test_mls_escrow_drain import AGENT, GROUP, FakeClient

MISSING = RineApiError(409, "escrow not stored", json.dumps({"error": "escrow_missing"}))
MISSING_AGAIN = RineApiError(409, "still missing", json.dumps({"error": "escrow_missing"}))


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    drop_escrow_keys()


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor with one escrow file waiting, as a sealed-but-not-uploaded epoch leaves it."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    client.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    write_pending(config_dir, AGENT, PendingEscrow(GROUP, 0, b"\x01" * 16, b"sealed"))
    return MlsActor(client=client, config_dir=config_dir, agent_id=AGENT)


class _Post:
    """A post that fails with the given errors, in order, then succeeds."""

    def __init__(self, *errors: Exception) -> None:
        self.errors = list(errors)
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return "posted"


def _uploads(actor: MlsActor) -> int:
    return sum(
        1 for path, _ in actor.client.calls if path.startswith(f"/groups/{GROUP}/mls/escrow")
    )


def test_post_with_escrow_retry_when_the_escrow_is_missing_then_uploads_and_posts_once_more(
    actor: MlsActor,
) -> None:
    post = _Post(MISSING)

    assert post_with_escrow_retry(actor, GROUP, post) == "posted"

    assert post.calls == 2
    assert _uploads(actor) == 1
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def test_post_with_escrow_retry_when_the_post_succeeds_then_uploads_nothing(
    actor: MlsActor,
) -> None:
    post = _Post()

    assert post_with_escrow_retry(actor, GROUP, post) == "posted"

    assert post.calls == 1
    assert _uploads(actor) == 0


def test_post_with_escrow_retry_when_the_retry_fails_too_then_the_error_propagates(
    actor: MlsActor,
) -> None:
    post = _Post(MISSING, MISSING_AGAIN)

    with pytest.raises(RineApiError) as raised:
        post_with_escrow_retry(actor, GROUP, post)

    assert raised.value is MISSING_AGAIN
    assert post.calls == 2
    assert _uploads(actor) == 1


@pytest.mark.parametrize(
    "error",
    [
        RineApiError(409, "epoch moved", json.dumps({"error": "epoch_conflict"})),
        RineApiError(422, "no", json.dumps({"error": "escrow_missing"})),
        RineApiError(409, "plain conflict"),
    ],
)
def test_post_with_escrow_retry_when_the_error_is_another_then_it_propagates_untouched(
    actor: MlsActor, error: RineApiError
) -> None:
    post = _Post(error)

    with pytest.raises(RineApiError) as raised:
        post_with_escrow_retry(actor, GROUP, post)

    assert raised.value is error
    assert post.calls == 1
    assert _uploads(actor) == 0


def test_is_escrow_missing_when_the_body_names_it_on_a_409_then_true() -> None:
    assert is_escrow_missing(MISSING)
    assert not is_escrow_missing(ValueError("escrow_missing"))


@pytest.mark.usefixtures("mls_escrow_stub")
async def test_async_client_when_the_escrow_is_missing_then_uploads_and_posts_once_more(
    async_client, tmp_config_dir, agent_id, mls_escrow_stub
) -> None:
    write_pending(tmp_config_dir, agent_id, PendingEscrow(GROUP, 0, b"\x01" * 16, b"sealed"))
    errors = [MISSING]
    calls = 0

    async def post() -> str:
        nonlocal calls
        calls += 1
        if errors:
            raise errors.pop()
        return "posted"

    assert await async_post_with_escrow_retry(async_client, agent_id, GROUP, post) == "posted"

    assert calls == 2
    assert mls_escrow_stub == [(GROUP, 0)]
    assert list_pending(tmp_config_dir, agent_id, GROUP) == []
