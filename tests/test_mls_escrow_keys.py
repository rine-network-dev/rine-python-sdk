"""The branch escrow key read: fetch, verify, cache and the 410."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest

from rine._actor import AGENT_HEADER
from rine._constants import KEY_CACHE_TTL
from rine._crypto._agent_keys import fetch_recipient_keys_sync
from rine._crypto.escrow_key import EscrowKeyError
from rine._mls.escrow_api import fetch_branch_escrow_key, upload_escrow
from rine._mls.escrow_keys import (
    BranchRevokedError,
    cached_escrow_key,
    drop_cached_escrow_key,
    drop_escrow_keys,
    resolve_escrow_key,
)
from rine._mls.heartbeat import MlsActor
from rine.errors import CryptoError, InternalServerError, RineApiError
from rine.testing import WORLD, World, write_agent_identity
from tests.test_crypto.world import KeyServer

if TYPE_CHECKING:
    from rine._crypto._key_pins import KeyPins

AGENT = "00000000-1111-2222-3333-444444444444"
RECIPIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP = "11111111-2222-3333-4444-555555555555"
OTHER_WORLD = World(root=bytes(range(1, 33)))

Tamper = Callable[[dict[str, Any]], dict[str, Any]]


class FakeClient:
    """A sync client serving the two escrow routes from a :class:`World`."""

    def __init__(self, world: World = WORLD) -> None:
        """Serve one world's keys and escrow key, recording every call."""
        self._keys = KeyServer(world)
        self.key_pins: KeyPins = self._keys.key_pins
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.escrow_error: RineApiError | None = None
        self.escrow_tamper: Tamper | None = None

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer a key or escrow-key read, recording the call."""
        self.calls.append((path, kwargs))
        if path.endswith("/keys"):
            return self._keys.get(path, **kwargs)
        if self.escrow_error is not None:
            raise self.escrow_error
        body = self._keys.world.escrow_response()
        return self.escrow_tamper(body) if self.escrow_tamper else body

    def put(self, path: str, **kwargs: Any) -> None:
        """Record an escrow upload."""
        self.calls.append((path, kwargs))


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Every test starts from a cold escrow-key cache."""
    drop_escrow_keys()


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor whose leaf keys are on disk and whose org is pinned."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    client.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    return MlsActor(client=client, config_dir=config_dir, agent_id=AGENT)


def _escrow_calls(actor: MlsActor) -> int:
    """How many escrow-key reads this actor's client has served."""
    return sum(1 for path, _ in actor.client.calls if path.endswith("/escrow-key"))


def test_resolve_escrow_key_when_the_key_chains_then_returns_it(actor: MlsActor) -> None:
    """A chain-valid key is returned with its own org and branch."""
    key = resolve_escrow_key(actor)
    assert key.x25519_public_key == WORLD.branch.escrow_x_pk
    assert key.ml_kem_public_key == WORLD.branch.escrow_kem_pk
    assert (key.org_id, key.branch) == (WORLD.org_id, WORLD.branch.name)


def test_resolve_escrow_key_when_called_twice_then_the_second_is_a_cache_hit(
    actor: MlsActor,
) -> None:
    """A second resolve makes no HTTP call at all."""
    resolve_escrow_key(actor)
    before = len(actor.client.calls)
    assert resolve_escrow_key(actor).branch == WORLD.branch.name
    assert len(actor.client.calls) == before


def test_cached_escrow_key_when_the_entry_outlives_the_key_cache_window_then_it_is_a_miss(
    actor: MlsActor,
) -> None:
    """A verified key is trusted for KEY_CACHE_TTL, not for the life of the process."""
    key = resolve_escrow_key(actor)
    calls = len(actor.client.calls)
    now = time.monotonic()

    assert cached_escrow_key(actor, now=now) == key
    assert cached_escrow_key(actor, now=now + KEY_CACHE_TTL + 1) is None
    assert cached_escrow_key(actor, now=now) is None
    assert len(actor.client.calls) == calls

    resolve_escrow_key(actor)
    assert _escrow_calls(actor) == 2


def test_drop_cached_escrow_key_when_called_then_only_this_agents_entry_goes(
    actor: MlsActor,
) -> None:
    """A branch_revoked answer drops the acting agent's key and nobody else's."""
    resolve_escrow_key(actor)
    other = MlsActor(client=actor.client, config_dir=actor.config_dir, agent_id=RECIPIENT)

    drop_cached_escrow_key(other)
    assert cached_escrow_key(actor) is not None

    drop_cached_escrow_key(actor)
    assert cached_escrow_key(actor) is None


def test_resolve_escrow_key_when_the_branch_is_revoked_then_raises_and_refetches(
    actor: MlsActor,
) -> None:
    """A 410 raises BranchRevokedError, drops the cache, and the next call fetches."""
    actor.client.escrow_error = RineApiError(410, "branch revoked")
    with pytest.raises(BranchRevokedError):
        resolve_escrow_key(actor)
    actor.client.escrow_error = None
    assert resolve_escrow_key(actor).branch == WORLD.branch.name
    assert _escrow_calls(actor) == 2


def test_resolve_escrow_key_when_the_branch_cert_is_another_orgs_then_refuses_uncached(
    actor: MlsActor,
) -> None:
    """A branch certificate of another org raises EscrowKeyError and caches nothing."""
    actor.client.escrow_tamper = lambda body: {
        **body,
        "branch_certificate": OTHER_WORLD.keys_response(AGENT)["branch_certificate"],
    }
    with pytest.raises(EscrowKeyError):
        resolve_escrow_key(actor)
    actor.client.escrow_tamper = None
    assert resolve_escrow_key(actor).branch == WORLD.branch.name
    assert _escrow_calls(actor) == 2


def test_resolve_escrow_key_when_the_agent_cert_names_another_key_then_refuses(
    actor: MlsActor,
) -> None:
    """An agent certificate naming a key this device does not hold is refused."""
    actor.client._keys.tamper = lambda body: {
        **body,
        "agent_certificate": WORLD.keys_response(RECIPIENT)["agent_certificate"],
    }
    with pytest.raises(EscrowKeyError):
        resolve_escrow_key(actor)


def test_resolve_escrow_key_when_no_org_is_pinned_then_raises_crypto_error(
    tmp_path: Any,
) -> None:
    """No own-org pin means the key cannot be verified, so the read refuses."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    unpinned = MlsActor(client=FakeClient(), config_dir=config_dir, agent_id=AGENT)
    with pytest.raises(CryptoError, match="no own org id"):
        resolve_escrow_key(unpinned)


def test_resolve_escrow_key_when_the_org_pin_came_from_a_served_chain_then_raises(
    tmp_path: Any,
) -> None:
    """A pin learned from a server answer is not a local fact: escrow never seals under it."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    fetch_recipient_keys_sync(client._keys, AGENT)
    assert client.key_pins.own_org_of(AGENT) is None
    with pytest.raises(CryptoError, match="no own org id"):
        resolve_escrow_key(MlsActor(client=client, config_dir=config_dir, agent_id=AGENT))


def test_resolve_escrow_key_when_the_server_500s_then_propagates_uncached(
    actor: MlsActor,
) -> None:
    """A 500 propagates as RineApiError and is not cached."""
    actor.client.escrow_error = InternalServerError(detail="boom")
    with pytest.raises(RineApiError) as first:
        resolve_escrow_key(actor)
    assert first.value.status == 500
    with pytest.raises(RineApiError):
        resolve_escrow_key(actor)
    actor.client.escrow_error = None
    assert resolve_escrow_key(actor).branch == WORLD.branch.name
    assert _escrow_calls(actor) == 3


def test_drop_escrow_keys_when_called_with_no_arguments_then_clears_everything(
    actor: MlsActor,
) -> None:
    """A bare drop clears the whole cache, so the next resolve fetches again."""
    resolve_escrow_key(actor)
    drop_escrow_keys()
    resolve_escrow_key(actor)
    assert _escrow_calls(actor) == 2


def test_upload_escrow_when_called_then_puts_the_body_as_the_acting_agent() -> None:
    """The upload PUTs the body to the epoch path with the acting-agent header."""
    client = FakeClient()
    body = {"fp": "AAAA", "sealed": "BBBB", "key_gen": 3, "sig": "CCCC"}
    upload_escrow(client, AGENT, GROUP, 7, body)
    path, kwargs = client.calls[-1]
    assert path == f"/groups/{GROUP}/mls/escrow/7"
    assert kwargs["json_body"] == body
    assert kwargs["extra_headers"] == {AGENT_HEADER: AGENT}


def test_fetch_branch_escrow_key_when_the_branch_has_specials_then_percent_encodes() -> None:
    """The branch is percent-encoded into the path and the header names the agent."""
    client = FakeClient()
    fetch_branch_escrow_key(client, AGENT, "feat/x y")
    path, kwargs = client.calls[-1]
    assert path == "/orgs/me/branches/feat%2Fx%20y/escrow-key"
    assert kwargs["extra_headers"] == {AGENT_HEADER: AGENT}
