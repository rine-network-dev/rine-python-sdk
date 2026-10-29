"""The key chain is refused when broken, at every consumer."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from rine._crypto._agent_keys import (
    fetch_recipient_keys_async,
    fetch_recipient_keys_sync,
    get_agent_keys_sync,
)
from rine._crypto._key_pins import KeyPins
from rine._crypto._sender_verify import verify_envelope_sender_async, verify_envelope_sender_sync
from rine._crypto.certs import (
    CHAIN_INVALID,
    ChainError,
    verify_agent_chain,
)
from rine._crypto.escrow_key import (
    ESCROW_KEY_INVALID,
    EscrowKeyError,
    OwnIdentity,
    verify_branch_escrow_key,
)
from rine._crypto.keys import make_kid
from rine._crypto.sign import MessageSig, sign_message
from rine._mls.tree import fetch_agent_identities
from rine._resolve import warn_if_handle_moved
from rine._utils import to_base64url
from rine.testing import WORLD, World
from tests.test_crypto.world import SUPERSEDED_AT, AsyncKeyServer, KeyServer

AGENT = "00000000-1111-2222-3333-444444444444"
RECIPIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER_WORLD = World(root=bytes(range(1, 33)))

Tamper = Callable[[dict[str, Any]], None]


def _swap_encryption_key(body: dict[str, Any]) -> None:
    body["encryption_public_key"] = WORLD.keys_response(RECIPIENT)["encryption_public_key"]


def _swap_signing_key(body: dict[str, Any]) -> None:
    body["signing_public_key"] = WORLD.keys_response(RECIPIENT)["signing_public_key"]


def _swap_pq_key(body: dict[str, Any]) -> None:
    body["pq_encryption_public_key"] = WORLD.keys_response(RECIPIENT)["pq_encryption_public_key"]


def _swap_mls_key(body: dict[str, Any]) -> None:
    body["mls_signing_public_key"] = WORLD.keys_response(RECIPIENT)["mls_signing_public_key"]


def _another_orgs_chain(body: dict[str, Any]) -> None:
    body.update(OTHER_WORLD.keys_response(AGENT))


def _org_keys_of_another_org(body: dict[str, Any]) -> None:
    body["org_signing_public_key"] = to_base64url(OTHER_WORLD.org.ed_pk)


def _org_id_not_derived_from_keys(body: dict[str, Any]) -> None:
    body["org_id"] = OTHER_WORLD.org_id


def _another_agents_certificate(body: dict[str, Any]) -> None:
    body["agent_certificate"] = WORLD.keys_response(RECIPIENT)["agent_certificate"]


def _another_generation(body: dict[str, Any]) -> None:
    body["key_gen"] = body["key_gen"] + 1


def _branch_certificate_of_another_org(body: dict[str, Any]) -> None:
    body["branch_certificate"] = OTHER_WORLD.keys_response(AGENT)["branch_certificate"]


def _no_agent_certificate(body: dict[str, Any]) -> None:
    del body["agent_certificate"]


def _no_branch_certificate(body: dict[str, Any]) -> None:
    del body["branch_certificate"]


def _corrupted_agent_certificate(body: dict[str, Any]) -> None:
    head, payload, signature = body["agent_certificate"].split(".")
    body["agent_certificate"] = f"{head}.{payload}.{'A' * len(signature)}"


BREAKS: dict[str, Tamper] = {
    "encryption key swapped": _swap_encryption_key,
    "signing key swapped": _swap_signing_key,
    "pq key swapped": _swap_pq_key,
    "mls key swapped": _swap_mls_key,
    "chain of another org": _another_orgs_chain,
    "org keys of another org": _org_keys_of_another_org,
    "org id not derived from the keys": _org_id_not_derived_from_keys,
    "another agent's certificate": _another_agents_certificate,
    "another generation": _another_generation,
    "branch certificate of another org": _branch_certificate_of_another_org,
    "no agent certificate": _no_agent_certificate,
    "no branch certificate": _no_branch_certificate,
    "corrupted agent certificate": _corrupted_agent_certificate,
}
# "chain of another org" is a complete, valid chain of a different org: only a pin refuses it.
BROKEN = [name for name in BREAKS if name != "chain of another org"]


def _broken(name: str) -> dict[str, Any]:
    body = copy.deepcopy(WORLD.keys_response(AGENT))
    BREAKS[name](body)
    return body


def test_an_intact_chain_verifies_to_the_agents_keys() -> None:
    keys = verify_agent_chain(WORLD.keys_response(AGENT), AGENT)
    node = WORLD.node(AGENT)
    assert (keys.agent_id, keys.org_id, keys.key_gen) == (AGENT, WORLD.org_id, 0)
    assert keys.signing_public_key == node.ed_pk
    assert keys.mls_public_key == node.mls_pk


@pytest.mark.parametrize("name", BROKEN)
def test_verify_agent_chain_refuses_a_broken_chain(name: str) -> None:
    with pytest.raises(ChainError, match=CHAIN_INVALID):
        verify_agent_chain(_broken(name), AGENT)


def test_verify_agent_chain_refuses_a_chain_vouching_for_another_agent() -> None:
    with pytest.raises(ChainError, match=CHAIN_INVALID):
        verify_agent_chain(WORLD.keys_response(AGENT), RECIPIENT)


@pytest.mark.parametrize("name", BROKEN)
def test_sealing_to_a_peer_refuses_a_broken_chain_sync(name: str) -> None:
    server = KeyServer()
    server.tamper = lambda body: BREAKS[name](body) or body
    with pytest.raises(ChainError, match=CHAIN_INVALID):
        fetch_recipient_keys_sync(server, AGENT)


@pytest.mark.parametrize("name", BROKEN)
async def test_sealing_to_a_peer_refuses_a_broken_chain_async(name: str) -> None:
    server = AsyncKeyServer()
    server.tamper = lambda body: BREAKS[name](body) or body
    with pytest.raises(ChainError, match=CHAIN_INVALID):
        await fetch_recipient_keys_async(server, AGENT)


@pytest.mark.parametrize("name", BROKEN)
def test_reading_a_peers_keys_refuses_a_broken_chain_and_caches_nothing(name: str) -> None:
    server = KeyServer()
    server.tamper = lambda body: BREAKS[name](body) or body
    with pytest.raises(ChainError):
        get_agent_keys_sync(server, AGENT)  # type: ignore[arg-type]
    assert server._keys_cache.get(AGENT) is None


def _signed_by_agent() -> tuple[str, bytes, bytes, MessageSig]:
    scope = MessageSig(RECIPIENT)
    payload = b"hello"
    signature = sign_message(WORLD.keys(AGENT).signing.private_key, scope, payload)
    return make_kid(AGENT, 0), payload, signature, scope


def test_a_signature_is_invalid_when_the_senders_chain_is_broken_sync() -> None:
    kid, payload, signature, scope = _signed_by_agent()
    good = verify_envelope_sender_sync(kid, payload, signature, scope, KeyServer(), AGENT)  # type: ignore[arg-type]
    assert good.verification_status == "verified"
    for name in BROKEN:
        server = KeyServer()
        server.tamper = lambda body, name=name: BREAKS[name](body) or body  # type: ignore[misc]
        verdict = verify_envelope_sender_sync(kid, payload, signature, scope, server, AGENT)  # type: ignore[arg-type]
        assert (verdict.verified, verdict.verification_status) == (False, "invalid"), name


async def test_a_signature_is_invalid_when_the_senders_chain_is_broken_async() -> None:
    kid, payload, signature, scope = _signed_by_agent()
    good = await verify_envelope_sender_async(
        kid,
        payload,
        signature,
        scope,
        AsyncKeyServer(),
        AGENT,  # type: ignore[arg-type]
    )
    assert good.verification_status == "verified"
    for name in BROKEN:
        server = AsyncKeyServer()
        server.tamper = lambda body, name=name: BREAKS[name](body) or body  # type: ignore[misc]
        verdict = await verify_envelope_sender_async(
            kid,
            payload,
            signature,
            scope,
            server,
            AGENT,  # type: ignore[arg-type]
        )
        assert (verdict.verified, verdict.verification_status) == (False, "invalid"), name


class _BatchClient(KeyServer):
    """Serve ``GET /agents/keys`` as a batch of key responses."""

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        ids = kwargs["params"]["ids"].split(",")
        return {"keys": {agent: self._batch_entry(agent) for agent in ids}}

    def _batch_entry(self, agent: str) -> dict[str, Any]:
        body = self.world.keys_response(agent)
        return self.tamper(body) if self.tamper and agent == AGENT else body


def test_mls_identities_drop_an_agent_whose_chain_is_broken() -> None:
    client = _BatchClient()
    assert set(fetch_agent_identities(client, [AGENT, RECIPIENT])) == {AGENT, RECIPIENT}
    for name in BROKEN:
        client = _BatchClient()
        client.tamper = lambda body, name=name: BREAKS[name](body) or body  # type: ignore[misc]
        assert set(fetch_agent_identities(client, [AGENT, RECIPIENT])) == {RECIPIENT}, name


def test_an_agent_cannot_move_to_another_org_once_pinned() -> None:
    server = KeyServer()
    fetch_recipient_keys_sync(server, AGENT)
    server.world = OTHER_WORLD
    with pytest.raises(ChainError, match="another org"):
        fetch_recipient_keys_sync(server, AGENT)


def test_the_own_org_pin_refuses_a_foreign_chain_on_the_first_read() -> None:
    server = KeyServer(OTHER_WORLD)
    server.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    with pytest.raises(ChainError, match="another org"):
        fetch_recipient_keys_sync(server, AGENT)


def test_a_handle_that_moves_to_another_org_is_reported_once_and_never_refused() -> None:
    pins = KeyPins()
    assert pins.note_handle_org("alpha@acme.rine.network", WORLD.org_id) is None
    assert pins.note_handle_org("alpha@acme.rine.network", WORLD.org_id) is None
    assert pins.note_handle_org("alpha@acme.rine.network", OTHER_WORLD.org_id) == WORLD.org_id
    assert pins.note_handle_org("alpha@acme.rine.network", OTHER_WORLD.org_id) is None


def test_warn_if_handle_moved_names_both_orgs_for_a_handle_and_skips_a_uuid(caplog) -> None:
    pins = KeyPins()
    warn_if_handle_moved(pins, "alpha@acme", WORLD.verified(AGENT))
    with caplog.at_level("WARNING", logger="rine"):
        warn_if_handle_moved(pins, "alpha@acme.rine.network", OTHER_WORLD.verified(AGENT))
        warn_if_handle_moved(pins, AGENT, WORLD.verified(AGENT))
        warn_if_handle_moved(pins, AGENT, OTHER_WORLD.verified(AGENT))
    assert [r.getMessage() for r in caplog.records] == [
        f"handle alpha@acme.rine.network now resolves to org {OTHER_WORLD.org_id}; "
        f"it resolved to org {WORLD.org_id} before"
    ]


def test_key_gen_cannot_go_backwards_once_seen() -> None:
    server = KeyServer()
    server.publish(AGENT, 2)
    fetch_recipient_keys_sync(server, AGENT)
    server.publish(AGENT, 1)
    with pytest.raises(ChainError, match="lower"):
        fetch_recipient_keys_sync(server, AGENT)


def test_a_signature_of_an_older_generation_verifies_without_moving_the_pin() -> None:
    scope, payload = MessageSig(RECIPIENT), b"old"
    signature = sign_message(WORLD.keys(AGENT, 0).signing.private_key, scope, payload)
    server = KeyServer()
    server.publish(AGENT, 3)
    verdict = verify_envelope_sender_sync(
        make_kid(AGENT, 0),
        payload,
        signature,
        scope,
        server,
        AGENT,  # type: ignore[arg-type]
        SUPERSEDED_AT,
    )
    assert verdict.verification_status == "verified"
    assert server.key_pins._key_gens[AGENT] == 3


def test_a_kid_naming_a_generation_the_server_never_served_is_invalid() -> None:
    scope, payload = MessageSig(RECIPIENT), b"ahead"
    signature = sign_message(WORLD.keys(AGENT, 0).signing.private_key, scope, payload)
    verdict = verify_envelope_sender_sync(
        make_kid(AGENT, 1),
        payload,
        signature,
        scope,
        KeyServer(),
        AGENT,  # type: ignore[arg-type]
    )
    assert (verdict.verified, verdict.verification_status) == (False, "invalid")


def test_a_cached_key_that_a_newer_pin_has_outdated_is_read_fresh() -> None:
    server = KeyServer()
    get_agent_keys_sync(server, AGENT)  # type: ignore[arg-type]
    server.publish(AGENT, 2)
    fetch_recipient_keys_sync(server, AGENT)  # advances the pin past the cached generation
    keys, from_cache = get_agent_keys_sync(server, AGENT)  # type: ignore[arg-type]
    assert (keys.key_gen, from_cache) == (2, False)


# --- the branch escrow key -----------------------------------------------------------


def _own(world: World = WORLD, agent_id: str = AGENT) -> OwnIdentity:
    return OwnIdentity(
        org_id=world.org_id,
        agent_id=agent_id,
        agent_signing_public_key=world.keys(agent_id).signing.public_key,
        agent_certificate=world.keys_response(agent_id)["agent_certificate"],
    )


def test_the_own_branch_escrow_key_verifies() -> None:
    key = verify_branch_escrow_key(WORLD.escrow_response(), _own())
    assert key.x25519_public_key == WORLD.branch.escrow_x_pk
    assert key.ml_kem_public_key == WORLD.branch.escrow_kem_pk
    assert (key.org_id, key.branch) == (WORLD.org_id, WORLD.branch.name)


def _escrow_of_another_branch() -> dict[str, Any]:
    sibling = World(branch_name="fleet")
    return sibling.escrow_response()


def _escrow_key_substituted() -> dict[str, Any]:
    body = WORLD.escrow_response()
    body["escrow_public_key"] = to_base64url(OTHER_WORLD.branch.escrow_x_pk)
    return body


def _escrow_pq_key_substituted() -> dict[str, Any]:
    body = WORLD.escrow_response()
    body["escrow_pq_public_key"] = to_base64url(OTHER_WORLD.branch.escrow_kem_pk)
    return body


def _escrow_of_another_org() -> dict[str, Any]:
    return OTHER_WORLD.escrow_response()


def _escrow_without_certificate() -> dict[str, Any]:
    body = WORLD.escrow_response()
    del body["branch_certificate"]
    return body


@pytest.mark.parametrize(
    "response",
    [
        _escrow_of_another_branch,
        _escrow_key_substituted,
        _escrow_pq_key_substituted,
        _escrow_of_another_org,
        _escrow_without_certificate,
    ],
)
def test_a_substituted_escrow_key_is_refused(response: Callable[[], dict[str, Any]]) -> None:
    with pytest.raises(EscrowKeyError, match=ESCROW_KEY_INVALID):
        verify_branch_escrow_key(response(), _own())


def test_an_escrow_key_is_refused_when_the_agent_cert_names_a_key_it_does_not_hold() -> None:
    own = replace(_own(), agent_signing_public_key=WORLD.keys(RECIPIENT).signing.public_key)
    with pytest.raises(EscrowKeyError, match=ESCROW_KEY_INVALID):
        verify_branch_escrow_key(WORLD.escrow_response(), own)


def test_an_escrow_key_is_refused_when_the_agent_cert_names_another_agent_id() -> None:
    own = replace(_own(), agent_id=RECIPIENT)
    with pytest.raises(EscrowKeyError, match=ESCROW_KEY_INVALID):
        verify_branch_escrow_key(WORLD.escrow_response(), own)


def test_an_escrow_key_is_refused_when_the_local_agent_cert_is_another_orgs() -> None:
    """The org id and cert are held locally, so a response cannot supply a matching pair."""
    own = replace(_own(), agent_certificate=_own(OTHER_WORLD).agent_certificate)
    with pytest.raises(EscrowKeyError, match=ESCROW_KEY_INVALID):
        verify_branch_escrow_key(WORLD.escrow_response(), own)
