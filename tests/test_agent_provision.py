"""Agent create and rotate through the public client.

The client mints the agent id, derives its keys from the org root (or a
delegate's branch files), signs its certificate with the branch key and sends
only the public halves. These tests drive the real derivation and the real
certificate chain — only the server is mocked.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
import respx

from rine import SyncRineClient
from rine._agent_provision import create_agent
from rine._crypto.certs import ChainError
from rine._crypto.derive_nodes import derive_branch
from rine._crypto.jws import JwsTyp, verify_jws
from rine._crypto.keys import load_agent_keys, save_agent_keys
from rine._custody import local_agent_ids
from rine._owner import resolve_owner_dir
from rine._profiles import get_profile
from rine._utils import to_base64url
from rine.errors import AgentIdMismatchError, ConfigError, ConflictError
from rine.testing import WORLD, World, write_owner
from tests.identity import echo_created_agent

API = "https://rine.network"


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _mock_create() -> respx.Route:
    return respx.post(f"{API}/agents").mock(side_effect=echo_created_agent)


def _mock_mls_upload() -> respx.Route:
    """The best-effort KeyPackage top-up create runs; unmocked it would fail noisily."""
    return respx.post(url__regex=rf"{API}/agents/[0-9a-f-]{{36}}/mls/key-packages").mock(
        return_value=httpx.Response(201, json={"stored": 16})
    )


def _agent_body(agent_id: str) -> dict:
    return {
        "id": agent_id,
        "name": "test-agent",
        "handle": "test-agent@myorg.rine.network",
        "human_oversight": True,
        "incoming_policy": "accept_all",
        "outgoing_policy": "send_all",
        "created_at": "2024-01-01T00:00:00Z",
    }


def _created_body(route: respx.Route) -> dict:
    return json.loads(route.calls.last.request.content)


def _assert_public_keys_match(body: dict, agent_id: str, gen: int) -> None:
    node = WORLD.node(agent_id, gen)
    assert body["signing_public_key"]["x"] == to_base64url(node.ed_pk)
    assert body["encryption_public_key"]["x"] == to_base64url(node.x_pk)
    assert body["pq_encryption_public_key"]["x"] == to_base64url(node.kem_pk)
    assert body["pq_signing_public_key"]["x"] == to_base64url(node.dsa_pk)
    assert body["mls_signing_public_key"]["x"] == to_base64url(node.mls_pk)


@respx.mock
def test_create_agent_when_org_root_held_then_posts_derived_keys_and_cert(sync_client):
    """The client mints the id and derives generation-0 keys before the server sees it."""
    write_owner(resolve_owner_dir())
    _mock_token()
    created = _mock_create()
    _mock_mls_upload()

    sync_client.create_agent("fresh", human_oversight=False, unlisted=True)

    body = _created_body(created)
    agent_id = body["id"]
    assert str(uuid.UUID(agent_id)) == agent_id
    assert body["name"] == "fresh"
    assert body["branch"] == "main"
    assert body["human_oversight"] is False
    assert body["unlisted"] is True

    claims = verify_jws(body["agent_certificate"], WORLD.branch.ed_pk, JwsTyp.AGENT_CERT)
    assert claims["agent"] == agent_id
    assert claims["gen"] == 0
    assert claims["org"] == WORLD.org_id
    assert claims["branch"] == "main"

    _assert_public_keys_match(body, agent_id, 0)


@respx.mock
def test_create_agent_when_the_server_answers_another_id_then_refuses_and_writes_nothing(tmp_path):
    """The certificate is bound to the minted id: an agent under another id gets no keys."""
    write_owner(resolve_owner_dir())
    _mock_token()
    other_id = str(uuid.uuid4())

    def _wrong_id(request: httpx.Request) -> httpx.Response:
        echoed = echo_created_agent(request)
        return httpx.Response(201, json={**json.loads(echoed.content), "id": other_id})

    created = respx.post(f"{API}/agents").mock(side_effect=_wrong_id)
    config_dir = str(tmp_path)
    client = SyncRineClient(config_dir=config_dir, api_url=API)
    try:
        with pytest.raises(AgentIdMismatchError) as caught:
            client.create_agent("fresh")
    finally:
        client.close()

    minted_id = _created_body(created)["id"]
    assert (caught.value.minted_id, caught.value.server_id) == (minted_id, other_id)
    assert local_agent_ids(config_dir) == []
    assert get_profile(config_dir) is None


@respx.mock
def test_create_agent_when_accepted_then_saves_leaf_keys_and_names_profile(tmp_path):
    """The leaf keys land on disk and the new agent is named in the default profile."""
    write_owner(resolve_owner_dir())
    _mock_token()
    created = _mock_create()
    _mock_mls_upload()
    config_dir = str(tmp_path)
    client = SyncRineClient(config_dir=config_dir, api_url=API)
    try:
        client.create_agent("fresh")
    finally:
        client.close()

    agent_id = _created_body(created)["id"]
    keys = load_agent_keys(config_dir, agent_id)
    assert keys.signing.private_key == WORLD.keys(agent_id).signing.private_key

    profile = get_profile(config_dir)
    assert profile is not None
    assert profile["principal"] == f"agent:{agent_id}"
    assert profile["org_id"] == WORLD.org_id
    assert profile["branch"] == "main"
    assert profile["agent_id"] == agent_id


@respx.mock
def test_create_agent_when_default_profile_exists_then_keeps_the_first_agent(tmp_path):
    """``add_profile_if_absent`` semantics: a taken name is never overwritten."""
    write_owner(resolve_owner_dir())
    _mock_token()
    created = _mock_create()
    _mock_mls_upload()
    config_dir = str(tmp_path)
    client = SyncRineClient(config_dir=config_dir, api_url=API)
    try:
        client.create_agent("first")
        first_id = _created_body(created)["id"]
        client.create_agent("second")
    finally:
        client.close()

    profile = get_profile(config_dir)
    assert profile is not None
    assert profile["agent_id"] == first_id


@respx.mock
def test_create_agent_when_no_key_material_then_raises_and_posts_nothing(sync_client):
    """No root and no branch files: a clean refusal, and the server is never called."""
    _mock_token()
    created = _mock_create()

    with pytest.raises(ConfigError, match="No key material"):
        sync_client.create_agent("fresh")

    assert created.call_count == 0


@respx.mock
def test_create_agent_when_branch_is_research_then_signs_with_that_branch(
    sync_client, tmp_config_dir
):
    """A non-default branch derives its own keys and signs with its own branch key."""
    write_owner(resolve_owner_dir())
    _mock_token()
    created = _mock_create()
    _mock_mls_upload()

    create_agent(
        sync_client._http,
        tmp_config_dir,
        resolve_owner_dir(),
        "researcher",
        branch="research",
    )

    body = _created_body(created)
    research = derive_branch(WORLD.org.r_read, WORLD.org.r_sign, "research")
    claims = verify_jws(body["agent_certificate"], research.ed_pk, JwsTyp.AGENT_CERT)
    assert claims["branch"] == "research"
    assert body["branch"] == "research"


@respx.mock
def test_create_agent_when_server_conflicts_then_raises_and_writes_nothing(tmp_path):
    """A rejected create leaves no leaf keys and no profile behind."""
    write_owner(resolve_owner_dir())
    _mock_token()
    respx.post(f"{API}/agents").mock(
        return_value=httpx.Response(409, json={"detail": "Agent name taken"})
    )
    _mock_mls_upload()
    config_dir = str(tmp_path)
    client = SyncRineClient(config_dir=config_dir, api_url=API)
    try:
        with pytest.raises(ConflictError):
            client.create_agent("dup")
    finally:
        client.close()

    assert get_profile(config_dir) is None
    assert local_agent_ids(config_dir) == []


@respx.mock
def test_rotate_keys_when_at_generation_zero_then_posts_generation_one(
    sync_client, tmp_config_dir, agent_id
):
    """Rotate reads the current generation and posts the next one, keys and cert alike."""
    write_owner(resolve_owner_dir())
    _mock_token()
    respx.get(f"{API}/agents/{agent_id}/keys").mock(
        return_value=httpx.Response(200, json=WORLD.keys_response(agent_id, 0))
    )
    posted = respx.post(f"{API}/agents/{agent_id}/keys").mock(
        return_value=httpx.Response(200, json=_agent_body(agent_id))
    )

    sync_client.rotate_keys(agent_id)

    body = _created_body(posted)
    assert body["key_gen"] == 1
    claims = verify_jws(body["agent_certificate"], WORLD.branch.ed_pk, JwsTyp.AGENT_CERT)
    assert claims["gen"] == 1
    _assert_public_keys_match(body, agent_id, 1)

    keys = load_agent_keys(tmp_config_dir, agent_id)
    assert keys.signing.private_key == WORLD.keys(agent_id, 1).signing.private_key


def _mock_rotation_world(agent_id: str, served: dict) -> respx.Route:
    """Serve ``served`` as the agent's key read; return the route a rotation would post to."""
    write_owner(resolve_owner_dir())
    _mock_token()
    respx.get(f"{API}/agents/{agent_id}/keys").mock(return_value=httpx.Response(200, json=served))
    return respx.post(f"{API}/agents/{agent_id}/keys").mock(
        return_value=httpx.Response(500, json={"detail": "must not be reached"})
    )


@respx.mock
def test_rotate_keys_when_the_key_read_does_not_chain_then_refuses_before_signing(
    sync_client, tmp_config_dir, agent_id
):
    """A key read the org never certified names neither a branch nor a generation to sign."""
    posted = _mock_rotation_world(agent_id, {"branch": "main", "key_gen": 0})

    with pytest.raises(ChainError):
        sync_client.rotate_keys(agent_id)

    assert not posted.called


@respx.mock
def test_rotate_keys_when_the_read_swaps_the_branch_then_refuses_before_signing(
    sync_client, tmp_config_dir, agent_id
):
    """The new certificate's branch comes from the verified chain, not the server's say-so."""
    served = {**WORLD.keys_response(agent_id, 0), "branch": "elsewhere"}
    posted = _mock_rotation_world(agent_id, served)

    with pytest.raises(ChainError):
        sync_client.rotate_keys(agent_id)

    assert not posted.called


@respx.mock
def test_rotate_keys_when_the_read_chains_to_another_org_then_refuses_before_signing(sync_client):
    """A validly certified chain of a foreign org is not this org's agent to rotate.

    The agent holds no keys here, so nothing pins it to an org: only the comparison
    against this device's custody can refuse it.
    """
    agent_id = str(uuid.uuid4())
    foreign = World(root=bytes([7] * 32))
    posted = _mock_rotation_world(agent_id, foreign.keys_response(agent_id, 0))

    with pytest.raises(ChainError, match="not to this device's org"):
        sync_client.rotate_keys(agent_id)

    assert not posted.called


@respx.mock
def test_rotate_keys_when_the_server_reports_an_older_generation_than_held_then_refuses(
    sync_client, tmp_config_dir, agent_id
):
    """A rolled-back answer must not make the client re-certify a superseded generation."""
    save_agent_keys(tmp_config_dir, agent_id, WORLD.keys(agent_id, 3))
    posted = _mock_rotation_world(agent_id, WORLD.keys_response(agent_id, 1))

    with pytest.raises(ChainError, match="older"):
        sync_client.rotate_keys(agent_id)

    assert not posted.called
    assert load_agent_keys(tmp_config_dir, agent_id).key_gen == 3


@respx.mock
def test_rotate_keys_when_the_server_matches_the_held_generation_then_rotates_to_the_next(
    sync_client, tmp_config_dir, agent_id
):
    """The false-positive guard: an honest answer at the held generation rotates."""
    save_agent_keys(tmp_config_dir, agent_id, WORLD.keys(agent_id, 3))
    _mock_rotation_world(agent_id, WORLD.keys_response(agent_id, 3))
    respx.post(f"{API}/agents/{agent_id}/keys").mock(
        return_value=httpx.Response(200, json=_agent_body(agent_id))
    )

    sync_client.rotate_keys(agent_id)

    assert load_agent_keys(tmp_config_dir, agent_id).key_gen == 4


@respx.mock
async def test_async_create_agent_when_org_root_held_then_posts_derived_keys_and_cert(
    async_client,
):
    """The async client derives and posts exactly what the sync one does."""
    write_owner(resolve_owner_dir())
    _mock_token()
    created = _mock_create()
    _mock_mls_upload()

    await async_client.create_agent("fresh", human_oversight=False, unlisted=True)

    body = _created_body(created)
    agent_id = body["id"]
    assert str(uuid.UUID(agent_id)) == agent_id
    assert body["name"] == "fresh"
    assert body["branch"] == "main"
    assert body["human_oversight"] is False
    assert body["unlisted"] is True

    claims = verify_jws(body["agent_certificate"], WORLD.branch.ed_pk, JwsTyp.AGENT_CERT)
    assert claims["agent"] == agent_id
    assert claims["gen"] == 0
    assert claims["org"] == WORLD.org_id
    assert claims["branch"] == "main"

    _assert_public_keys_match(body, agent_id, 0)
    await async_client.close()


@respx.mock
def test_fetch_agents_when_server_lists_a_foreign_agent_then_it_is_not_pinned_as_own(sync_client):
    """Which agents are ours is decided by the keys held locally, never by the server's listing."""
    foreign = "ffffffff-1111-2222-3333-444444444444"
    _mock_token()
    respx.get("https://rine.network/agents").mock(
        return_value=httpx.Response(200, json=[{"id": foreign, "name": "x"}])
    )

    sync_client._fetch_agents()

    assert sync_client._http.key_pins.own_org_of(foreign) is None
