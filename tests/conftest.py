"""Shared fixtures for rine SDK tests."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass

import pytest

from rine._crypto.certs import VerifiedAgentKeys
from rine._crypto.escrow_key import VerifiedEscrowKey
from rine._crypto.keys import AgentKeys, save_agent_keys
from rine.testing import WORLD
from tests.vote_world import seat_calls  # noqa: F401  (a shared fixture)


def recipient_view(keys: AgentKeys, agent_id: str) -> VerifiedAgentKeys:
    """An agent's keys as a sender gets them: through the full certificate chain.

    The published response is minted from the same derived keys the agent holds,
    then verified like any peer's, so a test that seals to this view exercises
    what production seals to. ``keys`` must be the agent's own derived keys.
    """
    return WORLD.verified(agent_id, keys.key_gen)


@pytest.fixture
def mls_escrow_stub():
    """Take the MLS flows' escrow and peer-admission HTTP out of a test that is not about them.

    The escrow key resolves to the shared world's branch key, so the drain still
    seals and writes its pending files for real; the upload is accepted without a
    server, and the group tree read admits no further peers (every agent a flow
    test uses already has its keys in the config dir, so is in the seeded set).
    Patched through its own context, so a test's ``monkeypatch.undo()`` leaves it.
    """
    from rine._mls.tree import GroupTree

    key = VerifiedEscrowKey(
        org_id=WORLD.org_id,
        branch=WORLD.branch.name,
        x25519_public_key=WORLD.branch.escrow_x_pk,
        ml_kem_public_key=WORLD.branch.escrow_kem_pk,
    )
    uploads: list[tuple[str, int]] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("rine._mls.escrow_drain.resolve_escrow_key", lambda actor: key)
        patch.setattr("rine._mls.escrow_sweep.resolve_escrow_key", lambda actor: key)
        patch.setattr(
            "rine._mls.escrow_upload.upload_escrow",
            lambda client, agent_id, group_id, epoch, body: uploads.append((group_id, epoch)),
        )
        patch.setattr(
            "rine._mls.allowed.read_group_tree",
            lambda client, group_id, headers: GroupTree(member_ids=(), invited_ids=()),
        )
        yield uploads


@pytest.fixture
def real_roster_read(mls_escrow_stub):
    """Undo the escrow stub's empty roster read, for a module about that read.

    ``mls_escrow_stub`` replaces ``rine._mls.allowed.read_group_tree`` with an
    empty tree so unrelated flows admit no peers. A test of the admission
    classification or of a Welcome naming members the roster read must see the real
    one; the escrow half of the stub stays in place. Patched through its own
    context, torn down before the stub's, so the stub never outlives the test.
    """
    from rine._mls import allowed, tree

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(allowed, "read_group_tree", tree.read_group_tree)
        yield


@pytest.fixture
def heartbeat_settles_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the heartbeat inside each sync from settling a rotation before the test does."""
    monkeypatch.setattr("rine._mls.heartbeat._settle_rotation_best_effort", lambda actor: None)


@pytest.fixture
def race(tmp_config_dir, monkeypatch):
    """ADMIN and PEER hold a group; PEER seats JOINER in the commit that wins the epoch race."""
    from tests.mls_race_world import race_world

    return race_world(tmp_config_dir, monkeypatch)


@pytest.fixture
def escrow_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every settle and drain the MLS replace and wipe sites make, in order, as (what, group id).

    The real functions still run. Only the sites' own references are wrapped, so
    the settle's inner drain is not recorded: an entry is a decision a site made.
    """
    from rine._mls import escrow_drain, escrow_settle

    calls: list[tuple[str, str]] = []

    def spy(name: str, real):
        def wrapper(actor, group_id, *rest, **options):
            calls.append((name, group_id))
            return real(actor, group_id, *rest, **options)

        return wrapper

    settle = spy("settle", escrow_settle.settle_escrow)
    drain = spy("drain", escrow_drain.drain_escrow)
    for module in ("_mls.resync", "_mls.external_join", "_mls.welcome_install", "_recover_reseat"):
        monkeypatch.setattr(f"rine.{module}.settle_escrow", settle)
        monkeypatch.setattr(f"rine.{module}.drain_escrow", drain)
    monkeypatch.setattr("rine._mls.leave.settle_escrow", settle)
    return calls


def sender_key_region_is_held_here(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether THIS thread holds one group's sender-key state file right now.

    The exclusion those regions buy is invisible in the state file: a write made
    inside one and a write made outside it leave identical bytes, and the loss
    they prevent needs a second writer landing in a window a test cannot open at
    every site. So the assertion has to be made while the site is mid-write —
    every caller of this patches the writer that site calls and asks from
    inside it.

    🔴 It asks who holds the lock, not merely whether it is held. "Somebody is
    inside a region" passes just as well when the site under test writes OUTSIDE
    its region while an unrelated holder happens to be inside one, which is the
    defect shape itself. Both tiers of
    :mod:`rine._crypto.sender_keys_thread_lock` record the holder, so one check
    covers a coroutine's region and a worker thread's alike — and for a
    coroutine that is exact rather than lucky, because the loop thread is the
    one running the write.
    """
    from rine._crypto import sender_keys_store, sender_keys_thread_lock

    key = sender_keys_store._file_key(config_dir, agent_id, group_id)
    entry = sender_keys_thread_lock._thread_locks.get(key)
    return entry is not None and entry.lock.locked() and entry.owner == threading.get_ident()


def signing_fingerprint(keys) -> str:
    """Fingerprint a keypair's signing key from its raw bytes.

    Derived straight from the 32 key bytes rather than through the SDK helper,
    so a test asserting a reported fingerprint checks the value and not just
    that the implementation agrees with itself.
    """
    return hashlib.sha256(keys.signing.public_key).hexdigest()


@pytest.fixture(autouse=True)
def _no_ambient_acting_agent(monkeypatch):
    """Keep the developer's own ``RINE_AGENT`` out of every test in this package.

    The client constructor reads it (rung 3 of the ladder), so a machine that
    exports one would silently give every client an actor the test never asked
    for. A test that wants the env rung sets it itself, after this has run.
    """
    monkeypatch.delenv("RINE_AGENT", raising=False)


@pytest.fixture(autouse=True)
def _isolated_owner_dir(monkeypatch, tmp_path_factory):
    """Point ``RINE_OWNER_DIR`` at an empty dir, so no test reads or writes the real one."""
    monkeypatch.setenv("RINE_OWNER_DIR", str(tmp_path_factory.mktemp("owner")))


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Provide a temporary config directory."""
    return str(tmp_path)


@pytest.fixture
def agent_keys(agent_id):
    """The derived leaf keys of the fixed agent."""
    return WORLD.keys(agent_id)


@pytest.fixture
def agent_id():
    """Provide a fixed agent UUID."""
    return "00000000-1111-2222-3333-444444444444"


@pytest.fixture
def other_agent_id():
    """Provide a second fixed agent UUID."""
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def saved_agent_keys(tmp_config_dir, agent_id, agent_keys):
    """Save agent keys to disk and return them."""
    save_agent_keys(tmp_config_dir, agent_id, agent_keys)
    return agent_keys


@pytest.fixture
def sync_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured SyncRineClient with a saved agent profile and keys."""
    from rine import SyncRineClient
    from rine.testing import write_agent_identity

    write_agent_identity(tmp_config_dir, agent_id)

    client = SyncRineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    yield client
    client.close()


@pytest.fixture
def async_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured RineClient with a saved agent profile and keys."""
    from rine import RineClient
    from rine.testing import write_agent_identity

    write_agent_identity(tmp_config_dir, agent_id)

    client = RineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    return client


# --- Cold sender-key group message (shared by the sync and async receive tests) ---

_API_URL = "https://rine.network"
_GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_GROUP_MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000101"
_DISTRIBUTION_ID = "cccccccc-dddd-eeee-ffff-000000000102"


@dataclass(frozen=True)
class GroupMessageFixture:
    """A sender-key group message the recipient cannot open yet.

    Reproduces the live cold-group case: a foreign agent sealed a group message
    with a sender key the recipient has never ingested, and the matching
    distribution DM is still sitting unread on the server.
    """

    group_id: str
    sender_id: str
    message_id: str
    plaintext: str
    message_row: dict
    distribution_row: dict
    sender_key_jwks: dict


@pytest.fixture
def group_message_fixture(tmp_config_dir, agent_id, other_agent_id, saved_agent_keys):
    """Build a cold sender-key group message plus its distribution DM."""
    from rine._constants import MessageType
    from rine._crypto.keys import load_agent_keys
    from rine._crypto.message import encrypt_group_message, encrypt_message
    from rine._crypto.sender_keys import generate_sender_key
    from rine._crypto.sender_keys_helpers import save_sender_key_state
    from rine._utils import to_base64url

    save_agent_keys(tmp_config_dir, other_agent_id, WORLD.keys(other_agent_id))

    state = generate_sender_key(_GROUP_ID, other_agent_id)
    distribution_payload = {
        "group_id": _GROUP_ID,
        "sender_key_id": state.sender_key_id,
        "chain_key": to_base64url(state.chain_key),
        "message_index": state.message_index,
        "sender_agent_id": other_agent_id,
    }

    payload = {"text": "hello group"}
    # The sender's own copy, which ``encrypt_group_message`` advances in place. A
    # stand-in sender needs it as much as a real one does: the tail refuses a state
    # that is on no disk at all rather than discarding the advance.
    save_sender_key_state(tmp_config_dir, other_agent_id, _GROUP_ID, [state])
    sealed, _ = encrypt_group_message(tmp_config_dir, other_agent_id, _GROUP_ID, state, payload)

    recipient = recipient_view(load_agent_keys(tmp_config_dir, agent_id), agent_id)
    distribution = encrypt_message(tmp_config_dir, other_agent_id, recipient, distribution_payload)

    def _row(message_id: str, msg_type: str, result, **extra) -> dict:
        return {
            "id": message_id,
            "conversation_id": "cccccccc-dddd-eeee-ffff-000000000103",
            "from_agent_id": other_agent_id,
            "to_agent_id": agent_id,
            "type": msg_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
            "created_at": "2024-01-01T00:00:00Z",
            **extra,
        }

    return GroupMessageFixture(
        group_id=_GROUP_ID,
        sender_id=other_agent_id,
        message_id=_GROUP_MESSAGE_ID,
        plaintext=json.dumps(payload, separators=(",", ":")),
        message_row=_row(
            _GROUP_MESSAGE_ID,
            MessageType.TASK_REQUEST,
            sealed,
            group_id=_GROUP_ID,
            to_agent_id=None,
        ),
        distribution_row=_row(_DISTRIBUTION_ID, MessageType.SENDER_KEY_DISTRIBUTION, distribution),
        sender_key_jwks=WORLD.keys_response(other_agent_id),
    )


@pytest.fixture
def mock_group_message_routes(group_message_fixture, agent_id):
    """Return a callable registering every route the cold-group flow needs.

    Call it from inside the test's ``respx.mock`` context — respx routes cannot
    be registered during fixture setup, which runs before the mock is active.
    """
    import httpx
    import respx

    from rine._constants import MessageType

    fx = group_message_fixture

    def _register() -> None:
        respx.post(f"{_API_URL}/oauth/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "test-token", "expires_in": 900}
            )
        )
        respx.get(f"{_API_URL}/agents").mock(
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
        respx.get(f"{_API_URL}/agents/{fx.sender_id}/keys").mock(
            return_value=httpx.Response(200, json=fx.sender_key_jwks)
        )
        # Registered before the unfiltered inbox route: respx matches in
        # registration order, and both share the same path.
        respx.get(
            f"{_API_URL}/agents/{agent_id}/messages",
            params={"type": MessageType.SENDER_KEY_DISTRIBUTION},
        ).mock(
            return_value=httpx.Response(200, json={"items": [{"id": fx.distribution_row["id"]}]})
        )
        respx.get(f"{_API_URL}/messages/{fx.distribution_row['id']}").mock(
            return_value=httpx.Response(200, json=fx.distribution_row)
        )
        respx.get(f"{_API_URL}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{_API_URL}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": [fx.message_row], "total": 1})
        )

    return _register
