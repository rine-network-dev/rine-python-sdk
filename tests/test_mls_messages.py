"""MLS sending and reading: the real crypto, only the server mocked.

Every group here is founded by a real second client through the same Rust core
the TypeScript stack binds, so a ciphertext asserted on is one the CLI would
produce, and a plaintext asserted on is one it would read.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from rine._constants import EncryptionVersion
from rine._crypto.group_read_cache import delete_group_read_cache
from rine._crypto.keys import make_kid, save_agent_keys
from rine._crypto.sender_keys_helpers import mark_sender_keys_retired
from rine._mls import (
    APP_MESSAGE_TAG,
    DEFAULT_CIPHER_SUITE,
    decrypt_mls_group_message,
    encrypt_mls_group_message,
    is_recoverable_mls_failure,
    is_unprocessable_commit,
    load_mls_group,
    mls_group_id_bytes,
    open_mls_client,
    process_mls_welcomes,
    publish_mls_key_packages,
    sync_mls_group,
)
from rine._mls.binding import (
    MlsStoreError,
    SelfMessageNotCachedError,
    credential_identity,
    local_allowed_identities,
)
from rine._mls.escrow_head import read_head
from rine._mls.failures import mls_boundary
from rine._mls.heartbeat import reset_mls_heartbeat_gate
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError, NoMlsGroupStateError, SenderMismatchError
from rine.testing import WORLD, write_agent_identity
from rine.types import GroupRead
from tests.conftest import signing_fingerprint

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
WELCOME_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
HANDSHAKE_ID = "55555555-6666-7777-8888-999999999999"
MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000001"
SECOND_MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000003"
CONVERSATION_ID = "cccccccc-dddd-eeee-ffff-000000000002"
IMPOSTOR_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"

_GROUP_JSON = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": "99999999-0000-1111-2222-333333333333",
    "mls_pending": False,
    "mls_cipher_suite": DEFAULT_CIPHER_SUITE,
}
GROUP = GroupRead.model_validate(_GROUP_JSON)


# --------------------------------------------------------------------------
# a real peer, and the server routes the flows touch
# --------------------------------------------------------------------------


class Peer:
    """A second real MLS client — the founder, and the far end of interop.

    ``also`` names every other agent this peer will seat or read from: the core
    refuses a leaf whose ``(agent id, leaf key)`` pair is outside the client's
    allowed set, which is every agent whose keys live in its config dir.
    """

    def __init__(self, tmp_path, agent_id: str, *also: str, gen: int = 0) -> None:
        self.agent_id = agent_id
        self.config_dir = str(tmp_path / f"peer-{agent_id}")
        self.keys = WORLD.keys(agent_id, gen)
        save_agent_keys(self.config_dir, agent_id, self.keys)
        for other in also:
            save_agent_keys(self.config_dir, other, WORLD.keys(other))
        self.allowed = local_allowed_identities(self.config_dir)
        self.client = open_mls_client(self.config_dir, agent_id, allowed=self.allowed)
        self.group = None

    def admit(self, newcomer: Peer) -> None:
        """Add a later joiner's (agent id, leaf key) pair to this peer's allowed set."""
        self.allowed.insert(credential_identity(newcomer.agent_id), newcomer.keys.mls.public_key, 0)

    def found(self, *key_packages: bytes):
        """Found the group, admitting each supplied KeyPackage."""
        self.group = self.client.create_group_with_members(
            mls_group_id_bytes(GROUP_ID), list(key_packages)
        )
        self.group.save()
        return self.group.last_commit()

    def add(self, key_package: bytes):
        bundle = self.group.add_member(key_package)
        self.group.save()
        return bundle

    def send(self, payload: object) -> str:
        """Encrypt as this peer would, through the SDK's own send path."""
        result = encrypt_mls_group_message(
            _NoServer(), self.config_dir, self.agent_id, GROUP, payload
        )
        return result.encrypted_payload

    def read(self, client, encrypted_payload: str, sender_id: str):
        return decrypt_mls_group_message(
            client, self.config_dir, self.agent_id, GROUP_ID, encrypted_payload, sender_id
        )


class _NoServer:
    """Stands in for a peer's HTTP client when no server exists for it.

    The encrypt itself is pure local crypto; the pre-send sync around it is
    best-effort by design, so it degrades to a no-op here rather than failing
    the send. That degradation is exactly what this asserts.
    """

    def get(self, *_a, **_k):
        raise ConnectionError("this peer has no server")

    def post(self, *_a, **_k):
        raise ConnectionError("this peer has no server")


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _mock_keys(*peers) -> None:
    """Serve each peer's published keys so the inner envelope can be verified."""
    for peer in peers:
        respx.get(f"{API}/agents/{peer.agent_id}/keys").mock(
            return_value=httpx.Response(
                200, json=WORLD.keys_response(peer.agent_id, peer.keys.key_gen)
            )
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


def _mock_no_handshakes() -> respx.Route:
    return respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
        return_value=httpx.Response(200, json={"handshakes": []})
    )


def _mock_groups_by_equality() -> None:
    """Route ``GET /groups`` the way the server routes it: the filter is EQUALITY.

    🔴 The filtering is the whole point, and a mock that answers every
    ``?handle=`` with the group it holds is the shape that made this bug
    invisible: the exact rung appears to answer, so nothing ever reaches the
    fallback rung and nothing ever posts a spelling the server would refuse.
    """

    def answer(request: httpx.Request) -> httpx.Response:
        wanted = request.url.params.get("handle")
        items = [g for g in [_GROUP_JSON] if wanted is None or g["handle"] == wanted]
        return httpx.Response(200, json={"items": items})

    respx.get(f"{API}/groups").mock(side_effect=answer)


def _mock_posted_message(agent_id: str) -> respx.Route:
    """Accept ``POST /messages`` and hand back a plausible group row."""
    return respx.post(f"{API}/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": MESSAGE_ID,
                "conversation_id": CONVERSATION_ID,
                "from_agent_id": agent_id,
                "group_id": GROUP_ID,
                "type": "rine.v1.task_request",
                "encrypted_payload": "x",
                "encryption_version": EncryptionVersion.MLS_V1,
                "sender_signing_kid": make_kid(agent_id, 0),
                "created_at": "2024-01-01T00:00:00Z",
            },
        )
    )


def _mock_handshakes(*commits: bytes) -> respx.Route:
    """Serve commits once, then nothing — as the server does past our epoch."""
    payload = {
        "handshakes": [
            {
                "id": f"{HANDSHAKE_ID[:-1]}{i}",
                "epoch": None,
                "blob": base64.b64encode(c).decode("ascii"),
                "created_at": "2024-01-01T00:00:00Z",
            }
            for i, c in enumerate(commits)
        ]
    }
    return respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
        side_effect=[
            httpx.Response(200, json=payload),
            *[httpx.Response(200, json={"handshakes": []}) for _ in range(9)],
        ]
    )


def _mock_ack() -> respx.Route:
    return respx.post(f"{API}/groups/{GROUP_ID}/mls/ack").mock(
        return_value=httpx.Response(200, json={"confirmed": True, "acks": 1, "needed": 1})
    )


def _mock_nack() -> respx.Route:
    return respx.post(f"{API}/groups/{GROUP_ID}/mls/nack").mock(
        return_value=httpx.Response(200, json={"quarantined": True})
    )


def _mock_group() -> respx.Route:
    return respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_GROUP_JSON)
    )


def _mock_welcomes(agent_id: str, *blobs: bytes) -> respx.Route:
    payloads = [
        {
            "id": WELCOME_ID,
            "group_id": GROUP_ID,
            "blob": base64.b64encode(b).decode("ascii"),
            "created_at": "2024-01-01T00:00:00Z",
        }
        for b in blobs
    ]
    return respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
        side_effect=[
            httpx.Response(200, json={"welcomes": payloads}),
            *[httpx.Response(200, json={"welcomes": []}) for _ in range(9)],
        ]
    )


def _mint_key_package(sync_client, config_dir: str, agent_id: str) -> bytes:
    """Publish this agent's pool and hand back one blob, as a peer would claim it."""
    route = respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(201, json={"stored": 10})
    )
    publish_mls_key_packages(sync_client._http, config_dir, agent_id)
    return base64.b64decode(
        json.loads(route.calls[0].request.content)["packages"][0], validate=True
    )


def _mls_row(ciphertext: str, sender_id: str) -> dict:
    """One ``mls-v1`` group row, shaped as the server serves it."""
    return {
        "id": MESSAGE_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": sender_id,
        "group_id": GROUP_ID,
        "type": "rine.v1.task_request",
        "encrypted_payload": ciphertext,
        "encryption_version": EncryptionVersion.MLS_V1,
        "sender_signing_kid": make_kid(sender_id, 0),
        "created_at": "2024-01-01T00:00:00Z",
    }


def _serve_honestly_then_renamed(row: dict) -> None:
    """Serve one row as its own sender's, then the same id as another agent's."""
    renamed = {
        **row,
        "from_agent_id": IMPOSTOR_ID,
        "sender_signing_kid": make_kid(IMPOSTOR_ID, 0),
    }
    respx.get(f"{API}/messages/{row['id']}").mock(
        side_effect=[
            httpx.Response(200, json=row),
            httpx.Response(200, json=renamed),
        ]
    )


def _mock_message_routes(agent_id: str, row: dict) -> None:
    """Serve one row on every receive surface: inbox page, read-by-id, thread."""
    respx.get(f"{API}/messages/{row['id']}").mock(return_value=httpx.Response(200, json=row))
    respx.get(f"{API}/agents/{agent_id}/messages").mock(
        return_value=httpx.Response(200, json={"items": [row], "total": 1})
    )
    respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": [row], "truncated": False})
    )


def _join_group(sync_client, config_dir: str, agent_id: str, peer: Peer) -> None:
    """Get the agent under test into a group the peer founds."""
    _mock_token()
    save_agent_keys(config_dir, peer.agent_id, peer.keys)
    key_package = _mint_key_package(sync_client, config_dir, agent_id)
    bundle = peer.found(key_package)
    _mock_welcomes(agent_id, bundle.welcomes[0])
    process_mls_welcomes(sync_client._http, config_dir, agent_id)


def _decrypt(sync_client, config_dir: str, agent_id: str, ciphertext: str, sender_id: str):
    """Read one MLS row BELOW the client, so no in-process memo can answer it."""
    return decrypt_mls_group_message(
        sync_client._http, config_dir, agent_id, GROUP_ID, ciphertext, sender_id
    )


# --------------------------------------------------------------------------


class TestRoundTrip:
    @respx.mock
    def test_a_peers_message_is_read_with_its_exact_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        payload = {"task": "summarize", "note": "unicode ✓ and a quote \\"}

        ciphertext = peer.send(payload)
        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext, other_agent_id
        )

        assert json.loads(result.plaintext) == payload
        assert result.verified is True
        assert result.verification_status == "verified"
        assert result.sender_kid == make_kid(other_agent_id, 0)

    @respx.mock
    def test_our_message_is_read_by_the_peer_with_its_exact_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys
    ):
        """The other direction: what this SDK sends, a different client reads."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(agent_id))
        )
        payload = {"reply": "read back by a different client"}

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, payload
        )
        result = peer.read(sync_client._http, sent.encrypted_payload, agent_id)

        assert json.loads(result.plaintext) == payload
        assert result.verified is True
        assert sent.encryption_version == EncryptionVersion.MLS_V1

    @respx.mock
    def test_the_payload_is_base64url_of_the_cores_own_version_tag(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The wire shape, read off the bytes rather than asserted from a constant."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"a": 1}
        )

        assert from_base64url(sent.encrypted_payload)[0] == APP_MESSAGE_TAG
        assert sent.sender_signing_kid == make_kid(agent_id, 0)

    @respx.mock
    def test_the_send_carries_the_escrow_fp_of_the_epoch_it_sealed_under(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The server refuses an mls-v1 post without it."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"a": 1}
        )

        head = read_head(tmp_config_dir, agent_id, str(GROUP.id))
        assert head is not None
        assert sent.escrow_fp == to_base64url(head.fp)


class TestSelfRead:
    @respx.mock
    def test_a_sender_reads_its_own_message_back(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys
    ):
        """Forward secrecy consumed the sender's ratchet step; the core's cache answers.

        There is no Python-side self-read mechanism — this passes only because
        the cache lives in the Rust core, keyed on the framed payload bytes, the
        one representation both stacks hold identically.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(agent_id))
        )
        payload = {"note": "a sender must be able to read its own thread"}

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, payload
        )
        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, sent.encrypted_payload, agent_id
        )

        assert json.loads(result.plaintext) == payload
        assert result.sender_kid == make_kid(agent_id, 0)

    def test_a_self_read_miss_is_never_retried(self):
        """Syncing cannot bring back a plaintext forward secrecy already consumed."""
        assert not is_recoverable_mls_failure(SelfMessageNotCachedError("aged out"))


class TestReadRecovery:
    @respx.mock
    def test_a_message_for_an_uninstalled_welcome_is_read_after_recovery(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The group was joined but the Welcome never processed — the read installs it."""
        _mock_token()
        peer = Peer(tmp_path, other_agent_id, agent_id)
        save_agent_keys(tmp_config_dir, other_agent_id, peer.keys)
        key_package = _mint_key_package(sync_client, tmp_config_dir, agent_id)
        bundle = peer.found(key_package)
        ciphertext = peer.send({"before": "you installed anything"})

        _mock_keys(peer)
        _mock_group()
        _mock_no_handshakes()
        welcomes = _mock_welcomes(agent_id, bundle.welcomes[0])
        assert load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID) is None

        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext, other_agent_id
        )

        assert json.loads(result.plaintext) == {"before": "you installed anything"}
        assert welcomes.called

    @respx.mock
    def test_an_unreachable_group_is_refused_by_name(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """No Welcome, no GroupInfo: recovery cannot invent state, and says which group."""
        _mock_token()
        peer = Peer(tmp_path, other_agent_id, agent_id)
        peer.found()
        ciphertext = peer.send({"not": "for you"})
        _mock_group()
        _mock_welcomes(agent_id)
        respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
        )

        with pytest.raises(Exception, match=GROUP_ID):
            decrypt_mls_group_message(
                sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext, other_agent_id
            )

    @respx.mock
    def test_a_message_naming_no_group_is_refused_without_touching_the_server(
        self, sync_client, tmp_config_dir, agent_id
    ):
        with pytest.raises(Exception, match="names no group"):
            decrypt_mls_group_message(
                sync_client._http, tmp_config_dir, agent_id, None, "BAAB", agent_id
            )


class TestSenderBinding:
    """The inner envelope must name the sender the server authenticated."""

    @respx.mock
    def test_a_message_attributed_to_another_agent_is_refused(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A peer's message re-posted under a third agent's name never opens.

        The refusal comes after the ratchet is persisted, deliberately: the
        message's one-time key is spent exactly as an honest message would spend
        it, so re-posting the same ciphertext is not a way to retry.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_group()
        _mock_no_handshakes()
        ciphertext = peer.send({"text": "the codeword is albatross"})

        with pytest.raises(SenderMismatchError):
            decrypt_mls_group_message(
                sync_client._http,
                tmp_config_dir,
                agent_id,
                GROUP_ID,
                ciphertext,
                IMPOSTOR_ID,
            )

        with pytest.raises(CryptoError):
            decrypt_mls_group_message(
                sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext, other_agent_id
            )

    @respx.mock
    def test_the_same_message_attributed_to_its_sender_reads(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The false-positive guard for the refusal above."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_no_handshakes()
        ciphertext = peer.send({"text": "the codeword is albatross"})

        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext, other_agent_id
        )

        assert json.loads(result.plaintext) == {"text": "the codeword is albatross"}
        assert result.verified is True
        assert result.verification_status == "verified"


class TestSync:
    @respx.mock
    def test_a_peers_commit_is_applied_and_acked(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, mls_escrow_stub
    ):
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        third = Peer(tmp_path, "11111111-2222-3333-4444-555555555555", agent_id)
        save_agent_keys(tmp_config_dir, third.agent_id, third.keys)
        peer.admit(third)
        added = peer.add(third.client.generate_key_package())
        before = load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID).epoch()
        _mock_handshakes(added.commit)
        ack = _mock_ack()

        result = sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.processed == 1
        assert result.epoch == before + 1
        assert result.evicted is False
        assert ack.called
        assert mls_escrow_stub[-1] == (GROUP_ID, result.epoch)

    @respx.mock
    def test_a_commit_that_cannot_be_applied_is_nacked_once(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_handshakes(b"\x00\x01not a commit")
        _mock_group()
        respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
        )
        nack = _mock_nack()

        result = sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.processed == 0
        assert nack.called
        assert json.loads(nack.calls[0].request.content)["object_id"] == f"{HANDSHAKE_ID[:-1]}0"

    def test_a_local_store_failure_never_nacks_a_peers_commit(self):
        """NACKing because our own disk failed would roll back a good commit."""
        assert not is_unprocessable_commit(MlsStoreError("disk full"))

    @respx.mock
    def test_a_remove_commit_reports_the_eviction_rather_than_failing(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """Eviction is the correct outcome of a valid commit, not an error."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        ours = peer.group.member_index(credential_identity(agent_id))
        removal = peer.group.remove_member(ours)
        peer.group.save()
        _mock_handshakes(removal.commit)
        _mock_ack()

        result = sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.evicted is True

    @respx.mock
    def test_syncing_a_group_this_agent_never_joined_is_refused_by_name(
        self, sync_client, tmp_config_dir, agent_id
    ):
        with pytest.raises(NoMlsGroupStateError, match=GROUP_ID):
            sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)


class TestEpochRetention:
    @respx.mock
    def test_a_message_from_an_earlier_epoch_still_reads_after_many_commits(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The undelivered queue holds messages indefinitely, so backlog must.

        The default retention reaches the full backlog. A message sent before six
        membership changes is exactly what a long-absent agent finds waiting.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        old_message = peer.send({"sent": "long before you came back"})

        commits = []
        for i in range(6):
            joiner = Peer(tmp_path, f"{i}1111111-2222-3333-4444-555555555555", agent_id)
            save_agent_keys(tmp_config_dir, joiner.agent_id, joiner.keys)
            peer.admit(joiner)
            commits.append(peer.add(joiner.client.generate_key_package()).commit)
        _mock_handshakes(*commits)
        _mock_ack()
        assert sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID).processed == 6

        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, old_message, other_agent_id
        )

        assert json.loads(result.plaintext) == {"sent": "long before you came back"}


class TestSendPath:
    @respx.mock
    def test_a_send_applies_pending_commits_before_encrypting(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A member who joined at a later epoch never held the earlier ones' secrets."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        latecomer = Peer(
            tmp_path, "22222222-3333-4444-5555-666666666666", agent_id, other_agent_id
        )
        save_agent_keys(tmp_config_dir, latecomer.agent_id, latecomer.keys)
        peer.admit(latecomer)
        added = peer.add(latecomer.client.generate_key_package())
        latecomer.group = latecomer.client.join_from_welcome(added.welcomes[0])
        latecomer.group.save()
        _mock_handshakes(added.commit)
        _mock_ack()
        _mock_keys(latecomer)
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(agent_id))
        )

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"for": "the latecomer"}
        )
        result = latecomer.read(sync_client._http, sent.encrypted_payload, agent_id)

        assert json.loads(result.plaintext) == {"for": "the latecomer"}

    @respx.mock
    def test_a_send_to_a_group_with_no_state_recovers_from_the_welcome(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        peer = Peer(tmp_path, other_agent_id, agent_id)
        save_agent_keys(tmp_config_dir, other_agent_id, peer.keys)
        key_package = _mint_key_package(sync_client, tmp_config_dir, agent_id)
        bundle = peer.found(key_package)
        welcomes = _mock_welcomes(agent_id, bundle.welcomes[0])
        _mock_no_handshakes()

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"first": "send"}
        )

        assert welcomes.called
        assert sent.encryption_version == EncryptionVersion.MLS_V1
        assert load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID) is not None


class TestThroughTheClients:
    @respx.mock
    def test_send_posts_an_mls_payload_for_an_mls_group(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_JSON]})
        )
        _mock_agents(agent_id)
        posted = _mock_posted_message(agent_id)

        sync_client.send(_GROUP_JSON["handle"], {"task": "through the client"})

        body = json.loads(posted.calls[0].request.content)
        assert body["encryption_version"] == EncryptionVersion.MLS_V1
        assert body["to_handle"] == _GROUP_JSON["handle"]
        assert from_base64url(body["encrypted_payload"])[0] == APP_MESSAGE_TAG

    @respx.mock
    def test_send_with_a_wrong_org_half_posts_the_handle_the_server_holds(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The ladder's resolve is only half the fix; this is the other half.

        The ladder resolves ``#test-group@acme…`` — a fabricated org half, which
        is what a model writes when it copies the domain out of a tool
        description — and the group is sealed for correctly. What used to reach
        the wire was the caller's spelling, and ``POST /messages`` looks
        ``to_handle`` up by exact equality: the server answered a bare ``Group
        not found``, indistinguishable from the ladder never having run.

        Measured, not hypothesised — it is the one hallucinated-handle
        failure that survived the ladder against live models.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        _mock_groups_by_equality()
        _mock_agents(agent_id)
        posted = _mock_posted_message(agent_id)

        sync_client.send("#test-group@acme.rine.network", {"task": "wrong org"})

        body = json.loads(posted.calls[0].request.content)
        assert body["to_handle"] == _GROUP_JSON["handle"]
        assert "acme" not in body["to_handle"]

    @respx.mock
    async def test_the_async_client_reads_an_mls_row_through_the_same_implementation(
        self, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys, sync_client
    ):
        from rine import RineClient

        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        ciphertext = peer.send({"async": "reads what sync writes"})
        write_agent_identity(tmp_config_dir, agent_id)
        _mock_agents(agent_id)
        _mock_message_routes(agent_id, _mls_row(ciphertext, other_agent_id))

        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            msg = await client.read(MESSAGE_ID)

        assert json.loads(msg.plaintext) == {"async": "reads what sync writes"}
        assert msg.decrypt_error is None
        assert msg.verified is True


class TestRowsSeenTwice:
    """One row, two receive surfaces. The MLS message key is single-use."""

    @respx.mock
    def test_read_after_inbox_on_an_mls_row_still_returns_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """An MLS group row seen twice by one client yields plaintext twice.

        Forward secrecy consumed the generation the first decrypt used, so the
        second can only come from the memo. This is the ordinary
        ``inbox()``-then-``read()`` sequence every rine integration performs.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        payload = {"task": "read me twice"}
        _mock_message_routes(agent_id, _mls_row(peer.send(payload), other_agent_id))

        page = sync_client.inbox()
        again = sync_client.read(MESSAGE_ID)

        assert json.loads(page.items[0].plaintext) == payload
        assert again.decrypt_error is None
        assert json.loads(again.plaintext) == payload

    @respx.mock
    async def test_read_after_inbox_on_an_mls_row_still_returns_plaintext_async(
        self, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys, sync_client
    ):
        """The async client carries the same guarantee, through the same memo."""
        from rine import RineClient

        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        write_agent_identity(tmp_config_dir, agent_id)
        payload = {"task": "read me twice, asynchronously"}
        _mock_message_routes(agent_id, _mls_row(peer.send(payload), other_agent_id))

        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            page = await client.inbox()
            again = await client.read(MESSAGE_ID)

        assert json.loads(page.items[0].plaintext) == payload
        assert again.decrypt_error is None
        assert json.loads(again.plaintext) == payload

    @respx.mock
    def test_thread_over_an_mls_group_conversation_is_re_readable(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """Rendering a group transcript twice renders it, never ``[unavailable]``."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        _mock_message_routes(
            agent_id, _mls_row(peer.send({"text": "hello group"}), other_agent_id)
        )

        first = sync_client.thread(CONVERSATION_ID)

        assert first[0].text == "hello group"
        assert sync_client.thread(CONVERSATION_ID) == first


class TestTheOnDiskReadCacheOnTheMlsPath:
    """The re-read guarantee, in the regime that is the default.

    :class:`TestRowsSeenTwice` above cannot stand in for this. It reads through
    the client, whose in-process ``MessageMemo`` answers the second read on its
    own — it was green before the on-disk cache existed and it stays green with
    the cache neutered. These cases call :func:`decrypt_mls_group_message`
    directly, which is below the memo, so the only thing that can answer twice
    is ``lookup_group_read``. The control arm deletes the cache file and asks
    again, which is what makes the replay attributable to it.
    """

    @respx.mock
    def test_second_decrypt_of_an_mls_row_returns_the_same_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """Two decrypts, one ciphertext, and no client in between to remember it."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        handshakes = _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        payload = {"task": "opened twice, below the memo"}
        ciphertext = peer.send(payload)

        first = _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)
        second = _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)

        assert json.loads(first.plaintext) == payload
        assert json.loads(second.plaintext) == payload
        assert second.sender_kid == first.sender_kid
        assert second.verification_status == "verified"
        # The replay opened no MLS state and asked the server nothing new: the
        # first read's catch-up is the only handshake request either made.
        assert handshakes.call_count == 1

    @respx.mock
    def test_second_decrypt_when_the_cache_is_removed_then_the_secret_is_gone(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The control arm. One variable changes: the cache file.

        MLS deletes the secret-tree entry at the first decrypt, so the recovery
        path cannot bring it back either — the row is simply unreadable again.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        ciphertext = peer.send({"task": "opened once"})

        _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)
        delete_group_read_cache(tmp_config_dir, agent_id, GROUP_ID)

        with pytest.raises(CryptoError):
            _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)

    @respx.mock
    def test_replay_when_the_group_is_retired_then_the_cache_stays_shut(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A retirement closes this cache with everything else, in BOTH regimes.

        A leave writes a retirement marker beside the keys it wipes and deletes
        the cache in the same breath, so today this is defensive rather than
        live. It still has to hold: the marker has to be re-armable, and a
        message opened while it was absent must stop opening once it is back.
        The sender-key twin is ``_crypto.message._replayed_envelope`` and the
        TypeScript twin gates both regimes in one place
        (``rine-core/src/message-group.ts``); this path may not be the one hole.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        ciphertext = peer.send({"task": "opened once, then retired"})

        _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)
        mark_sender_keys_retired(tmp_config_dir, agent_id, GROUP_ID)

        # Same control arm as the case above: the secret-tree entry is spent, so
        # with the cache shut there is nothing left to answer with.
        with pytest.raises(CryptoError):
            _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)

    @respx.mock
    def test_a_replay_naming_a_different_sender_is_refused(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A replay is verified against the sender the row names NOW.

        The same rule the sender-key path holds, reached through the MLS branch:
        the cache answers what the bytes said, never who they were attributed to
        the first time.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        ciphertext = peer.send({"task": "opened once, then renamed"})

        _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, other_agent_id)

        with pytest.raises(SenderMismatchError):
            _decrypt(sync_client, tmp_config_dir, agent_id, ciphertext, IMPOSTOR_ID)


class TestRepeatReadKeepsTheBinding:
    """Who a row is from is decided on every read, not once per client.

    A row already opened is answered from the memo, so nothing re-derives the
    verdict — the message's one-time key is spent by then. The binding is what
    has to be held again, or a row re-served under another name comes back
    verified as an agent that never signed it.
    """

    @respx.mock
    def test_a_row_re_served_under_another_sender_is_not_replayed_as_verified(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """Read once honestly, then served again with the sender renamed."""
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        _serve_honestly_then_renamed(_mls_row(peer.send({"text": "albatross"}), other_agent_id))

        first = sync_client.read(MESSAGE_ID)
        second = sync_client.read(MESSAGE_ID)

        assert first.verified is True
        assert second.verified is False
        assert second.verification_status == "sender-mismatch"
        assert second.plaintext is None
        assert second.decrypt_error is not None

    @respx.mock
    async def test_a_row_re_served_under_another_sender_is_not_replayed_as_verified_async(
        self, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys, sync_client
    ):
        """The async client shares the memo's contract, and its refusal."""
        from rine import RineClient

        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        write_agent_identity(tmp_config_dir, agent_id)
        _serve_honestly_then_renamed(_mls_row(peer.send({"text": "albatross"}), other_agent_id))

        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            first = await client.read(MESSAGE_ID)
            second = await client.read(MESSAGE_ID)

        assert first.verified is True
        assert second.verified is False
        assert second.verification_status == "sender-mismatch"
        assert second.plaintext is None


class TestRotationOnAGroupRow:
    """A peer's key rotation reaches the caller from either client."""

    @respx.mock
    async def test_a_rotated_sender_key_is_reported_on_an_mls_row_by_both_clients(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys
    ):
        """The async client runs MLS on a worker thread; the signal must survive that.

        Both clients hold the same superseded copy of the peer's signing key, so
        the cached key fails, the one refetch finds the peer's real one, and the
        rotation is reported. A worker with a cache of its own starts empty, has
        no stale key to fail on, and reports nothing.
        """
        from rine import RineClient

        peer = Peer(tmp_path, other_agent_id, agent_id, gen=1)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        write_agent_identity(tmp_config_dir, agent_id)
        superseded = WORLD.verified(other_agent_id, 0)
        _mock_message_routes(agent_id, _mls_row(peer.send({"text": "one"}), other_agent_id))
        respx.get(f"{API}/messages/{SECOND_MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_mls_row(peer.send({"text": "two"}), other_agent_id),
                    "id": SECOND_MESSAGE_ID,
                },
            )
        )

        sync_client._http._keys_cache.set(other_agent_id, superseded)
        from_sync = sync_client.read(MESSAGE_ID)
        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            client._http._keys_cache.set(other_agent_id, superseded)
            from_async = await client.read(SECOND_MESSAGE_ID)

        assert from_sync.key_changed is not None
        assert from_sync.key_changed.agent_id == other_agent_id
        assert from_sync.key_changed.current_fingerprint == signing_fingerprint(peer.keys)
        assert from_async.key_changed == from_sync.key_changed


class TestFailedReadKeepsTheRow:
    """A read that cannot deliver plaintext must not spend the row's key."""

    @respx.mock
    def test_read_that_fails_after_the_ratchet_step_reports_the_same_failure_twice(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A failure after the MLS decrypt must leave the message where it was.

        The ciphertext is a well-formed MLS frame around a malformed inner
        envelope, so the ratchet step succeeds and everything after it fails.
        Persisting the advance there turns the second read's honest "envelope
        too short" into "invalid generation 0" — a fault report that no longer
        describes the fault, and a plaintext that would have been recoverable
        for a transient failure is gone.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        framed = peer.group.encrypt_application_message(b"\x01")
        peer.group.save()
        _mock_message_routes(agent_id, _mls_row(to_base64url(framed), other_agent_id))

        first = sync_client.read(MESSAGE_ID)
        second = sync_client.read(MESSAGE_ID)

        assert first.plaintext is None
        assert first.decrypt_error is not None
        assert second.decrypt_error == first.decrypt_error


class TestReadDegrades:
    """``read()`` carries ``inbox()``'s contract: a bad row never raises."""

    @respx.mock
    def test_read_an_mls_row_this_agent_cannot_open_sets_decrypt_error(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """No state, no Welcome, no GroupInfo: the row degrades rather than raising."""
        _unreachable_group(sync_client, tmp_path, agent_id, other_agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None

    @respx.mock
    async def test_read_an_mls_row_this_agent_cannot_open_sets_decrypt_error_async(
        self, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys, sync_client
    ):
        """The async client degrades identically — one contract, not two."""
        from rine import RineClient

        _unreachable_group(sync_client, tmp_path, agent_id, other_agent_id)
        write_agent_identity(tmp_config_dir, agent_id)

        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            msg = await client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None

    @respx.mock
    def test_a_row_committed_before_this_agents_leaf_says_so_in_rines_words(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The measured leak, and the reason a reader could do nothing with it.

        The peer sends one epoch before this agent has a leaf, so no key it will
        ever hold opens that row — correct MLS behaviour, reported by the core as
        mls-rs's own KDF refusal: *the provided length of the key 0 is shorter
        than the minimum length 32*. That names no group, no cause a reader
        recognises and no move, and ``decrypt_error`` carried it verbatim to
        every SDK caller and every framework tool built on one.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _mock_token()
        save_agent_keys(tmp_config_dir, other_agent_id, peer.keys)
        key_package = _mint_key_package(sync_client, tmp_config_dir, agent_id)
        peer.found()
        before_the_leaf = peer.send({"not": "openable"})
        bundle = peer.add(key_package)
        _mock_welcomes(agent_id, bundle.welcomes[0])
        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        _mock_message_routes(agent_id, _mls_row(before_the_leaf, other_agent_id))

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert "shorter than the minimum length" not in msg.decrypt_error
        assert f"holds no MLS key for group {GROUP_ID}" in msg.decrypt_error
        assert f'groups.sync("{GROUP_ID}")' in msg.decrypt_error

    @respx.mock
    def test_a_row_for_a_group_this_agent_holds_no_state_for_says_the_same_thing(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The other half of the same agent's failure, and it used to say something else.

        A carried vote seats an agent on the roster with no Welcome, so it holds
        no leaf and no local state at all. Reading a group row then fails before
        any key is tried, as :class:`~rine.errors.NoMlsGroupStateError`, and the
        SDK printed the class's own sentence — which names neither
        ``groups.sync()`` nor the key packages an admission has to claim, and so
        told the one agent this phase was opened for nothing it could act on.
        The CLI has covered both arms (``isRecoverableMlsRead``); this
        is the SDK saying the same thing to the same agent.

        The group's MLS state is unfounded here, which is what leaves the
        recovery with nothing to install and nothing to join.
        """
        _mock_token()
        peer = Peer(tmp_path, other_agent_id, agent_id)
        peer.found()
        ciphertext = peer.send({"not": "openable"})
        _mock_keys(peer)
        _mock_agents(agent_id)
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json={**_GROUP_JSON, "mls_group_id": None})
        )
        _mock_welcomes(agent_id)
        _mock_no_handshakes()
        _mock_message_routes(agent_id, _mls_row(ciphertext, other_agent_id))

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert "This agent is not in the group's MLS state yet" not in msg.decrypt_error
        assert f"holds no MLS key for group {GROUP_ID}" in msg.decrypt_error
        assert f'groups.sync("{GROUP_ID}")' in msg.decrypt_error

    @respx.mock
    def test_a_group_that_never_published_a_group_info_keeps_its_own_refusal(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The translation is narrow on purpose, and this is the neighbour it must not eat.

        A group with no published GroupInfo is a different fact from a leaf that
        does not reach far enough back — it names something a *member* must do,
        not this agent — and rine already had a sentence for it. Widening the
        branch to "any MLS failure" would replace an accurate sentence with a
        vaguer one, which is the failure this whole finding is about.
        """
        _unreachable_group(sync_client, tmp_path, agent_id, other_agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert f"Cannot self-join MLS group {GROUP_ID}" in msg.decrypt_error
        assert "holds no MLS key for group" not in msg.decrypt_error

    @respx.mock
    def test_a_core_failure_the_sdk_does_not_name_reaches_the_caller_as_a_rine_error(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A frame the core refuses by a class the SDK never re-exported.

        ``UnexpectedVersionTagError`` is one of the ten ``rine_mls`` classes with
        no SDK name, so a caller could not write an ``except`` for it even if it
        wanted to. It must arrive normalised, carrying the core's own code.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_group()
        _mock_no_handshakes()

        with pytest.raises(CryptoError) as caught:
            decrypt_mls_group_message(
                sync_client._http,
                tmp_config_dir,
                agent_id,
                GROUP_ID,
                to_base64url(b"\x00"),
                other_agent_id,
            )

        assert caught.value.code

    def test_every_mls_core_failure_class_crosses_the_boundary_as_a_rine_error(self):
        """Enumerated off the wheel, so a class added upstream fails here first.

        The core's code enum is ``#[non_exhaustive]``: a new code lands on the
        base class, which no ``except`` list over the leaves would catch.
        """
        import rine_mls

        classes = [rine_mls.RineMlsError, *rine_mls.RineMlsError.__subclasses__()]
        assert len(classes) > 15

        for cls in classes:
            with pytest.raises(CryptoError) as caught:
                _raise_through_the_boundary(cls)
            assert caught.value.code == getattr(cls, "code", None)


def _unreachable_group(sync_client, tmp_path, agent_id: str, other_agent_id: str) -> None:
    """Serve an MLS row for a group this agent can never establish state for."""
    _mock_token()
    peer = Peer(tmp_path, other_agent_id, agent_id)
    peer.found()
    ciphertext = peer.send({"not": "for you"})
    _mock_agents(agent_id)
    _mock_group()
    _mock_welcomes(agent_id)
    respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
        return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
    )
    _mock_message_routes(agent_id, _mls_row(ciphertext, other_agent_id))


@mls_boundary
def _raise_through_the_boundary(cls: type[BaseException]) -> None:
    """Stand in for the compiled core raising one of its own classes."""
    raise cls("boom")


class TestAReadSaysWhatItDidToTheGroupState:
    """The eager catch-up's own result, carried out to the caller.

    Reading a closed-group message advances this agent's MLS state behind the
    read: it applies whatever commits it finds, lands on an epoch, and can
    discover that the agent has been removed. All three were computed on every
    read and thrown away, so the one surface that already knew a member had
    been evicted said nothing about it.

    What is deliberately absent is *distance*. "You were N epochs behind" needs
    the group's confirmed epoch from the server — a second round trip on the
    hottest path in the product — and ``groups.sync`` is where that question is
    asked.
    """

    @respx.mock
    def test_read_when_a_group_row_is_opened_then_it_reports_the_catch_up_it_ran(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        _mock_message_routes(agent_id, _mls_row(peer.send({"task": "hello"}), other_agent_id))

        msg = sync_client.read(MESSAGE_ID)

        assert msg.catch_up is not None
        assert msg.catch_up.processed == 0, "a current member with nothing pending"
        assert msg.catch_up.epoch >= 0
        assert msg.catch_up.evicted is False

    @respx.mock
    def test_read_when_the_row_was_already_opened_then_it_reports_no_catch_up(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A replay applied nothing, so it must claim nothing.

        The gate is reset between the two reads on purpose: without that, a
        silent second read would be indistinguishable from the once-a-minute
        floor swallowing it. Reset, the only reason this read reports no work is
        that it did none — it came from the memo.
        """
        peer = Peer(tmp_path, other_agent_id, agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        _mock_agents(agent_id)
        _mock_group()
        _mock_no_handshakes()
        reset_mls_heartbeat_gate()
        _mock_message_routes(agent_id, _mls_row(peer.send({"task": "twice"}), other_agent_id))

        first = sync_client.inbox().items[0]
        reset_mls_heartbeat_gate()
        again = sync_client.read(MESSAGE_ID)

        assert first.catch_up is not None
        assert again.plaintext == first.plaintext
        assert again.catch_up is None
