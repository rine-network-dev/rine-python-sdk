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
from rine._crypto.keys import (
    generate_agent_keys,
    save_agent_keys,
    signing_public_key_to_jwk,
)
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
)
from rine._utils import from_base64url
from rine.errors import NoMlsGroupStateError
from rine.types import GroupRead

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
WELCOME_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
HANDSHAKE_ID = "55555555-6666-7777-8888-999999999999"
MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000001"

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
    """A second real MLS client — the founder, and the far end of interop."""

    def __init__(self, tmp_path, agent_id: str) -> None:
        self.agent_id = agent_id
        self.config_dir = str(tmp_path / f"peer-{agent_id}")
        self.keys = generate_agent_keys()
        save_agent_keys(self.config_dir, agent_id, self.keys)
        self.client = open_mls_client(self.config_dir, agent_id)
        self.group = None

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

    def read(self, client, encrypted_payload: str):
        return decrypt_mls_group_message(
            client, self.config_dir, self.agent_id, GROUP_ID, encrypted_payload
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
    """Serve each peer's signing key so the inner envelope can be verified."""
    for peer in peers:
        respx.get(f"{API}/agents/{peer.agent_id}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": peer.agent_id,
                    "signing_public_key": signing_public_key_to_jwk(peer.keys.signing.public_key),
                },
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


def _join_group(sync_client, config_dir: str, agent_id: str, peer: Peer) -> None:
    """Get the agent under test into a group the peer founds."""
    _mock_token()
    key_package = _mint_key_package(sync_client, config_dir, agent_id)
    bundle = peer.found(key_package)
    _mock_welcomes(agent_id, bundle.welcomes[0])
    process_mls_welcomes(sync_client._http, config_dir, agent_id)


# --------------------------------------------------------------------------


class TestRoundTrip:
    @respx.mock
    def test_a_peers_message_is_read_with_its_exact_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        payload = {"task": "summarize", "note": "unicode ✓ and a quote \\"}

        ciphertext = peer.send(payload)
        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext
        )

        assert json.loads(result.plaintext) == payload
        assert result.verified is True
        assert result.verification_status == "verified"
        assert result.sender_kid == f"rine:{other_agent_id}"

    @respx.mock
    def test_our_message_is_read_by_the_peer_with_its_exact_plaintext(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys
    ):
        """The other direction: what this SDK sends, a different client reads."""
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": agent_id,
                    "signing_public_key": signing_public_key_to_jwk(
                        saved_agent_keys.signing.public_key
                    ),
                },
            )
        )
        payload = {"reply": "read back by a different client"}

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, payload
        )
        result = peer.read(sync_client._http, sent.encrypted_payload)

        assert json.loads(result.plaintext) == payload
        assert result.verified is True
        assert sent.encryption_version == EncryptionVersion.MLS_V1

    @respx.mock
    def test_the_payload_is_base64url_of_the_cores_own_version_tag(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The wire shape, read off the bytes rather than asserted from a constant."""
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"a": 1}
        )

        assert from_base64url(sent.encrypted_payload)[0] == APP_MESSAGE_TAG
        assert sent.sender_signing_kid == f"rine:{agent_id}"


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
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": agent_id,
                    "signing_public_key": signing_public_key_to_jwk(
                        saved_agent_keys.signing.public_key
                    ),
                },
            )
        )
        payload = {"note": "a sender must be able to read its own thread"}

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, payload
        )
        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, sent.encrypted_payload
        )

        assert json.loads(result.plaintext) == payload
        assert result.sender_kid == f"rine:{agent_id}"

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
        peer = Peer(tmp_path, other_agent_id)
        key_package = _mint_key_package(sync_client, tmp_config_dir, agent_id)
        bundle = peer.found(key_package)
        ciphertext = peer.send({"before": "you installed anything"})

        _mock_keys(peer)
        _mock_group()
        _mock_no_handshakes()
        welcomes = _mock_welcomes(agent_id, bundle.welcomes[0])
        assert load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID) is None

        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext
        )

        assert json.loads(result.plaintext) == {"before": "you installed anything"}
        assert welcomes.called

    @respx.mock
    def test_an_unreachable_group_is_refused_by_name(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """No Welcome, no GroupInfo: recovery cannot invent state, and says which group."""
        _mock_token()
        peer = Peer(tmp_path, other_agent_id)
        peer.found()
        ciphertext = peer.send({"not": "for you"})
        _mock_group()
        _mock_welcomes(agent_id)
        respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
        )

        with pytest.raises(Exception, match=GROUP_ID):
            decrypt_mls_group_message(
                sync_client._http, tmp_config_dir, agent_id, GROUP_ID, ciphertext
            )

    @respx.mock
    def test_a_message_naming_no_group_is_refused_without_touching_the_server(
        self, sync_client, tmp_config_dir, agent_id
    ):
        with pytest.raises(Exception, match="names no group"):
            decrypt_mls_group_message(sync_client._http, tmp_config_dir, agent_id, None, "BAAB")


class TestSync:
    @respx.mock
    def test_a_peers_commit_is_applied_and_acked(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        third = Peer(tmp_path, "11111111-2222-3333-4444-555555555555")
        added = peer.add(third.client.generate_key_package())
        before = load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID).epoch()
        _mock_handshakes(added.commit)
        ack = _mock_ack()

        result = sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.processed == 1
        assert result.epoch == before + 1
        assert result.evicted is False
        assert ack.called

    @respx.mock
    def test_a_commit_that_cannot_be_applied_is_nacked_once(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        peer = Peer(tmp_path, other_agent_id)
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
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        ours = peer.group.member_index(open_mls_client(tmp_config_dir, agent_id).public_key())
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
        """DEC-8: the undelivered queue holds messages indefinitely, so backlog must.

        The default retention reaches the full backlog. A message sent before six
        membership changes is exactly what a long-absent agent finds waiting.
        """
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        old_message = peer.send({"sent": "long before you came back"})

        commits = []
        for i in range(6):
            joiner = Peer(tmp_path, f"{i}1111111-2222-3333-4444-555555555555")
            commits.append(peer.add(joiner.client.generate_key_package()).commit)
        _mock_handshakes(*commits)
        _mock_ack()
        assert sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID).processed == 6

        result = decrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP_ID, old_message
        )

        assert json.loads(result.plaintext) == {"sent": "long before you came back"}


class TestSendPath:
    @respx.mock
    def test_a_send_applies_pending_commits_before_encrypting(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """A member who joined at a later epoch never held the earlier ones' secrets."""
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        latecomer = Peer(tmp_path, "22222222-3333-4444-5555-666666666666")
        added = peer.add(latecomer.client.generate_key_package())
        latecomer.group = latecomer.client.join_from_welcome(added.welcomes[0])
        latecomer.group.save()
        _mock_handshakes(added.commit)
        _mock_ack()
        _mock_keys(latecomer)
        respx.get(f"{API}/agents/{agent_id}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": agent_id,
                    "signing_public_key": signing_public_key_to_jwk(
                        open_mls_client(tmp_config_dir, agent_id).public_key()
                    ),
                },
            )
        )

        sent = encrypt_mls_group_message(
            sync_client._http, tmp_config_dir, agent_id, GROUP, {"for": "the latecomer"}
        )
        result = latecomer.read(sync_client._http, sent.encrypted_payload)

        assert json.loads(result.plaintext) == {"for": "the latecomer"}

    @respx.mock
    def test_a_send_to_a_group_with_no_state_recovers_from_the_welcome(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        peer = Peer(tmp_path, other_agent_id)
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
        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_no_handshakes()
        respx.get(f"{API}/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_JSON]})
        )
        _mock_agents(agent_id)
        posted = respx.post(f"{API}/messages").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": MESSAGE_ID,
                    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
                    "from_agent_id": agent_id,
                    "group_id": GROUP_ID,
                    "type": "rine.v1.task_request",
                    "encrypted_payload": "x",
                    "encryption_version": EncryptionVersion.MLS_V1,
                    "sender_signing_kid": f"rine:{agent_id}",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            )
        )

        sync_client.send(_GROUP_JSON["handle"], {"task": "through the client"})

        body = json.loads(posted.calls[0].request.content)
        assert body["encryption_version"] == EncryptionVersion.MLS_V1
        assert body["to_handle"] == _GROUP_JSON["handle"]
        assert from_base64url(body["encrypted_payload"])[0] == APP_MESSAGE_TAG

    @respx.mock
    async def test_the_async_client_reads_an_mls_row_through_the_same_implementation(
        self, tmp_config_dir, agent_id, other_agent_id, tmp_path, saved_agent_keys, sync_client
    ):
        from rine import RineClient
        from rine._config import save_credentials

        peer = Peer(tmp_path, other_agent_id)
        _join_group(sync_client, tmp_config_dir, agent_id, peer)
        _mock_keys(peer)
        ciphertext = peer.send({"async": "reads what sync writes"})
        save_credentials(
            tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "csecret"}}
        )
        _mock_agents(agent_id)
        respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": MESSAGE_ID,
                    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
                    "from_agent_id": other_agent_id,
                    "group_id": GROUP_ID,
                    "type": "rine.v1.task_request",
                    "encrypted_payload": ciphertext,
                    "encryption_version": EncryptionVersion.MLS_V1,
                    "sender_signing_kid": f"rine:{other_agent_id}",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            )
        )

        async with RineClient(config_dir=tmp_config_dir, api_url=API, agent=agent_id) as client:
            msg = await client.read(MESSAGE_ID)

        assert json.loads(msg.plaintext) == {"async": "reads what sync writes"}
        assert msg.decrypt_error is None
        assert msg.verified is True
