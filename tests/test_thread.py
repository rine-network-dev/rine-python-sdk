"""Self-seal on send/reply + thread()/get_conversation_messages.

Covers both the async (``RineClient``) and sync (``SyncRineClient``) clients with
the identical behavioral assertions (the sync client is a hand-mirror of async).
HTTP is mocked via ``respx``; crypto is real (the message helpers are pure and
operate on the tmp-config agent keys saved by the fixtures).
"""

from __future__ import annotations

import json

import httpx
import respx

from rine._crypto.keys import (
    generate_agent_keys,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.message import encrypt_message
from tests.conftest import recipient_view
from rine._utils import to_base64url
from rine.types import DecryptedMessage, ThreadEntry

API = "https://rine.network"
AGENT_ID = "00000000-1111-2222-3333-444444444444"  # matches conftest fixtures
PEER_ID = "99999999-8888-7777-6666-555555555555"
CONVERSATION_ID = "dddddddd-eeee-ffff-0000-111111111111"
TOKEN = {"access_token": "test-token", "expires_in": 900}


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))


def _mock_agents() -> None:
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": AGENT_ID,
                        "name": "me",
                        "handle": "me@myorg.rine.network",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _keys_jwk(keys) -> dict:
    return {
        "agent_id": AGENT_ID,
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": {
            "kty": "OKP",
            "crv": "X25519",
            "x": to_base64url(keys.encryption.public_key),
        },
    }


# ---------------------------------------------------------------------------
# Fixtures: pre-built both-sided rows for a conversation
# ---------------------------------------------------------------------------


def _build_rows(config_dir: str, peer_keys) -> tuple[list[dict], dict]:
    """Build a both-sided row set + the agent's own keys JWK for verify.

    Rows: a SENT row (with self-blob), a RECEIVED row (sealed to the agent),
    and a SENT row with a NULL self-blob (legacy / undecryptable).
    """
    from rine._crypto.keys import load_agent_keys

    my_keys = load_agent_keys(config_dir, AGENT_ID)

    # SENT: agent → peer. encrypt_message produces both the recipient copy AND
    # the self-blob (sealed to the agent's own key).
    sent = encrypt_message(
        config_dir,
        AGENT_ID,
        recipient_view(peer_keys),
        {"text": "hi peer, the codeword is albatross"},
    )

    # RECEIVED: peer → agent. Seal to the AGENT's encryption key, signed by peer.
    # We reuse encrypt_message from the PEER's perspective: save peer keys under
    # PEER_ID so its signature can be verified, then seal to the agent.
    save_agent_keys(config_dir, PEER_ID, peer_keys)
    received = encrypt_message(
        config_dir, PEER_ID, recipient_view(my_keys), {"text": "got it, albatross noted"}
    )

    rows = [
        {
            "id": "11111111-0000-0000-0000-000000000001",
            "conversation_id": CONVERSATION_ID,
            "from_agent_id": AGENT_ID,
            "to_agent_id": PEER_ID,
            "type": "rine.v1.task_request",
            "direction": "sent",
            "encrypted_payload": sent.encrypted_payload,
            "self_encrypted_payload": sent.self_encrypted_payload,
            "encryption_version": "hpke-v1",
            "sender_handle": "me@myorg.rine.network",
            "created_at": "2024-01-01T00:00:01Z",
        },
        {
            "id": "11111111-0000-0000-0000-000000000002",
            "conversation_id": CONVERSATION_ID,
            "from_agent_id": PEER_ID,
            "to_agent_id": AGENT_ID,
            "type": "rine.v1.task_response",
            "direction": "received",
            "encrypted_payload": received.encrypted_payload,
            "self_encrypted_payload": None,
            "encryption_version": "hpke-v1",
            "sender_handle": "peer@myorg.rine.network",
            "created_at": "2024-01-01T00:00:02Z",
        },
        {
            "id": "11111111-0000-0000-0000-000000000003",
            "conversation_id": CONVERSATION_ID,
            "from_agent_id": AGENT_ID,
            "to_agent_id": PEER_ID,
            "type": "rine.v1.task_request",
            "direction": "sent",
            "encrypted_payload": "legacy-recipient-only-blob",
            "self_encrypted_payload": None,  # legacy: no self-seal
            "encryption_version": "hpke-v1",
            "sender_handle": "me@myorg.rine.network",
            "created_at": "2024-01-01T00:00:03Z",
        },
    ]
    return rows, _keys_jwk(my_keys)


def _mock_keys(agent_jwk: dict, peer_keys) -> None:
    """Mock /agents/{id}/keys for both the agent (self-verify) and peer."""
    respx.get(f"{API}/agents/{AGENT_ID}/keys").mock(
        return_value=httpx.Response(200, json=agent_jwk)
    )
    respx.get(f"{API}/agents/{PEER_ID}/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "agent_id": PEER_ID,
                "signing_public_key": signing_public_key_to_jwk(peer_keys.signing.public_key),
                "encryption_public_key": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": to_base64url(peer_keys.encryption.public_key),
                },
            },
        )
    )


# ---------------------------------------------------------------------------
# Send / reply self-blob wiring
# ---------------------------------------------------------------------------


class TestSelfSealOnSend:
    """Send/reply carry the self-seal blob on the wire."""

    @respx.mock
    async def test_async_send_includes_self_encrypted_payload(self, async_client):
        """A 1:1 send POSTs self_encrypted_payload (async)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        respx.get(f"{API}/agents/{PEER_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": PEER_ID,
                    "signing_public_key": signing_public_key_to_jwk(peer_keys.signing.public_key),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(peer_keys.encryption.public_key),
                    },
                },
            )
        )
        post = respx.post(f"{API}/messages").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "aaaa1111-0000-0000-0000-000000000001",
                    "conversation_id": CONVERSATION_ID,
                    "from_agent_id": AGENT_ID,
                    "to_agent_id": PEER_ID,
                    "type": "rine.v1.task_request",
                    "encrypted_payload": "x",
                    "encryption_version": "hpke-v1",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            )
        )

        await async_client.send(PEER_ID, {"text": "hi"})

        body = json.loads(post.calls[0].request.content)
        assert "self_encrypted_payload" in body
        assert body["self_encrypted_payload"]
        await async_client.close()

    @respx.mock
    def test_sync_send_includes_self_encrypted_payload(self, sync_client):
        """A 1:1 send POSTs self_encrypted_payload (sync)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        respx.get(f"{API}/agents/{PEER_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": PEER_ID,
                    "signing_public_key": signing_public_key_to_jwk(peer_keys.signing.public_key),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(peer_keys.encryption.public_key),
                    },
                },
            )
        )
        post = respx.post(f"{API}/messages").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "aaaa1111-0000-0000-0000-000000000001",
                    "conversation_id": CONVERSATION_ID,
                    "from_agent_id": AGENT_ID,
                    "to_agent_id": PEER_ID,
                    "type": "rine.v1.task_request",
                    "encrypted_payload": "x",
                    "encryption_version": "hpke-v1",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            )
        )

        sync_client.send(PEER_ID, {"text": "hi"})

        body = json.loads(post.calls[0].request.content)
        assert "self_encrypted_payload" in body
        assert body["self_encrypted_payload"]

    @respx.mock
    async def test_async_reply_includes_self_encrypted_payload(self, async_client):
        """A 1:1 reply POSTs self_encrypted_payload (async)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        original_id = "bbbb1111-0000-0000-0000-000000000001"
        # reply() fetches the original to recover the peer (from_agent_id).
        respx.get(f"{API}/messages/{original_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": original_id,
                    "conversation_id": CONVERSATION_ID,
                    "from_agent_id": PEER_ID,
                    "to_agent_id": AGENT_ID,
                    "type": "rine.v1.task_request",
                    "encrypted_payload": "x",
                    "encryption_version": "hpke-v1",
                    "created_at": "2024-01-01T00:00:00Z",
                },
            )
        )
        respx.get(f"{API}/agents/{PEER_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": PEER_ID,
                    "signing_public_key": signing_public_key_to_jwk(peer_keys.signing.public_key),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(peer_keys.encryption.public_key),
                    },
                },
            )
        )
        post = respx.post(f"{API}/messages/{original_id}/reply").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "cccc1111-0000-0000-0000-000000000001",
                    "conversation_id": CONVERSATION_ID,
                    "from_agent_id": AGENT_ID,
                    "to_agent_id": PEER_ID,
                    "type": "rine.v1.task_response",
                    "encrypted_payload": "x",
                    "encryption_version": "hpke-v1",
                    "created_at": "2024-01-01T00:00:04Z",
                },
            )
        )

        await async_client.reply(original_id, {"text": "reply body"})

        body = json.loads(post.calls[0].request.content)
        assert "self_encrypted_payload" in body
        assert body["self_encrypted_payload"]
        await async_client.close()


# ---------------------------------------------------------------------------
# get_conversation_messages + thread()
# ---------------------------------------------------------------------------


def _mock_thread_endpoint(rows: list[dict]) -> None:
    # The real Slice A endpoint returns ConversationMessagesPage
    # (`{messages, truncated}`), NOT a cursor `{items}` page.
    respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": rows, "truncated": False})
    )


class TestGetConversationMessages:
    """Both-sided fetch decrypts each side, degrades gracefully."""

    @respx.mock
    async def test_async_decrypts_both_directions_and_degrades(self, async_client, tmp_config_dir):
        """Sent rows decrypt from the self-blob, received from the recipient blob (async)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)
        _mock_keys(agent_jwk, peer_keys)
        _mock_thread_endpoint(rows)

        msgs = await async_client.get_conversation_messages(CONVERSATION_ID)

        assert len(msgs) == 3
        assert all(isinstance(m, DecryptedMessage) for m in msgs)
        # SENT row decrypts from its self-blob.
        assert json.loads(msgs[0].plaintext)["text"].startswith("hi peer")
        assert msgs[0].decrypt_error is None
        # RECEIVED row decrypts from the recipient blob.
        assert json.loads(msgs[1].plaintext)["text"] == "got it, albatross noted"
        # Legacy SENT row with no self-blob degrades, never raises.
        assert msgs[2].plaintext is None
        assert msgs[2].decrypt_error is not None
        await async_client.close()

    @respx.mock
    async def test_async_classical_self_blob_on_hybrid_row_decrypts(
        self, async_client, tmp_config_dir
    ):
        """A classical self-blob on a ``hpke-hybrid-v1`` sent row still self-reads.

        The row is tagged hybrid (recipient negotiation) but the self-blob is a
        CLASSICAL ``hpke-v1`` seal; the swap pins the version to the blob's actual
        scheme instead of degrading the recoverable row to [unavailable].
        """
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)
        _mock_keys(agent_jwk, peer_keys)
        # The server tagged the row hybrid (sealed to a PQ-capable recipient),
        # but the Python SDK only ever self-seals classical.
        rows[0]["encryption_version"] = "hpke-hybrid-v1"
        _mock_thread_endpoint(rows)

        msgs = await async_client.get_conversation_messages(CONVERSATION_ID)

        assert msgs[0].decrypt_error is None
        assert json.loads(msgs[0].plaintext)["text"].startswith("hi peer")
        await async_client.close()

    @respx.mock
    def test_sync_decrypts_both_directions_and_degrades(self, sync_client, tmp_config_dir):
        """Sent rows decrypt from the self-blob, received from the recipient blob (sync)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)
        _mock_keys(agent_jwk, peer_keys)
        _mock_thread_endpoint(rows)

        msgs = sync_client.get_conversation_messages(CONVERSATION_ID)

        assert len(msgs) == 3
        assert json.loads(msgs[0].plaintext)["text"].startswith("hi peer")
        assert json.loads(msgs[1].plaintext)["text"] == "got it, albatross noted"
        assert msgs[2].plaintext is None
        assert msgs[2].decrypt_error is not None


class TestThread:
    """thread() renders the role-tagged transcript."""

    @respx.mock
    async def test_async_thread_renders_role_tagged_transcript(self, async_client, tmp_config_dir):
        """Both turns decrypt + render; undecryptable rows are [unavailable] (async)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)
        _mock_keys(agent_jwk, peer_keys)
        _mock_thread_endpoint(rows)

        entries = await async_client.thread(CONVERSATION_ID)

        assert len(entries) == 3
        assert all(isinstance(e, ThreadEntry) for e in entries)
        assert [e.direction for e in entries] == ["sent", "received", "sent"]
        # `{text}` payload is unwrapped to the bare string.
        assert entries[0].text.startswith("hi peer")
        assert entries[1].text == "got it, albatross noted"
        assert entries[1].sender_handle == "peer@myorg.rine.network"
        # F4: a successfully-decrypted+verified row carries its signature status.
        assert entries[1].verification_status == "verified"
        # Undecryptable legacy sent row renders [unavailable].
        assert entries[2].text == "[unavailable]"
        # F4: a degraded row reports its (non-"verified") status — never silently
        # "verified" — so a downstream consumer can exclude untrusted turns.
        assert entries[2].verification_status != "verified"
        await async_client.close()

    @respx.mock
    def test_sync_thread_renders_role_tagged_transcript(self, sync_client, tmp_config_dir):
        """Both turns decrypt + render; undecryptable rows are [unavailable] (sync)."""
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)
        _mock_keys(agent_jwk, peer_keys)
        _mock_thread_endpoint(rows)

        entries = sync_client.thread(CONVERSATION_ID)

        assert [e.direction for e in entries] == ["sent", "received", "sent"]
        assert entries[0].text.startswith("hi peer")
        assert entries[1].text == "got it, albatross noted"
        # F4: signature status is carried through (verified turn vs degraded turn).
        assert entries[1].verification_status == "verified"
        assert entries[2].text == "[unavailable]"
        assert entries[2].verification_status != "verified"

    @respx.mock
    async def test_async_thread_forwards_limit(self, async_client, tmp_config_dir):
        """thread(limit=N) forwards the limit query param."""
        _mock_token()
        _mock_agents()
        route = respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )

        await async_client.thread(CONVERSATION_ID, limit=5)

        assert b"limit=5" in route.calls[0].request.url.query
        await async_client.close()

    @respx.mock
    async def test_async_thread_forged_signature_is_unavailable(
        self, async_client, tmp_config_dir
    ):
        """F3 (fail-closed) — a forged-signature received turn is [unavailable].

        A received row whose sender signature does NOT match the key
        ``/agents/{id}/keys`` returns degrades to [unavailable] and never enters
        the transcript as trusted content (async).
        """
        _mock_token()
        _mock_agents()
        peer_keys = generate_agent_keys()
        rows, agent_jwk = _build_rows(tmp_config_dir, peer_keys)

        # Self-verify keys are honest; the PEER's published signing key is a
        # DIFFERENT key than the one that actually signed the received row, so
        # verification returns "invalid" → CryptoError → degrade.
        forged_keys = generate_agent_keys()
        respx.get(f"{API}/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(200, json=agent_jwk)
        )
        respx.get(f"{API}/agents/{PEER_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": PEER_ID,
                    "signing_public_key": signing_public_key_to_jwk(
                        forged_keys.signing.public_key
                    ),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(peer_keys.encryption.public_key),
                    },
                },
            )
        )
        _mock_thread_endpoint(rows)

        entries = await async_client.thread(CONVERSATION_ID)

        # The RECEIVED row (index 1) was forged → it must NOT render its plaintext.
        assert entries[1].direction == "received"
        assert entries[1].text == "[unavailable]"
        assert "albatross" not in entries[1].text
        # A forged turn reports "invalid" (NOT the default "unverifiable"), so a
        # consumer can distinguish a tampered turn from an honestly-unverifiable
        # one. This mirrors the TS SDK, which also tags such a row "invalid".
        assert entries[1].verification_status == "invalid"
        await async_client.close()

    @respx.mock
    async def test_async_thread_forwards_agent_override(self, async_client, tmp_config_dir):
        """F5 — thread(agent=...) forwards the X-Rine-Agent override header.

        A non-default agent must read its OWN thread (self-sealed sent rows are
        sealed to one specific agent).
        """
        _mock_token()
        _mock_agents()
        route = respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )
        # A UUID override resolves locally (no discovery round-trip) and is
        # forwarded verbatim as the X-Rine-Agent header.
        await async_client.thread(CONVERSATION_ID, agent=PEER_ID)

        assert route.calls[0].request.headers.get("x-rine-agent") == PEER_ID
        await async_client.close()


class TestRenderTextContentType:
    """``render_text`` gates the JSON unwrap on ``content_type`` like the TS SDK.

    The TS ``autoParsePlaintext`` only ``JSON.parse``s when the content type is
    ``application/json`` or absent; a ``text/plain`` body that merely looks like
    JSON is passed through literally. Python must match so a transcript reads
    identically across surfaces.
    """

    def test_application_json_unwraps_text_shape(self):
        """An application/json {text:...} body unwraps to the bare string."""
        from rine._thread import render_text

        assert render_text('{"text":"hi"}', "application/json") == "hi"

    def test_absent_content_type_unwraps_text_shape(self):
        """Absent content type defaults to application/json (TS parity)."""
        from rine._thread import render_text

        assert render_text('{"text":"hi"}', None) == "hi"

    def test_text_plain_json_looking_body_passes_through(self):
        """A text/plain JSON-shaped body is NOT unwrapped in either SDK."""
        from rine._thread import render_text

        assert render_text('{"text":"hi"}', "text/plain") == '{"text":"hi"}'
