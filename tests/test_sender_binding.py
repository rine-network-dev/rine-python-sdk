"""An envelope's signature only counts for the sender the server authenticated.

A signature travels with the bytes it covers, so a peer holding a message signed
by B can re-seal it to a victim and post it as its own. These tests hold the
envelope's key id against the row's server-stamped sender on every decrypt path,
sync and async, and pair each refusal with the positive control that would catch
a check which simply rejects everything.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._crypto._key_cache import KeyCache
from rine._crypto._sender_verify import (
    verify_envelope_sender_async,
    verify_envelope_sender_sync,
)
from rine._crypto.keys import (
    generate_agent_keys,
    make_kid,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_group_message_sync,
    decrypt_message_async,
    decrypt_message_sync,
    encrypt_group_message,
    encrypt_message,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._utils import to_base64url
from rine.errors import SenderMismatchError, SignatureVerificationError
from tests.conftest import recipient_view

SENDER_B = "11111111-1111-1111-1111-111111111111"
IMPOSTOR_C = "cccccccc-cccc-cccc-cccc-cccccccccccc"
VICTIM_V = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
PAYLOAD = {"text": "the codeword is albatross"}


def _published(keys) -> dict:
    return {
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": {
            "kty": "OKP",
            "crv": "X25519",
            "x": to_base64url(keys.encryption.public_key),
        },
    }


class KeyServer:
    """A stand-in HTTP client that counts every key read it is asked for."""

    def __init__(self, keys) -> None:
        """Serve one agent's published keys, from cold."""
        self._keys_cache = KeyCache(600.0, 256)
        self._body = _published(keys)
        self.reads = 0

    def get(self, _path: str, **_kwargs: object) -> dict:
        """Answer a key read, counting it."""
        self.reads += 1
        return self._body


class AsyncKeyServer(KeyServer):
    """The async twin: the same counter behind an awaitable ``get``."""

    async def get(self, _path: str, **_kwargs: object) -> dict:  # type: ignore[override]
        """Answer a key read, counting it."""
        self.reads += 1
        return self._body


def _reseal_to_victim(config_dir: str) -> tuple[str, KeyServer]:
    """Post B's genuinely-signed message to the victim as if it were another's.

    The envelope is produced by B's own send path — a real key id, a real
    signature over the real plaintext — and then sealed to the victim, which
    needs nothing of B's but the victim's published encryption key.
    """
    sender_keys = generate_agent_keys()
    victim_keys = generate_agent_keys()
    save_agent_keys(config_dir, SENDER_B, sender_keys)
    save_agent_keys(config_dir, VICTIM_V, victim_keys)
    resealed = encrypt_message(config_dir, SENDER_B, recipient_view(victim_keys), PAYLOAD)
    return resealed.encrypted_payload, KeyServer(sender_keys)


class TestOneToOne:
    """The 1:1 DM path, classical and post-quantum alike.

    The version byte does not enter into it: the comparison is on the envelope
    the DM opens to, which is the same envelope under either seal.
    """

    def test_decrypt_when_kid_names_a_different_agent_then_rejects(self, tmp_config_dir):
        """B's envelope, posted as C's, is refused with the mismatch spelled out."""
        payload, server = _reseal_to_victim(tmp_config_dir)

        with pytest.raises(SenderMismatchError) as caught:
            decrypt_message_sync(tmp_config_dir, VICTIM_V, payload, server, IMPOSTOR_C)

        assert "does not match" in str(caught.value)
        assert isinstance(caught.value, SignatureVerificationError)

    async def test_decrypt_async_when_kid_names_a_different_agent_then_rejects(
        self, tmp_config_dir
    ):
        """The async twin refuses the same envelope."""
        payload, _ = _reseal_to_victim(tmp_config_dir)
        server = AsyncKeyServer(generate_agent_keys())

        with pytest.raises(SenderMismatchError):
            await decrypt_message_async(tmp_config_dir, VICTIM_V, payload, server, IMPOSTOR_C)

    def test_decrypt_when_kid_names_the_rows_sender_then_verifies(self, tmp_config_dir):
        """The false-positive guard: the same envelope, attributed correctly."""
        payload, server = _reseal_to_victim(tmp_config_dir)

        result = decrypt_message_sync(tmp_config_dir, VICTIM_V, payload, server, SENDER_B)

        assert json.loads(result.plaintext) == PAYLOAD
        assert result.verified is True
        assert result.verification_status == "verified"

    async def test_decrypt_async_when_kid_names_the_rows_sender_then_verifies(
        self, tmp_config_dir
    ):
        """The async false-positive guard."""
        sender_keys = generate_agent_keys()
        victim_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_B, sender_keys)
        save_agent_keys(tmp_config_dir, VICTIM_V, victim_keys)
        resealed = encrypt_message(tmp_config_dir, SENDER_B, recipient_view(victim_keys), PAYLOAD)
        server = AsyncKeyServer(sender_keys)

        result = await decrypt_message_async(
            tmp_config_dir, VICTIM_V, resealed.encrypted_payload, server, SENDER_B
        )

        assert result.verified is True
        assert result.verification_status == "verified"

    def test_decrypt_when_the_sender_is_the_reader_then_verifies(self, tmp_config_dir):
        """A message an agent sent to itself — the funnel's shape — still verifies."""
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_B, keys)
        sent = encrypt_message(tmp_config_dir, SENDER_B, recipient_view(keys), PAYLOAD)
        server = KeyServer(keys)

        result = decrypt_message_sync(
            tmp_config_dir, SENDER_B, sent.encrypted_payload, server, SENDER_B
        )

        assert result.verified is True
        assert result.sender_kid == make_kid(SENDER_B)

    async def test_decrypt_async_when_the_sender_is_the_reader_then_verifies(self, tmp_config_dir):
        """A sender re-opening its own self-sealed copy verifies (async)."""
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_B, keys)
        sent = encrypt_message(tmp_config_dir, SENDER_B, recipient_view(keys), PAYLOAD)
        server = AsyncKeyServer(keys)

        result = await decrypt_message_async(
            tmp_config_dir, SENDER_B, sent.self_encrypted_payload, server, SENDER_B
        )

        assert result.verified is True

    def test_decrypt_when_the_sender_id_differs_only_in_case_then_verifies(self, tmp_config_dir):
        """Two spellings of one server-issued id are one sender, not two."""
        payload, server = _reseal_to_victim(tmp_config_dir)

        result = decrypt_message_sync(
            tmp_config_dir, VICTIM_V, payload, server, f"  {SENDER_B.upper()}  "
        )

        assert result.verified is True


class TestNoNetworkOnMismatch:
    """A mismatch is not a question for the key endpoint."""

    def test_a_mismatch_reads_no_published_key(self, tmp_config_dir):
        """The refusal costs no request."""
        payload, server = _reseal_to_victim(tmp_config_dir)

        with pytest.raises(SenderMismatchError):
            decrypt_message_sync(tmp_config_dir, VICTIM_V, payload, server, IMPOSTOR_C)

        assert server.reads == 0

    async def test_a_mismatch_reads_no_published_key_async(self, tmp_config_dir):
        """The refusal costs no request (async)."""
        payload, _ = _reseal_to_victim(tmp_config_dir)
        server = AsyncKeyServer(generate_agent_keys())

        with pytest.raises(SenderMismatchError):
            await decrypt_message_async(tmp_config_dir, VICTIM_V, payload, server, IMPOSTOR_C)

        assert server.reads == 0

    def test_verify_reports_the_mismatch_without_a_verdict_on_the_bytes(self, tmp_config_dir):
        """The status distinguishes wrong-agent from tampered-bytes."""
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_B, keys)
        server = KeyServer(keys)

        verification = verify_envelope_sender_sync(
            make_kid(SENDER_B), b"payload", b"signature", server, IMPOSTOR_C
        )

        assert verification.verification_status == "sender-mismatch"
        assert verification.verified is False
        assert server.reads == 0

    async def test_verify_async_reports_the_mismatch(self, tmp_config_dir):
        """The status is reported the same way on the async path."""
        server = AsyncKeyServer(generate_agent_keys())

        verification = await verify_envelope_sender_async(
            make_kid(SENDER_B), b"payload", b"signature", server, IMPOSTOR_C
        )

        assert verification.verification_status == "sender-mismatch"
        assert verification.verified is False
        assert server.reads == 0


def _group_message(config_dir: str) -> tuple[str, object]:
    """One sender-key group message from B, with B's key ingested by the victim.

    Returns the ciphertext and B's keypair, so a test can hand the key endpoint
    either the honest key or another one.
    """
    sender_keys = generate_agent_keys()
    save_agent_keys(config_dir, SENDER_B, sender_keys)
    # The reader owns this config dir, so it owns keys in it: the group decrypt's
    # downgrade guard reads the reader's own MLS state, which is keyed by its
    # signing key.
    save_agent_keys(config_dir, VICTIM_V, generate_agent_keys())
    state = generate_sender_key(GROUP_ID, SENDER_B)
    save_sender_key_state(
        config_dir,
        VICTIM_V,
        GROUP_ID,
        [
            SenderKeyState(
                sender_key_id=state.sender_key_id,
                group_id=GROUP_ID,
                sender_agent_id=SENDER_B,
                chain_key=state.chain_key,
                message_index=state.message_index,
            )
        ],
    )
    # The sender's own copy, which ``encrypt_group_message`` advances in place. A
    # stand-in sender needs it as much as a real one does: the tail refuses a
    # state that is on no disk at all rather than discarding the advance.
    save_sender_key_state(config_dir, SENDER_B, GROUP_ID, [state])
    sealed, _ = encrypt_group_message(config_dir, SENDER_B, GROUP_ID, state, PAYLOAD)
    return sealed.encrypted_payload, sender_keys


def _persisted_index(config_dir: str) -> int:
    states = load_sender_key_states(config_dir, VICTIM_V, GROUP_ID)
    return next(s.message_index for s in states if s.sender_agent_id == SENDER_B)


class TestGroupSenderKey:
    """A group message refused leaves the ratchet where the sender left it."""

    def test_decrypt_when_kid_names_a_different_agent_then_rejects_before_persisting(
        self, tmp_config_dir
    ):
        """The refusal happens before the advance is saved, so the message still reads."""
        payload, sender_keys = _group_message(tmp_config_dir)
        server = KeyServer(sender_keys)
        before = _persisted_index(tmp_config_dir)

        with pytest.raises(SenderMismatchError):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, IMPOSTOR_C
            )

        # The ratchet is not spent on a message this client refuses, so the
        # honest message at that index is still readable afterwards.
        assert _persisted_index(tmp_config_dir) == before
        result = decrypt_group_message_sync(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )
        assert json.loads(result.plaintext) == PAYLOAD
        assert result.verified is True
        assert _persisted_index(tmp_config_dir) == before + 1

    async def test_decrypt_async_when_kid_names_a_different_agent_then_rejects(
        self, tmp_config_dir
    ):
        """The async twin refuses and persists nothing either."""
        payload, sender_keys = _group_message(tmp_config_dir)
        before = _persisted_index(tmp_config_dir)
        server = AsyncKeyServer(sender_keys)

        with pytest.raises(SenderMismatchError):
            await decrypt_group_message_async(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, IMPOSTOR_C
            )

        assert _persisted_index(tmp_config_dir) == before
        assert server.reads == 0
        result = await decrypt_group_message_async(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )
        assert json.loads(result.plaintext) == PAYLOAD


# ---------------------------------------------------------------------------
# The receive surfaces: what a caller of read() actually sees
# ---------------------------------------------------------------------------

API = "https://rine.network"
MESSAGE_ID = "dddddddd-0000-0000-0000-000000000001"


def _mock_server(agent_id: str, row: dict, sender_keys) -> tuple[object, object]:
    """Serve the row plus both candidate senders' keys; report if either is read."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": agent_id,
                        "name": "me",
                        "handle": "me@myorg.rine.network",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )
    respx.get(f"{API}/messages/{MESSAGE_ID}").mock(return_value=httpx.Response(200, json=row))
    signer_keys = respx.get(f"{API}/agents/{SENDER_B}/keys").mock(
        return_value=httpx.Response(200, json=_published(sender_keys))
    )
    impostor_keys = respx.get(f"{API}/agents/{IMPOSTOR_C}/keys").mock(
        return_value=httpx.Response(200, json=_published(sender_keys))
    )
    return signer_keys, impostor_keys


def _row_from(config_dir: str, agent_id: str, stamped_sender: str) -> tuple[dict, object]:
    """A row the server attributes to ``stamped_sender``, with B's envelope inside."""
    from rine._crypto.keys import load_agent_keys

    sender_keys = generate_agent_keys()
    save_agent_keys(config_dir, SENDER_B, sender_keys)
    resealed = encrypt_message(
        config_dir, SENDER_B, recipient_view(load_agent_keys(config_dir, agent_id)), PAYLOAD
    )
    row = {
        "id": MESSAGE_ID,
        "conversation_id": "dddddddd-0000-0000-0000-000000000002",
        "from_agent_id": stamped_sender,
        "to_agent_id": agent_id,
        "type": "rine.v1.task_request",
        "encrypted_payload": resealed.encrypted_payload,
        "encryption_version": "hpke-v1",
        "sender_signing_kid": make_kid(SENDER_B),
        "created_at": "2024-01-01T00:00:00Z",
    }
    return row, sender_keys


class TestReceiveSurfaces:
    """The status a reader is handed, and the plaintext it is not."""

    @respx.mock
    def test_read_when_the_row_names_another_sender_then_reports_the_mismatch(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """A reader is handed the mismatch and no plaintext."""
        row, sender_keys = _row_from(tmp_config_dir, agent_id, IMPOSTOR_C)
        signer_keys, impostor_keys = _mock_server(agent_id, row, sender_keys)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.verification_status == "sender-mismatch"
        assert msg.verified is False
        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert not signer_keys.called
        assert not impostor_keys.called

    @respx.mock
    async def test_read_async_when_the_row_names_another_sender_then_reports_the_mismatch(
        self, async_client, tmp_config_dir, agent_id
    ):
        """A reader is handed the mismatch and no plaintext (async)."""
        row, sender_keys = _row_from(tmp_config_dir, agent_id, IMPOSTOR_C)
        signer_keys, impostor_keys = _mock_server(agent_id, row, sender_keys)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.verification_status == "sender-mismatch"
        assert msg.verified is False
        assert msg.plaintext is None
        assert not signer_keys.called
        assert not impostor_keys.called
        await async_client.close()

    @respx.mock
    def test_read_when_the_row_names_the_signer_then_the_message_reads(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """The receive-surface false-positive guard."""
        row, sender_keys = _row_from(tmp_config_dir, agent_id, SENDER_B)
        _mock_server(agent_id, row, sender_keys)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.verification_status == "verified"
        assert msg.verified is True
        assert json.loads(msg.plaintext) == PAYLOAD

    @respx.mock
    async def test_read_async_when_the_row_names_the_signer_then_the_message_reads(
        self, async_client, tmp_config_dir, agent_id
    ):
        """The receive-surface false-positive guard (async)."""
        row, sender_keys = _row_from(tmp_config_dir, agent_id, SENDER_B)
        _mock_server(agent_id, row, sender_keys)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.verification_status == "verified"
        assert json.loads(msg.plaintext) == PAYLOAD
        await async_client.close()
