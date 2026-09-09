"""Tests for high-level message encrypt/decrypt."""

from __future__ import annotations

import json

from rine._crypto._key_cache import KeyCache
from rine._crypto.keys import (
    generate_agent_keys,
    make_kid,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.message import (
    decrypt_message_sync,
    encrypt_group_message,
    encrypt_message,
)
from rine._crypto.sender_keys import generate_sender_key
from rine._crypto.sender_keys_helpers import save_sender_key_state
from rine._utils import to_base64url
from tests.conftest import recipient_view

SENDER_ID = "11111111-1111-1111-1111-111111111111"
RECIPIENT_ID = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"


class TestEncryptMessage:
    def test_encrypt_to_a_pq_recipient_produces_hpke_hybrid_v1(self, tmp_config_dir):
        """A recipient that publishes an ML-KEM key gets the post-quantum envelope."""
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)

        result = encrypt_message(
            tmp_config_dir,
            SENDER_ID,
            recipient_view(recipient_keys),
            {"hello": "world"},
        )
        assert result.encryption_version == "hpke-hybrid-v1"
        assert result.sender_signing_kid == make_kid(SENDER_ID)
        assert len(result.encrypted_payload) > 0

    def test_encrypt_to_a_classical_recipient_produces_hpke_v1(self, tmp_config_dir):
        """A recipient with no ML-KEM key still gets the classical envelope."""
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        recipient_keys.pq_encryption = None
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)

        result = encrypt_message(
            tmp_config_dir,
            SENDER_ID,
            recipient_view(recipient_keys),
            {"hello": "world"},
        )
        assert result.encryption_version == "hpke-v1"

    def test_encrypt_produces_self_seal_blob(self, tmp_config_dir):
        """encrypt_message sets a self_encrypted_payload distinct from the recipient copy."""
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)

        result = encrypt_message(
            tmp_config_dir,
            SENDER_ID,
            recipient_view(recipient_keys),
            {"hello": "world"},
        )
        assert result.self_encrypted_payload is not None
        assert len(result.self_encrypted_payload) > 0
        # The self-blob is a DIFFERENT ciphertext than the recipient copy.
        assert result.self_encrypted_payload != result.encrypted_payload

    def test_self_seal_round_trip_sender_reads_own_message(self, tmp_config_dir):
        """The sender can self-read its own message via the blob."""
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)
        save_agent_keys(tmp_config_dir, RECIPIENT_ID, recipient_keys)

        payload = {"task": "remember", "codeword": "albatross"}
        result = encrypt_message(
            tmp_config_dir,
            SENDER_ID,
            recipient_view(recipient_keys),
            payload,
        )

        class MockClient:
            def __init__(self):
                self._keys_cache = KeyCache(600.0, 256)

            def get(self, path, **kwargs):
                return {
                    "signing_public_key": signing_public_key_to_jwk(
                        sender_keys.signing.public_key
                    ),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(sender_keys.encryption.public_key),
                    },
                }

        # Decrypt the SELF blob with the SENDER's own id — own signature verifies.
        assert result.self_encrypted_payload is not None
        decrypted = decrypt_message_sync(
            tmp_config_dir,
            SENDER_ID,
            result.self_encrypted_payload,
            MockClient(),
            SENDER_ID,
        )
        assert json.loads(decrypted.plaintext) == payload
        assert decrypted.verified is True
        assert decrypted.verification_status == "verified"

    def test_encrypt_decrypt_round_trip(self, tmp_config_dir):
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)
        save_agent_keys(tmp_config_dir, RECIPIENT_ID, recipient_keys)

        payload = {"task": "summarize", "content": "test data"}
        result = encrypt_message(
            tmp_config_dir,
            SENDER_ID,
            recipient_view(recipient_keys),
            payload,
        )

        # Mock HTTP client that returns sender's public keys
        class MockClient:
            def __init__(self):
                self._keys_cache = KeyCache(600.0, 256)

            def get(self, path, **kwargs):
                return {
                    "signing_public_key": signing_public_key_to_jwk(
                        sender_keys.signing.public_key
                    ),
                    "encryption_public_key": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": to_base64url(sender_keys.encryption.public_key),
                    },
                }

        decrypted = decrypt_message_sync(
            tmp_config_dir,
            RECIPIENT_ID,
            result.encrypted_payload,
            MockClient(),
            SENDER_ID,
        )
        assert json.loads(decrypted.plaintext) == payload
        assert decrypted.verified is True
        assert decrypted.verification_status == "verified"


class TestEncryptGroupMessage:
    def test_encrypt_group_produces_sender_key_v1(self, tmp_config_dir):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, keys)
        state = generate_sender_key(GROUP_ID, SENDER_ID)
        # The sender's own copy, which ``encrypt_group_message`` advances in place.
        # A stand-in sender needs it as much as a real one does: the tail refuses a
        # state that is on no disk at all rather than discarding the advance.
        save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [state])

        result, updated = encrypt_group_message(
            tmp_config_dir,
            SENDER_ID,
            GROUP_ID,
            state,
            {"group": "msg"},
        )
        assert result.encryption_version == "sender-key-v1"
        assert updated.message_index == state.message_index + 1
        # Group sends carry NO self-seal blob (they self-read via the cache).
        assert result.self_encrypted_payload is None

    def test_self_read_key_cached(self, tmp_config_dir):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, keys)
        state = generate_sender_key(GROUP_ID, SENDER_ID)
        save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [state])
        original_index = state.message_index

        _, updated = encrypt_group_message(
            tmp_config_dir,
            SENDER_ID,
            GROUP_ID,
            state,
            {"test": True},
        )
        # Self-read key should be cached at the original index
        assert original_index in updated.skipped_keys
