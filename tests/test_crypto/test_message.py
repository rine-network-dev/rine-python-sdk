"""Tests for high-level message encrypt/decrypt."""

from __future__ import annotations

import json

import pytest

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
from rine._utils import to_base64url


SENDER_ID = "11111111-1111-1111-1111-111111111111"
RECIPIENT_ID = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"


class TestEncryptMessage:
    def test_encrypt_produces_hpke_v1(self, tmp_config_dir):
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)

        result = encrypt_message(
            tmp_config_dir, SENDER_ID, recipient_keys.encryption.public_key,
            {"hello": "world"},
        )
        assert result.encryption_version == "hpke-v1"
        assert result.sender_signing_kid == make_kid(SENDER_ID)
        assert len(result.encrypted_payload) > 0

    def test_encrypt_decrypt_round_trip(self, tmp_config_dir):
        sender_keys = generate_agent_keys()
        recipient_keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, sender_keys)
        save_agent_keys(tmp_config_dir, RECIPIENT_ID, recipient_keys)

        payload = {"task": "summarize", "content": "test data"}
        result = encrypt_message(
            tmp_config_dir, SENDER_ID, recipient_keys.encryption.public_key, payload,
        )

        # Mock HTTP client that returns sender's public keys
        class MockClient:
            def get(self, path, **kwargs):
                return {
                    "signing_public_key": signing_public_key_to_jwk(
                        sender_keys.signing.public_key
                    ),
                    "encryption_public_key": {
                        "kty": "OKP", "crv": "X25519",
                        "x": to_base64url(sender_keys.encryption.public_key),
                    },
                }

        decrypted = decrypt_message_sync(
            tmp_config_dir, RECIPIENT_ID, result.encrypted_payload, MockClient(),
        )
        assert json.loads(decrypted.plaintext) == payload
        assert decrypted.verified is True
        assert decrypted.verification_status == "verified"


class TestEncryptGroupMessage:
    def test_encrypt_group_produces_sender_key_v1(self, tmp_config_dir):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, keys)
        state = generate_sender_key(GROUP_ID, SENDER_ID)

        result, updated = encrypt_group_message(
            tmp_config_dir, SENDER_ID, GROUP_ID, state, {"group": "msg"},
        )
        assert result.encryption_version == "sender-key-v1"
        assert updated.message_index == state.message_index + 1

    def test_self_read_key_cached(self, tmp_config_dir):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, SENDER_ID, keys)
        state = generate_sender_key(GROUP_ID, SENDER_ID)
        original_index = state.message_index

        _, updated = encrypt_group_message(
            tmp_config_dir, SENDER_ID, GROUP_ID, state, {"test": True},
        )
        # Self-read key should be cached at the original index
        assert original_index in updated.skipped_keys
