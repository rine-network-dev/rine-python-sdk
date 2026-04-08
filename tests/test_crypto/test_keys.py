"""Tests for key generation, JWK serialization, and file persistence."""

from __future__ import annotations

import os

import pytest

from rine._crypto.keys import (
    agent_id_from_kid,
    agent_keys_exist,
    encryption_public_key_to_jwk,
    generate_agent_keys,
    generate_encryption_keypair,
    generate_signing_keypair,
    jwk_to_public_key,
    load_agent_keys,
    make_kid,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine.errors import CryptoError


class TestKeyGeneration:
    def test_signing_keypair_sizes(self):
        kp = generate_signing_keypair()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_encryption_keypair_sizes(self):
        kp = generate_encryption_keypair()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_agent_keys_has_both_pairs(self):
        keys = generate_agent_keys()
        assert len(keys.signing.private_key) == 32
        assert len(keys.encryption.private_key) == 32

    def test_keypairs_are_unique(self):
        k1 = generate_signing_keypair()
        k2 = generate_signing_keypair()
        assert k1.private_key != k2.private_key


class TestJWK:
    def test_signing_public_key_to_jwk(self, agent_keys):
        jwk = signing_public_key_to_jwk(agent_keys.signing.public_key)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk

    def test_encryption_public_key_to_jwk(self, agent_keys):
        jwk = encryption_public_key_to_jwk(agent_keys.encryption.public_key)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "X25519"
        assert "x" in jwk

    def test_jwk_round_trip(self, agent_keys):
        jwk = signing_public_key_to_jwk(agent_keys.signing.public_key)
        recovered = jwk_to_public_key(jwk)
        assert recovered == agent_keys.signing.public_key

    def test_jwk_missing_x_raises(self):
        with pytest.raises(CryptoError, match="missing 'x'"):
            jwk_to_public_key({"kty": "OKP", "crv": "Ed25519"})

    def test_jwk_wrong_size_raises(self):
        from rine._utils import to_base64url
        with pytest.raises(CryptoError, match="Invalid key size"):
            jwk_to_public_key({"x": to_base64url(b"short")})


class TestKID:
    def test_make_kid(self):
        kid = make_kid("12345678-1234-1234-1234-123456789abc")
        assert kid == "rine:12345678-1234-1234-1234-123456789abc"

    def test_agent_id_from_kid(self):
        uid = agent_id_from_kid("rine:12345678-1234-1234-1234-123456789abc")
        assert uid == "12345678-1234-1234-1234-123456789abc"

    def test_invalid_kid_raises(self):
        with pytest.raises(CryptoError, match="Invalid KID"):
            agent_id_from_kid("invalid")


class TestKeyPersistence:
    def test_save_and_load_round_trip(self, tmp_config_dir, agent_id, agent_keys):
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        loaded = load_agent_keys(tmp_config_dir, agent_id)
        assert loaded.signing.private_key == agent_keys.signing.private_key
        assert loaded.encryption.private_key == agent_keys.encryption.private_key
        assert loaded.signing.public_key == agent_keys.signing.public_key
        assert loaded.encryption.public_key == agent_keys.encryption.public_key

    def test_key_file_permissions(self, tmp_config_dir, agent_id, agent_keys):
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        sign_path = os.path.join(tmp_config_dir, "keys", agent_id, "signing.key")
        stat = os.stat(sign_path)
        assert stat.st_mode & 0o777 == 0o600

    def test_agent_keys_exist(self, tmp_config_dir, agent_id, agent_keys):
        assert not agent_keys_exist(tmp_config_dir, agent_id)
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        assert agent_keys_exist(tmp_config_dir, agent_id)

    def test_load_missing_raises(self, tmp_config_dir, agent_id):
        with pytest.raises(CryptoError, match="not found"):
            load_agent_keys(tmp_config_dir, agent_id)

    def test_invalid_agent_id_raises(self, tmp_config_dir, agent_keys):
        with pytest.raises(CryptoError, match="Invalid agent_id"):
            save_agent_keys(tmp_config_dir, "not-a-uuid", agent_keys)
