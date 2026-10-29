"""Tests for key generation, JWK serialization, and file persistence."""

from __future__ import annotations

import os

import pytest

from rine._crypto.keys import (
    agent_id_from_kid,
    agent_keys_exist,
    encryption_public_key_to_jwk,
    jwk_to_public_key,
    load_agent_keys,
    make_kid,
    public_keys_body,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.pq_keys import UPGRADE_DETAIL, jwk_to_pq_signing_public_key
from rine.errors import CryptoError
from rine.testing import WORLD


class TestKeyGeneration:
    def test_signing_keypair_sizes(self, agent_id):
        kp = WORLD.keys(agent_id).signing
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_encryption_keypair_sizes(self, agent_id):
        kp = WORLD.keys(agent_id).encryption
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32

    def test_agent_keys_has_both_pairs(self, agent_id):
        keys = WORLD.keys(agent_id)
        assert len(keys.signing.private_key) == 32
        assert len(keys.encryption.private_key) == 32

    def test_keypairs_are_unique(self, agent_id, other_agent_id):
        k1 = WORLD.keys(agent_id).signing
        k2 = WORLD.keys(other_agent_id).signing
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
        kid = make_kid("12345678-1234-1234-1234-123456789abc", 0)
        assert kid == "rine:12345678-1234-1234-1234-123456789abc#0"

    def test_make_kid_when_the_id_is_upper_case_then_it_mints_the_canonical_kid(self):
        kid = make_kid("12345678-1234-1234-1234-123456789ABC", 2)
        assert kid == "rine:12345678-1234-1234-1234-123456789abc#2"
        assert agent_id_from_kid(kid) == "12345678-1234-1234-1234-123456789abc"

    def test_agent_id_from_kid(self):
        uid = agent_id_from_kid("rine:12345678-1234-1234-1234-123456789abc#0")
        assert uid == "12345678-1234-1234-1234-123456789abc"

    def test_invalid_kid_raises(self):
        with pytest.raises(CryptoError, match="Invalid KID"):
            agent_id_from_kid("invalid")

    @pytest.mark.parametrize(
        "kid",
        [
            "rine:12345678-1234-1234-1234-123456789abc#0\n",
            "rine:12345678-1234-1234-1234-123456789ABC#0",
            "RINE:12345678-1234-1234-1234-123456789abc#0",
            "rine:12345678-1234-1234-1234-123456789abc#00",
        ],
        ids=["trailing-newline", "upper-case-uuid", "upper-case-prefix", "leading-zero-gen"],
    )
    def test_agent_id_from_kid_when_not_canonical_then_raises(self, kid):
        with pytest.raises(CryptoError, match="Invalid KID"):
            agent_id_from_kid(kid)


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


class TestPublicKeysBody:
    def test_public_keys_body_when_derived_agent_then_has_five_keys(self, agent_id):
        node = WORLD.node(agent_id)
        body = public_keys_body(WORLD.keys(agent_id), node.dsa_pk)
        assert set(body) == {
            "signing_public_key",
            "encryption_public_key",
            "pq_encryption_public_key",
            "pq_signing_public_key",
            "mls_signing_public_key",
        }

    def test_public_keys_body_when_derived_agent_then_pq_signing_decodes_to_passed_bytes(
        self, agent_id
    ):
        node = WORLD.node(agent_id)
        body = public_keys_body(WORLD.keys(agent_id), node.dsa_pk)
        assert jwk_to_pq_signing_public_key(body["pq_signing_public_key"]) == node.dsa_pk


class TestRetiredInstallUpgradeDetail:
    def test_load_agent_keys_when_mls_key_deleted_then_raises_upgrade_detail(
        self, tmp_config_dir, agent_id, agent_keys
    ):
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        os.remove(os.path.join(tmp_config_dir, "keys", agent_id, "mls.key"))
        with pytest.raises(CryptoError) as excinfo:
            load_agent_keys(tmp_config_dir, agent_id)
        assert str(excinfo.value) == UPGRADE_DETAIL

    def test_load_agent_keys_when_key_gen_deleted_then_raises_upgrade_detail(
        self, tmp_config_dir, agent_id, agent_keys
    ):
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        os.remove(os.path.join(tmp_config_dir, "keys", agent_id, "key_gen"))
        with pytest.raises(CryptoError) as excinfo:
            load_agent_keys(tmp_config_dir, agent_id)
        assert str(excinfo.value) == UPGRADE_DETAIL

    def test_load_agent_keys_when_signing_key_deleted_then_says_not_found(
        self, tmp_config_dir, agent_id, agent_keys
    ):
        save_agent_keys(tmp_config_dir, agent_id, agent_keys)
        os.remove(os.path.join(tmp_config_dir, "keys", agent_id, "signing.key"))
        with pytest.raises(CryptoError, match="Key file not found"):
            load_agent_keys(tmp_config_dir, agent_id)
