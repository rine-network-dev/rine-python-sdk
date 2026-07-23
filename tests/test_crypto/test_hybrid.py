"""``hpke-hybrid-v1`` — the post-quantum 1:1 DM envelope.

The forward vectors these read are produced by rine-core, the TypeScript stack,
via ``tests/fixtures/generate_hybrid_vectors.mjs``. That is deliberate: a Python
round-trip only proves Python agrees with itself, and the property that matters
is that a message either stack seals opens in the other.

Both directions are covered, because ML-KEM makes them genuinely distinct code
paths — encapsulation and decapsulation are different operations, so proving
noble-encaps → libcrux-decaps says nothing about libcrux-encaps → noble-decaps:

- TS-seals → Python-opens: :class:`TestTypeScriptInterop`, forward vectors above.
- Python-seals → TS-opens: :class:`TestReverseInterop` keeps the committed
  ``hybrid_reverse_vector.json`` golden readable here, and
  ``tests/fixtures/verify_hybrid_reverse.mjs`` is the noble side that actually
  opens that Python-sealed payload (run when the fixture is regenerated).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rine._crypto import hybrid
from rine._crypto.envelope import decode_envelope
from rine._crypto.keys import (
    AgentKeys,
    KeyPair,
    generate_agent_keys,
    load_agent_keys,
    save_agent_keys,
)
from rine._crypto.pq_keys import (
    generate_pq_keypair,
    jwk_to_pq_public_key,
    pq_key_path,
    pq_public_key_to_jwk,
)
from rine._utils import from_base64url
from rine.errors import CryptoError

FIXTURES = Path(__file__).parent.parent / "fixtures" / "hybrid_vectors.json"
REVERSE_FIXTURES = Path(__file__).parent.parent / "fixtures" / "hybrid_reverse_vector.json"


@pytest.fixture(scope="module")
def vectors():
    """Load the TypeScript-produced hybrid vectors."""
    with open(FIXTURES) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def reverse_vectors():
    """Load the Python-sealed reverse-interop golden that noble opens."""
    with open(REVERSE_FIXTURES) as f:
        return json.load(f)


@pytest.fixture
def recipient_keys(vectors):
    """The vector's recipient, as this SDK's key objects."""
    return AgentKeys(
        signing=KeyPair(
            private_key=from_base64url(vectors["recipient_signing_private_key"]),
            public_key=b"",
        ),
        encryption=KeyPair(
            private_key=from_base64url(vectors["recipient_encryption_private_key"]),
            public_key=from_base64url(vectors["recipient_encryption_public_key"]),
        ),
        pq_encryption=KeyPair(
            private_key=from_base64url(vectors["recipient_pq_private_key"]),
            public_key=from_base64url(vectors["recipient_pq_public_key"]),
        ),
    )


class TestTypeScriptInterop:
    """Ciphertext sealed by rine-core opens here, byte-for-byte."""

    def test_ts_sealed_payload_when_opened_in_python_yields_the_exact_plaintext(
        self, vectors, recipient_keys
    ):
        envelope = hybrid.open(
            recipient_keys.encryption.private_key,
            recipient_keys.pq_encryption.private_key,
            from_base64url(vectors["encrypted_payload"]),
        )
        decoded = decode_envelope(envelope)

        assert decoded.payload.decode() == vectors["plaintext"]
        assert decoded.kid == vectors["sender_signing_kid"]

    def test_ts_sealed_payload_when_aad_matches_is_accepted(self, vectors, recipient_keys):
        plaintext = hybrid.open(
            recipient_keys.encryption.private_key,
            recipient_keys.pq_encryption.private_key,
            from_base64url(vectors["aad_payload"]),
            from_base64url(vectors["aad"]),
        )

        assert plaintext.decode() == vectors["aad_plaintext"]

    def test_ts_sealed_payload_when_aad_is_omitted_is_refused(self, vectors, recipient_keys):
        with pytest.raises(CryptoError, match="hpke-hybrid-v1 decryption failed"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                recipient_keys.pq_encryption.private_key,
                from_base64url(vectors["aad_payload"]),
            )

    def test_python_seals_to_ts_minted_keys_and_python_opens_it(self, vectors, recipient_keys):
        # Python seals to the TypeScript-MINTED public keys and opens it with the
        # TypeScript-minted private keys. This proves the key material crosses the
        # stacks and Python's own seal/open round-trips on it — it does NOT prove
        # noble can open a libcrux-sealed payload (encaps here is still Python).
        # That reverse direction is proven by TestReverseInterop below plus
        # tests/fixtures/verify_hybrid_reverse.mjs.
        payload = hybrid.seal(
            recipient_keys.encryption.public_key,
            recipient_keys.pq_encryption.public_key,
            b"sealed by python",
        )

        assert (
            hybrid.open(
                recipient_keys.encryption.private_key,
                recipient_keys.pq_encryption.private_key,
                payload,
            )
            == b"sealed by python"
        )

    def test_ts_self_blob_when_opened_by_its_sender_yields_the_same_plaintext(self, vectors):
        # rine-core self-seals hybrid when the SENDER has a PQ key, so a sent row
        # is readable by its own sender — the property `thread()` depends on.
        envelope = hybrid.open(
            from_base64url(vectors["sender_encryption_private_key"]),
            from_base64url(vectors["sender_pq_private_key"]),
            from_base64url(vectors["self_encrypted_payload"]),
        )

        assert decode_envelope(envelope).payload.decode() == vectors["plaintext"]


class TestReverseInterop:
    """Python-seals → TS-opens: the ``hybrid_reverse_vector.json`` golden.

    The bytes here were sealed by Python (libcrux ML-KEM encaps) and are opened
    by noble in ``tests/fixtures/verify_hybrid_reverse.mjs`` — that .mjs is the
    load-bearing cross-stack proof. These tests keep the golden honest: a
    regeneration that produced an unopenable payload fails here before it could
    ever be handed to noble.
    """

    def test_python_sealed_golden_when_opened_here_yields_its_plaintext(self, reverse_vectors):
        plaintext = hybrid.open(
            from_base64url(reverse_vectors["recipient_encryption_private_key"]),
            from_base64url(reverse_vectors["recipient_pq_private_key"]),
            from_base64url(reverse_vectors["encrypted_payload"]),
        )

        assert plaintext.decode() == reverse_vectors["plaintext"]

    def test_python_sealed_golden_when_aad_matches_is_accepted(self, reverse_vectors):
        plaintext = hybrid.open(
            from_base64url(reverse_vectors["recipient_encryption_private_key"]),
            from_base64url(reverse_vectors["recipient_pq_private_key"]),
            from_base64url(reverse_vectors["aad_payload"]),
            from_base64url(reverse_vectors["aad"]),
        )

        assert plaintext.decode() == reverse_vectors["plaintext"]

    def test_python_sealed_golden_when_aad_is_omitted_is_refused(self, reverse_vectors):
        with pytest.raises(CryptoError, match="hpke-hybrid-v1 decryption failed"):
            hybrid.open(
                from_base64url(reverse_vectors["recipient_encryption_private_key"]),
                from_base64url(reverse_vectors["recipient_pq_private_key"]),
                from_base64url(reverse_vectors["aad_payload"]),
            )


class TestWireFormat:
    """The layout is wire format, not an implementation detail."""

    def test_sealed_payload_when_inspected_has_the_documented_header(self, recipient_keys):
        payload = hybrid.seal(
            recipient_keys.encryption.public_key,
            recipient_keys.pq_encryption.public_key,
            b"x" * 16,
        )

        assert payload[0] == hybrid.VERSION_HYBRID == 0x03
        # 1 version + 32 X25519 + 1088 ML-KEM + 16 plaintext + 16 GCM tag.
        assert len(payload) == 1 + 32 + 1088 + 16 + 16

    def test_ts_payload_and_python_payload_when_compared_have_the_same_header_size(
        self, vectors, recipient_keys
    ):
        ts_payload = from_base64url(vectors["aad_payload"])
        py_payload = hybrid.seal(
            recipient_keys.encryption.public_key,
            recipient_keys.pq_encryption.public_key,
            vectors["aad_plaintext"].encode(),
            from_base64url(vectors["aad"]),
        )

        assert len(py_payload) == len(ts_payload)

    def test_classical_payload_when_passed_to_hybrid_open_is_refused_by_version(
        self, recipient_keys
    ):
        classical = bytes([0x01]) + b"\x00" * 1200

        with pytest.raises(CryptoError, match="Unknown hybrid version: 0x01"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                recipient_keys.pq_encryption.private_key,
                classical,
            )

    def test_truncated_payload_when_opened_is_refused_before_any_crypto(self, recipient_keys):
        with pytest.raises(CryptoError, match="too short"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                recipient_keys.pq_encryption.private_key,
                bytes([0x03]) + b"\x00" * 64,
            )

    def test_tampered_ciphertext_when_opened_is_refused(self, vectors, recipient_keys):
        payload = bytearray(from_base64url(vectors["encrypted_payload"]))
        payload[-1] ^= 0xFF

        with pytest.raises(CryptoError, match="hpke-hybrid-v1 decryption failed"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                recipient_keys.pq_encryption.private_key,
                bytes(payload),
            )

    def test_wrong_pq_key_when_opening_is_refused_by_the_aead(self, vectors, recipient_keys):
        other_private, _ = generate_pq_keypair()

        with pytest.raises(CryptoError, match="hpke-hybrid-v1 decryption failed"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                other_private,
                from_base64url(vectors["encrypted_payload"]),
            )

    def test_short_pq_key_when_opening_is_refused_with_its_length(self, vectors, recipient_keys):
        with pytest.raises(CryptoError, match="must be 2400 bytes, got 32"):
            hybrid.open(
                recipient_keys.encryption.private_key,
                b"\x00" * 32,
                from_base64url(vectors["encrypted_payload"]),
            )


class TestPqKeyLifecycle:
    """Minting, persisting and publishing the agent's ML-KEM key."""

    def test_generated_agent_keys_when_inspected_carry_a_pq_keypair(self):
        keys = generate_agent_keys()

        assert keys.pq_encryption is not None
        assert len(keys.pq_encryption.private_key) == 2400
        assert len(keys.pq_encryption.public_key) == 1184

    def test_saved_agent_keys_when_reloaded_round_trip_the_pq_key(self, tmp_config_dir, agent_id):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, agent_id, keys)

        loaded = load_agent_keys(tmp_config_dir, agent_id)

        assert loaded.pq_encryption is not None
        assert loaded.pq_encryption.private_key == keys.pq_encryption.private_key
        assert loaded.pq_encryption.public_key == keys.pq_encryption.public_key

    def test_agent_without_a_pq_key_file_when_loaded_has_none(self, tmp_config_dir, agent_id):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, agent_id, keys)
        Path(pq_key_path(tmp_config_dir, agent_id)).unlink()

        assert load_agent_keys(tmp_config_dir, agent_id).pq_encryption is None

    def test_corrupt_pq_key_file_when_loaded_is_an_error_not_a_silent_downgrade(
        self, tmp_config_dir, agent_id
    ):
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, agent_id, keys)
        Path(pq_key_path(tmp_config_dir, agent_id)).write_text("bm90LWEta2V5")

        with pytest.raises(CryptoError, match="Invalid PQ key size"):
            load_agent_keys(tmp_config_dir, agent_id)

    def test_pq_key_file_when_written_is_owner_only(self, tmp_config_dir, agent_id):
        save_agent_keys(tmp_config_dir, agent_id, generate_agent_keys())

        assert Path(pq_key_path(tmp_config_dir, agent_id)).stat().st_mode & 0o777 == 0o600

    def test_ts_published_pq_key_when_read_here_is_the_same_key(self, vectors):
        published = jwk_to_pq_public_key(
            {"kty": "MLKEM", "alg": "ML-KEM-768", "x": vectors["recipient_pq_public_key"]}
        )

        assert published == from_base64url(vectors["recipient_pq_public_key"])

    def test_published_pq_key_when_round_tripped_keeps_the_wrapper_ts_expects(self):
        _, public = generate_pq_keypair()

        jwk = pq_public_key_to_jwk(public)

        assert jwk["kty"] == "MLKEM"
        assert jwk["alg"] == "ML-KEM-768"
        assert jwk_to_pq_public_key(jwk) == public

    def test_pq_key_wrapper_of_the_wrong_length_when_read_is_refused(self):
        with pytest.raises(CryptoError, match="expected 1184 bytes"):
            jwk_to_pq_public_key({"kty": "MLKEM", "alg": "ML-KEM-768", "x": "AAAA"})
