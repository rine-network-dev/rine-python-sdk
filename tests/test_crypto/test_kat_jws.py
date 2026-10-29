"""Known-answer tests for the restricted JCS profile and the compact JWS."""

from __future__ import annotations

import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto.jws import (
    JwsError,
    JwsTyp,
    canonicalize,
    is_canonical_text,
    sign_jws,
    verify_jws,
)
from tests.test_crypto.kat import load_kat

#: The negative names that are chain-level checks, not JWS-level refusals.
_CHAIN_LEVEL_NEGATIVES = frozenset({"field_mismatch"})


def _strict_parse(text: str) -> Any:
    """Parse JSON text with the profile's duplicate-key and number refusals."""

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise JwsError(f"duplicate key: {key}")
            result[key] = item
        return result

    def refuse_number(token: str) -> Any:
        raise JwsError(f"number outside the integer profile: {token}")

    return json.loads(
        text,
        object_pairs_hook=no_duplicates,
        parse_float=refuse_number,
        parse_constant=refuse_number,
    )


def _entries(section: Any) -> list[dict[str, Any]]:
    """Return the fixture entries of a section that is a list or a mapping."""
    return list(section.values()) if isinstance(section, dict) else list(section)


def _assert_verifies(entry: dict[str, Any], typ: JwsTyp) -> None:
    """Assert one fixture JWS verifies under its signer and returns its payload."""
    assert verify_jws(entry["jws"], bytes.fromhex(entry["signer_pk"]), typ) == entry["payload"]


class TestJcsCanonicalize:
    """The canonicalize vectors: canonical text is reproduced and recognized."""

    def test_canonicalize_matches_fixture(self) -> None:
        """Every canonicalize vector re-serializes to its canonical text."""
        for entry in load_kat()["jcs"]["canonicalize"]:
            assert canonicalize(json.loads(entry["input"])) == entry["canonical"], entry["name"]

    def test_canonical_text_is_canonical(self) -> None:
        """Every canonical text is recognized as canonical."""
        for entry in load_kat()["jcs"]["canonicalize"]:
            assert is_canonical_text(entry["canonical"]) is True, entry["name"]


class TestJcsRefused:
    """The refused vectors: none is canonical text, and profile ones raise."""

    def test_every_refused_entry_is_not_canonical_text(self) -> None:
        """No refused input is canonical text."""
        for entry in load_kat()["jcs"]["refused"]:
            assert is_canonical_text(entry["input"]) is False, entry["name"]

    def test_profile_refusals_raise_or_fail_to_parse(self) -> None:
        """A profile refusal either fails to parse or raises from canonicalize."""
        for entry in load_kat()["jcs"]["refused"]:
            if entry["kind"] != "profile":
                continue
            try:
                parsed = _strict_parse(entry["input"])
            except (JwsError, ValueError):
                continue
            with pytest.raises(JwsError):
                canonicalize(parsed)


class TestCertificates:
    """Every fixture certificate verifies under its signer and expected typ."""

    def test_branch_certs_verify(self) -> None:
        """Branch certificates verify as ``BRANCH_CERT``."""
        for root in load_kat()["certs"]["roots"]:
            for entry in _entries(root["branch_certs"]):
                _assert_verifies(entry, JwsTyp.BRANCH_CERT)

    def test_agent_certs_verify(self) -> None:
        """Agent certificates verify as ``AGENT_CERT``."""
        for root in load_kat()["certs"]["roots"]:
            for entry in _entries(root["agent_certs"]):
                _assert_verifies(entry, JwsTyp.AGENT_CERT)

    def test_assertions_verify(self) -> None:
        """Assertions verify under the typ the fixture names."""
        for root in load_kat()["certs"]["roots"]:
            for entry in _entries(root["assertions"]):
                _assert_verifies(entry, JwsTyp(entry["typ"]))

    def test_register_pop_verifies(self) -> None:
        """Register proofs of possession verify under the typ the fixture names."""
        for root in load_kat()["certs"]["roots"]:
            entry = root["register_pop"]
            _assert_verifies(entry, JwsTyp(entry["typ"]))


class TestRoundTrip:
    """A freshly signed JWS verifies and returns its claims."""

    def test_sign_then_verify(self) -> None:
        """Signing with a fresh key round-trips through verification."""
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes_raw()
        public_key = private_key.public_key().public_bytes_raw()
        payload = {"branch": "main", "iat": 1790000000, "v": 1}
        compact = sign_jws(JwsTyp.BRANCH_CERT, payload, seed)
        assert verify_jws(compact, public_key, JwsTyp.BRANCH_CERT) == payload


class TestNegatives:
    """Every JWS-level negative is refused with a ``JwsError``."""

    @pytest.mark.parametrize("kind", ["branch_cert", "agent_cert"])
    def test_refusals(self, kind: str) -> None:
        """Each non-chain-level negative raises ``JwsError``."""
        for entry in load_kat()["certs"]["negatives"][kind]:
            if entry["name"] in _CHAIN_LEVEL_NEGATIVES:
                continue
            assert entry["expect"] == "refuse"
            with pytest.raises(JwsError):
                verify_jws(
                    entry["jws"],
                    bytes.fromhex(entry["verifier_pk"]),
                    JwsTyp(entry["expected_typ"]),
                )

    def test_non_zero_trailing_bits_in_a_part_are_refused(self) -> None:
        """A 64-byte signature has 4 spare bits in its last base64url character."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        compact = sign_jws(JwsTyp.BRANCH_CERT, {"v": 1}, private_key.private_bytes_raw())
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        body, last = compact[:-1], compact[-1]
        malleable = body + alphabet[alphabet.index(last) | 1]
        assert malleable != compact
        with pytest.raises(JwsError):
            verify_jws(malleable, public_key, JwsTyp.BRANCH_CERT)
