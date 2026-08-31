"""Verification words — the derivation, and the byte-compat contract.

The goldens are generated from the **server's** implementation
(``tests/fixtures/generate_verification_words_vectors.py``) and replayed by
three suites: the server's, ``rine-core``'s vitest and this one. Three
implementations of one derivation is exactly the shape that drifts, and this
file is one of the three places that would notice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mnemonic import Mnemonic

from rine._utils import from_base64url
from rine.verification_words import (
    compare_verification_words,
    verification_words_for_jwk,
    verification_words_for_key,
)

FIXTURES = Path(__file__).parent / "fixtures" / "verification_words_vectors.json"


@pytest.fixture(scope="module")
def goldens() -> dict:
    return json.loads(FIXTURES.read_text())


@pytest.fixture(scope="module")
def by_name(goldens: dict) -> dict:
    return {v["name"]: v for v in goldens["vectors"]}


def test_words_for_jwk_when_replaying_goldens_then_matches_the_server(goldens: dict):
    for vector in goldens["vectors"]:
        assert verification_words_for_jwk(vector["jwk"]) == vector["words"], vector["name"]


def test_words_for_key_when_replaying_goldens_then_matches_the_server(goldens: dict):
    for vector in goldens["vectors"]:
        raw = from_base64url(vector["jwk"]["x"])
        assert verification_words_for_key(raw) == vector["words"], vector["name"]


def test_words_when_one_key_bit_changes_then_the_words_change(goldens: dict, by_name: dict):
    baseline, flipped = (by_name[n] for n in goldens["one_bit_flip"])
    assert verification_words_for_jwk(flipped["jwk"]) != verification_words_for_jwk(
        baseline["jwk"]
    )


def test_words_when_x_carries_padding_then_the_answer_is_unchanged(goldens: dict, by_name: dict):
    unpadded, padded = (by_name[n] for n in goldens["same_key"])
    assert verification_words_for_jwk(padded["jwk"]) == verification_words_for_jwk(unpadded["jwk"])


def test_words_when_given_any_key_then_five_bip39_words_come_back():
    wordlist = set(Mnemonic("english").wordlist)
    words = verification_words_for_key(bytes([7]) * 32).split(" ")
    assert len(words) == 5
    assert all(word in wordlist for word in words)


def test_words_when_the_key_is_not_32_bytes_then_it_refuses():
    with pytest.raises(ValueError, match="expected 32 bytes"):
        verification_words_for_key(bytes(31))


def test_words_when_the_jwk_has_no_x_then_it_refuses():
    with pytest.raises(ValueError, match="no string 'x' member"):
        verification_words_for_jwk({"kty": "OKP", "crv": "Ed25519"})


def test_compare_when_the_server_asserts_what_we_compute_then_match(by_name: dict):
    held = by_name["baseline"]
    result = compare_verification_words(held["jwk"], held["words"])
    assert result.status == "match"
    assert result.match is True
    assert result.computed == held["words"]
    assert result.asserted == held["words"]


def test_compare_when_the_values_differ_then_both_are_reported(by_name: dict):
    held, other = by_name["baseline"], by_name["baseline-one-bit"]
    result = compare_verification_words(held["jwk"], other["words"])
    assert result.status == "mismatch"
    assert result.match is False
    assert result.computed == held["words"]
    assert result.asserted == other["words"]


def test_compare_when_no_local_key_material_then_it_says_so(by_name: dict):
    held = by_name["baseline"]
    result = compare_verification_words(None, held["words"])
    assert result.status == "not-computed"
    assert result.computed is None
    assert result.asserted == held["words"]
    assert result.match is None


def test_compare_when_the_server_asserts_nothing_then_it_says_so(by_name: dict):
    held = by_name["baseline"]
    result = compare_verification_words(held["jwk"], None)
    assert result.status == "not-asserted"
    assert result.computed == held["words"]
    assert result.match is None


def test_compare_when_given_raw_bytes_then_it_computes_the_same(by_name: dict):
    held = by_name["baseline"]
    raw = from_base64url(held["jwk"]["x"])
    assert compare_verification_words(raw, held["words"]).status == "match"


def test_compare_when_spacing_or_case_differs_then_it_is_not_a_mismatch(by_name: dict):
    held = by_name["baseline"]
    noisy = f"  {held['words'].upper().replace(' ', '   ')}\n"
    result = compare_verification_words(held["jwk"], noisy)
    assert result.match is True
    # The operator is shown what the server actually sent, not a cleaned copy.
    assert result.asserted == noisy
