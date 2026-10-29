"""Recipient-key words — the golden the fleet and the TypeScript twin share.

The words are computed over the SHA-256 of the raw 1216-byte recipient key, so
the golden in ``tests/fixtures/recipient_key_words_vector.json`` is what pins
this implementation, the fleet's ``recipient_words`` and ``recipientKeyWords``
in ``rine-core/src/crypto/recipient-key.ts`` to one answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rine.errors import CryptoError
from rine.verification_words import RECIPIENT_KEY_SIZE, recipient_key_words

FIXTURE = Path(__file__).parent / "fixtures" / "recipient_key_words_vector.json"


@pytest.fixture(scope="module")
def golden() -> dict:
    return json.loads(FIXTURE.read_text())


def test_recipient_key_words_when_replaying_the_golden_then_matches(golden: dict):
    key = bytes.fromhex(golden["key_hex"])
    assert len(key) == RECIPIENT_KEY_SIZE
    assert recipient_key_words(key) == golden["words"]


def test_recipient_key_words_when_key_is_one_byte_short_then_it_is_refused(golden: dict):
    key = bytes.fromhex(golden["key_hex"])
    with pytest.raises(CryptoError, match="recipient key must be 1216 bytes"):
        recipient_key_words(key[:-1])


def test_recipient_key_words_when_key_is_one_byte_long_then_it_is_refused(golden: dict):
    key = bytes.fromhex(golden["key_hex"])
    with pytest.raises(CryptoError, match="recipient key must be 1216 bytes"):
        recipient_key_words(key + b"\x00")


def test_recipient_key_words_when_one_byte_changes_then_the_words_change(golden: dict):
    key = bytes.fromhex(golden["key_hex"])
    changed = key[:100] + bytes([key[100] ^ 0x01]) + key[101:]
    assert recipient_key_words(changed) != recipient_key_words(key)
