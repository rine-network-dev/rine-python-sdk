"""Verification words, computed here rather than read off the wire.

Five BIP39 English words derived from an agent's Ed25519 signing key. They exist
so two operators can compare a short human-readable string out of band and see
that they are talking about the same key.

🔴 **The words are computed from the key the client holds. Full stop.** A key
fetched from ``GET /agents/{id}/keys`` *is* the key the server asserts, so words
recomputed from it agree with the server's by construction and the comparison
says nothing at all — while every test still passes. A surface holding no local
key material does not recompute and says so: that is what
:func:`compare_verification_words` answers ``"not-computed"`` for.

The reference implementation is the server's ``compute_verification_words``
(``src/rine/auth/service.py``); the TypeScript twin is
``rine-core/src/crypto/verification-words.ts``. All three replay the same
goldens (``rine-sdk/tests/fixtures/verification_words_vectors.json``), because
three implementations of one derivation is exactly the shape that drifts.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from mnemonic import Mnemonic

from rine._crypto import _mlkem
from rine.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Mapping

#: How many words a verification string carries.
_WORD_COUNT = 5
#: BIP39 indexes are 11 bits, so five of them consume 55 of the digest's bits.
_BITS_PER_WORD = 11
_WORD_MASK = 0x7FF

#: The exact length of a recipient key: X25519 ‖ ML-KEM-768.
RECIPIENT_KEY_SIZE = 32 + _mlkem.PUBLIC_KEY_SIZE

#: Whether the local computation and the server's assertion agree, and why not.
#:
#: ``not-computed`` means this client holds no key material for the agent;
#: ``not-asserted`` means the server named no words. Byte-identical to the
#: TypeScript ``VerificationWordsStatus``.
VerificationWordsStatus = Literal["match", "mismatch", "not-computed", "not-asserted"]


@dataclass(frozen=True)
class VerificationWordsComparison:
    """What a surface renders: both values, a boolean, and why either is absent."""

    status: VerificationWordsStatus
    """Whether the two agree, or which side had nothing to say."""

    computed: str | None
    """Words this client derived from key material it holds, or ``None``."""

    asserted: str | None
    """Words the server asserted, as received, or ``None``."""

    match: bool | None
    """``None`` whenever one side is missing — absence is not disagreement."""


def _words_from_digest(digest: bytes) -> str:
    """SHA-256 digest to five words: first 55 bits, five 11-bit BIP39 indexes."""
    # Seven bytes are 56 bits; the derivation uses 55 and drops the lowest.
    bits = int.from_bytes(digest[:7], "big") >> 1
    indexes: list[int] = []
    for _ in range(_WORD_COUNT):
        indexes.append(bits & _WORD_MASK)
        bits >>= _BITS_PER_WORD
    indexes.reverse()

    wordlist = Mnemonic("english").wordlist
    return " ".join(wordlist[i] for i in indexes)


def verification_words_for_key(public_key: bytes) -> str:
    """The five words for a raw 32-byte Ed25519 public key.

    Args:
        public_key: Raw public key bytes — not base64, not a JWK.

    Returns:
        Five space-separated BIP39 English words.

    Raises:
        ValueError: If the key is not 32 bytes. The server derives words from
            whatever it decodes; refusing is the stricter answer and cannot
            disagree with it about any real Ed25519 key.
    """
    if len(public_key) != 32:
        raise ValueError(f"Invalid signing public key: expected 32 bytes, got {len(public_key)}")
    return _words_from_digest(hashlib.sha256(public_key).digest())


def recipient_key_words(public_key: bytes) -> str:
    """The five words of a recipient key: the words of its SHA-256.

    A recipient key is an X25519 public key followed by an ML-KEM-768 public key
    — 1216 bytes, not the 32 the word function is defined over — so the words are
    taken over the key's SHA-256 digest, which is 32 bytes. Both sides of a
    delegation compute them the same way: the fleet's ``recipient_words`` and the
    TypeScript twin ``recipientKeyWords``
    (``rine-core/src/crypto/recipient-key.ts``) hash the raw key identically, and
    the shared golden ``tests/fixtures/recipient_key_words_vector.json`` pins all
    three.

    Args:
        public_key: The raw recipient key, X25519 ‖ ML-KEM-768.

    Returns:
        Five space-separated BIP39 English words.

    Raises:
        CryptoError: If the key is not 1216 bytes.
    """
    if len(public_key) != RECIPIENT_KEY_SIZE:
        raise CryptoError(f"recipient key must be {RECIPIENT_KEY_SIZE} bytes")
    return verification_words_for_key(hashlib.sha256(public_key).digest())


def verification_words_for_jwk(jwk: Mapping[str, object]) -> str:
    """The five words for an Ed25519 signing key in JWK form.

    Accepts ``x`` with or without base64url padding, as the server does.

    Args:
        jwk: The agent's signing public key, carrying an ``x`` member.

    Returns:
        Five space-separated BIP39 English words.

    Raises:
        ValueError: If ``x`` is missing, is not a string, or does not decode to
            32 bytes.
    """
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("Invalid signing public key JWK: no string 'x' member")
    padding = (4 - len(x) % 4) % 4
    return verification_words_for_key(base64.urlsafe_b64decode(x + "=" * padding))


def _same_words(a: str, b: str) -> bool:
    """Two word strings mean the same key if they name the same five words.

    Whitespace runs are collapsed and case is ignored, because the BIP39 English
    list is lower-case with no spaces inside a word — so neither normalisation
    can turn one word into another, and both remove a class of false mismatch
    that would send an operator looking for an attacker who is not there. The
    TypeScript twin normalises identically.
    """
    return " ".join(a.lower().split()) == " ".join(b.lower().split())


def compare_verification_words(
    held_key: bytes | Mapping[str, object] | None,
    asserted_words: str | None,
) -> VerificationWordsComparison:
    """Compare the words this client computes against the words the server asserts.

    A mismatch is a designed state, not an error: it is returned, never raised,
    and it never gates sending. Both values come back so a surface can show both.

    Args:
        held_key: Key material this client holds for the agent — raw 32 bytes or
            the JWK it stores them in — or ``None`` when it holds none.
            🔴 Never pass a key just fetched from ``GET /agents/{id}/keys``: that
            is the server's own assertion, and feeding it back in makes the
            result ``"match"`` no matter what is true.
        asserted_words: The words the server named, e.g. from an agent card.

    Returns:
        Both values, a boolean, and why either is absent.
    """
    if held_key is None:
        computed = None
    elif isinstance(held_key, (bytes, bytearray)):
        computed = verification_words_for_key(bytes(held_key))
    else:
        computed = verification_words_for_jwk(held_key)

    if computed is None:
        return VerificationWordsComparison("not-computed", None, asserted_words, None)
    if asserted_words is None:
        return VerificationWordsComparison("not-asserted", computed, None, None)
    match = _same_words(computed, asserted_words)
    return VerificationWordsComparison(
        "match" if match else "mismatch", computed, asserted_words, match
    )


__all__ = [
    "RECIPIENT_KEY_SIZE",
    "VerificationWordsComparison",
    "VerificationWordsStatus",
    "compare_verification_words",
    "recipient_key_words",
    "verification_words_for_jwk",
    "verification_words_for_key",
]
