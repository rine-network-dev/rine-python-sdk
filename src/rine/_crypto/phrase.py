"""The 24-word recovery phrase an org root is written down as.

BIP39 English, 24 words, over the ``mnemonic`` package. The phrase encodes the
32-byte org root directly: the root is the BIP39 *entropy*, not a PBKDF2 seed,
and no passphrase is involved. That is what makes the phrase a lossless
encoding of the root rather than a one-way derivation from it, so a phrase
written down on paper and a root held in memory are the same secret.

The TypeScript stack uses ``@scure/bip39`` for the same job, and both are BIP39,
so a phrase from either stack reads on the other.
"""

from __future__ import annotations

import unicodedata

from mnemonic import Mnemonic

from rine.errors import CryptoError

#: The number of words a recovery phrase has.
WORD_COUNT = 24

#: The 2048 BIP39 English words, in the order the checksum indexes them.
WORDLIST: tuple[str, ...] = tuple(Mnemonic("english").wordlist)

_MNEMONIC = Mnemonic("english")
_WORDS = frozenset(WORDLIST)


class PhraseError(CryptoError):
    """A recovery phrase could not be read or written."""


class WrongWordCountError(PhraseError):
    """A phrase did not have exactly :data:`WORD_COUNT` words."""


class UnknownWordError(PhraseError):
    """A phrase carried a word that is not in the BIP39 English wordlist."""


class BadChecksumError(PhraseError):
    """A phrase's words are all known but its BIP39 checksum does not match."""


def phrase_from_entropy(root: bytes) -> str:
    """Encode a 32-byte org root as a 24-word recovery phrase.

    Args:
        root: The 32-byte org root, used as BIP39 entropy.

    Returns:
        The 24 words joined by single spaces.

    Raises:
        PhraseError: ``root`` is not 32 bytes.
    """
    if len(root) != 32:
        raise PhraseError("root must be 32 bytes")
    return _MNEMONIC.to_mnemonic(root)


def entropy_from_phrase(text: str) -> bytes:
    """Decode a recovery phrase back to the 32-byte org root it encodes.

    The text is NFKD-normalised and lowercased, then split on any run of
    Unicode whitespace, so a phrase pasted with full-width characters, non-
    breaking spaces or stray newlines reads the same as a clean one.

    Args:
        text: The recovery phrase, in any case and any whitespace.

    Returns:
        The 32-byte org root.

    Raises:
        WrongWordCountError: The phrase is not :data:`WORD_COUNT` words long.
        UnknownWordError: A word is not in the BIP39 English wordlist.
        BadChecksumError: Every word is known but the checksum does not match.
    """
    words = unicodedata.normalize("NFKD", text).lower().split()
    if len(words) != WORD_COUNT:
        raise WrongWordCountError(f"wrong word count: expected 24, got {len(words)}")
    for position, word in enumerate(words, start=1):
        if word not in _WORDS:
            raise UnknownWordError(f"unknown word at position {position}")
    try:
        return bytes(_MNEMONIC.to_entropy(words))
    except ValueError as exc:
        raise BadChecksumError("bad checksum") from exc


__all__ = [
    "WORDLIST",
    "WORD_COUNT",
    "BadChecksumError",
    "PhraseError",
    "UnknownWordError",
    "WrongWordCountError",
    "entropy_from_phrase",
    "phrase_from_entropy",
]
