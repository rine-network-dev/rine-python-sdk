"""The eight-word human-readable name of an org.

An org id is a UUID, which nobody reads aloud or checks by eye. These eight
words are a short, stable rendering of the same id: derived from it, never
stored beside it, and reproducible by anyone holding the id. Two people
comparing words are comparing the id.

The derivation is a domain-separated SHA-256 over the id's 16 raw bytes, and
the first 88 bits of the digest are read as eight 11-bit indexes into the BIP39
English wordlist — the same list the recovery phrase uses, so an operator reads
one vocabulary across both.
"""

from __future__ import annotations

import hashlib
import re

from rine._crypto.phrase import WORDLIST
from rine.errors import CryptoError

#: The domain separator, so this digest can never collide with another use of
#: SHA-256 over the same org id.
_DOMAIN = b"rine.v1.org-words"

#: An org id once its hyphens are removed: exactly 16 bytes of hex.
_HEX_ID = re.compile(r"[0-9a-fA-F]{32}")

#: The number of words an org name has.
WORD_COUNT = 8

#: The bit width of one wordlist index.
_INDEX_BITS = 11

#: The bit mask selecting one index.
_INDEX_MASK = (1 << _INDEX_BITS) - 1


def org_words(org_id: str) -> str:
    """Return the eight words that name ``org_id``.

    Args:
        org_id: The org's UUID, hyphenated or bare hex.

    Returns:
        The eight words joined by single spaces, most significant first.

    Raises:
        CryptoError: ``org_id`` is not 16 bytes of hex.
    """
    bare = org_id.replace("-", "")
    if not _HEX_ID.fullmatch(bare):
        raise CryptoError("org id must be 16 bytes of hex")
    digest = hashlib.sha256(_DOMAIN + b"\x00" + bytes.fromhex(bare)).digest()
    value = int.from_bytes(digest[:11], "big")
    shifts = range((WORD_COUNT - 1) * _INDEX_BITS, -1, -_INDEX_BITS)
    return " ".join(WORDLIST[(value >> shift) & _INDEX_MASK] for shift in shifts)


__all__ = ["WORD_COUNT", "org_words"]
