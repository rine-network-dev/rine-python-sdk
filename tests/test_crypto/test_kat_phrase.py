"""Replay of the recovery-phrase and org-word vectors in ``org-root-v1.json``.

The fixture is owned by ``rine-core`` and shared with the TypeScript stack, so
these tests read it and never restate a value from it. ``load_kat`` skips the
whole module when the sibling checkout is absent.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from rine._crypto.org_words import org_words
from rine._crypto.phrase import (
    WORDLIST,
    BadChecksumError,
    PhraseError,
    UnknownWordError,
    WrongWordCountError,
    entropy_from_phrase,
    phrase_from_entropy,
)
from tests.test_crypto.kat import load_kat

#: The exception each refusal prefix pins, so a refusal is classified by type
#: and not only by the words it starts with. The unknown-word prefix carries the
#: position, so it is matched as a prefix rather than as a whole key.
_REFUSAL_TYPES: tuple[tuple[str, type[PhraseError]], ...] = (
    ("wrong word count", WrongWordCountError),
    ("unknown word at position", UnknownWordError),
    ("bad checksum", BadChecksumError),
)


def _refusal_type(prefix: str) -> type[PhraseError]:
    return next(kind for start, kind in _REFUSAL_TYPES if prefix.startswith(start))


def _phrases() -> dict[str, Any]:
    return load_kat()["phrases"]  # type: ignore[no-any-return]


def _roots() -> list[dict[str, Any]]:
    return load_kat()["roots"]["roots"]  # type: ignore[no-any-return]


def _accepted_ids() -> list[str]:
    return [entry["name"] for entry in _phrases()["accepted"]]


def _refused_ids() -> list[str]:
    return [entry["name"] for entry in _phrases()["refused"]]


def _root_ids() -> list[str]:
    return [f"root-{entry['index']}" for entry in _roots()]


def _accepted(name: str) -> dict[str, Any]:
    return next(e for e in _phrases()["accepted"] if e["name"] == name)  # type: ignore[no-any-return]


def _refused(name: str) -> dict[str, Any]:
    return next(e for e in _phrases()["refused"] if e["name"] == name)  # type: ignore[no-any-return]


def _root(name: str) -> dict[str, Any]:
    index = int(name.removeprefix("root-"))
    return next(e for e in _roots() if e["index"] == index)  # type: ignore[no-any-return]


def test_wordlist_matches_fixture() -> None:
    """The bundled wordlist is the 2048 words the fixture hashes."""
    expected = _phrases()["wordlist"]
    assert len(WORDLIST) == expected["words"]
    digest = hashlib.sha256("\n".join(WORDLIST).encode()).hexdigest()
    assert digest == expected["sha256"]


@pytest.mark.parametrize("name", _root_ids())
def test_root_round_trip(name: str) -> None:
    """Each root encodes to its phrase, decodes back, and names its org."""
    entry = _root(name)
    entropy = bytes.fromhex(entry["entropy"])
    assert phrase_from_entropy(entropy) == entry["phrase"]
    assert entropy_from_phrase(entry["phrase"]) == entropy
    assert org_words(entry["org"]["org_id"]) == entry["org_words"]


@pytest.mark.parametrize("name", _accepted_ids())
def test_accepted_phrase(name: str) -> None:
    """A phrase in any case and whitespace decodes to its root."""
    entry = _accepted(name)
    assert entropy_from_phrase(entry["input"]) == bytes.fromhex(entry["entropy"])


@pytest.mark.parametrize("name", _refused_ids())
def test_refused_phrase(name: str) -> None:
    """A refused phrase raises the typed error its prefix pins."""
    entry = _refused(name)
    prefix = entry["error_prefix"]
    with pytest.raises(PhraseError) as excinfo:
        entropy_from_phrase(entry["input"])
    assert str(excinfo.value).startswith(prefix)
    assert isinstance(excinfo.value, _refusal_type(prefix))


def test_refusal_never_echoes_the_word() -> None:
    """An unknown-word refusal names the position and not the word."""
    entry = _refused("unknown_word")
    with pytest.raises(UnknownWordError) as excinfo:
        entropy_from_phrase(entry["input"])
    assert "abandonx" not in str(excinfo.value)
