"""History admission skips a generation that cannot go in, and nothing else.

The core refuses a second generation of one agent that carries a leaf key already
admitted under another generation. That refusal is the typed
``AllowedGenerationConflictError``; the history walk skips exactly it, so one such
generation never costs the agent's other generations their admission. Any other
failure is a real one and propagates. The TypeScript twin is ``admitHistory``.
"""

from __future__ import annotations

import pytest

from rine._crypto.certs import ChainError
from rine._mls import allowed_history
from rine._mls.actor import MlsActor
from rine._mls.allowed_history import admit_history
from rine._mls.binding import AllowedIdentities, credential_identity

PEER = "00000000-0000-4000-8000-0000000000a1"
KEY_A = b"\x01" * 32
KEY_B = b"\x02" * 32
KEY_C = b"\x03" * 32


class _Keys:
    def __init__(self, key: bytes) -> None:
        self.mls_public_key = key


def _serve(monkeypatch, by_gen: dict[int, bytes | Exception]) -> None:
    def fetch(_client, agent_id, *, gen):
        outcome = by_gen[gen]
        if isinstance(outcome, Exception):
            raise outcome
        return _Keys(outcome)

    monkeypatch.setattr(
        allowed_history, "get_agent_keys_sync", lambda c, a, *, gen: (fetch(c, a, gen=gen), False)
    )


@pytest.fixture
def actor():
    return MlsActor(client=object(), config_dir="unused", agent_id="self")


def test_admit_history_when_two_generations_share_a_key_skips_the_duplicate(monkeypatch, actor):
    _serve(monkeypatch, {0: KEY_A, 1: KEY_A, 2: KEY_B})
    allowed = AllowedIdentities()

    assert admit_history(actor, allowed, PEER, 3) is True

    assert allowed.contains(credential_identity(PEER), KEY_A)
    assert allowed.contains(credential_identity(PEER), KEY_B)


def test_admit_history_when_only_the_duplicate_is_left_still_reports_the_first_admission(
    monkeypatch, actor
):
    _serve(monkeypatch, {0: KEY_A, 1: KEY_A})

    assert admit_history(actor, AllowedIdentities(), PEER, 2) is True


def test_admit_history_when_a_generation_fails_the_chain_skips_it(monkeypatch, actor):
    _serve(monkeypatch, {0: ChainError("broken"), 1: KEY_C})
    allowed = AllowedIdentities()

    assert admit_history(actor, allowed, PEER, 2) is True

    assert allowed.contains(credential_identity(PEER), KEY_C)


def test_admit_history_when_nothing_verifies_admits_nothing(monkeypatch, actor):
    _serve(monkeypatch, {0: ChainError("broken")})

    assert admit_history(actor, AllowedIdentities(), PEER, 1) is False


def test_admit_history_when_a_read_fails_propagates_it(monkeypatch, actor):
    _serve(monkeypatch, {0: KEY_A, 1: OSError("network down")})

    with pytest.raises(OSError, match="network down"):
        admit_history(actor, AllowedIdentities(), PEER, 2)


def test_admit_history_when_an_insert_fails_otherwise_propagates_it(monkeypatch, actor):
    _serve(monkeypatch, {0: KEY_A})

    class Refusing:
        def insert(self, *_args):
            raise ValueError("not a conflict")

    with pytest.raises(ValueError, match="not a conflict"):
        admit_history(actor, Refusing(), PEER, 1)
