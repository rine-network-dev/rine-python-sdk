"""What ``admit_refused_peers`` does with a refusal, against a handle that only counts calls.

The TypeScript twin is ``rine-core/test/mls-commit-admission.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.binding import (
    MlsProtocolError,
    PeerNotAdmittedError,
    credential_identity,
)
from rine._mls.commit_admission import admit_refused_peers
from rine._mls.failures import is_unprocessable_commit
from rine._mls.heartbeat import MlsActor
from tests.mls_admission_world import ADDED, FOUNDER, MEMBER, Server, device


def test_peer_not_admitted_when_raised_then_it_is_a_protocol_error_that_earns_a_nack() -> None:
    """Existing handlers for protocol errors keep catching the refusal."""
    assert issubclass(PeerNotAdmittedError, MlsProtocolError)
    assert is_unprocessable_commit(PeerNotAdmittedError("x"))


class _Refusing:
    """A handle that refuses a fixed number of calls, naming the same agent each time."""

    def __init__(self, refusals: int, named: bytes | None) -> None:
        self.refusals, self.named, self.calls = refusals, named, 0

    def refused_peer(self) -> bytes | None:
        return self.named

    def call(self) -> str:
        self.calls += 1
        if self.calls <= self.refusals:
            raise PeerNotAdmittedError("not admitted")
        return "done"


@pytest.mark.parametrize("named", [None, b"\xff\xfe", b"not-a-uuid"])
def test_admit_refused_peers_when_the_refused_agent_is_unusable_then_it_reads_nothing(
    tmp_path: Any, named: bytes | None
) -> None:
    """No agent, or an undecodable one, is the final refusal with nothing verified."""
    server = Server()
    actor = MlsActor(client=server, config_dir=device(tmp_path, "m", MEMBER), agent_id=MEMBER)
    handle = _Refusing(1, named)

    with pytest.raises(PeerNotAdmittedError):
        admit_refused_peers(actor, handle, handle.call)

    assert handle.calls == 1
    assert server.key_reads == []


def test_admit_refused_peers_when_an_agent_is_refused_twice_then_it_stops_after_one_read(
    tmp_path: Any,
) -> None:
    """A second refusal of an agent already verified is final."""
    server = Server()
    actor = MlsActor(client=server, config_dir=device(tmp_path, "m", MEMBER), agent_id=MEMBER)
    handle = _Refusing(5, credential_identity(ADDED))

    with pytest.raises(PeerNotAdmittedError):
        admit_refused_peers(actor, handle, handle.call)

    assert handle.calls == 2
    assert server.key_reads == [[ADDED]]


class _Roll:
    """A handle whose successive calls refuse the next agent of a list, then succeed."""

    def __init__(self, *agents: str) -> None:
        self.agents, self.calls = [credential_identity(a) for a in agents], 0

    def refused_peer(self) -> bytes:
        return self.agents[self.calls - 1]

    def call(self) -> str:
        self.calls += 1
        if self.calls <= len(self.agents):
            raise PeerNotAdmittedError("not admitted")
        return "done"


def test_admit_refused_peers_when_a_limit_is_reached_then_the_next_refusal_is_final_and_unread(
    tmp_path: Any,
) -> None:
    """The refusal after the limit's last verification is thrown without a read."""
    server = Server()
    actor = MlsActor(client=server, config_dir=device(tmp_path, "m", MEMBER), agent_id=MEMBER)
    handle = _Roll(ADDED, FOUNDER)

    with pytest.raises(PeerNotAdmittedError):
        admit_refused_peers(actor, handle, handle.call, limit=1)

    assert handle.calls == 2
    assert server.key_reads == [[ADDED]]


def test_admit_refused_peers_when_the_limit_covers_every_refusal_then_the_retry_applies(
    tmp_path: Any,
) -> None:
    """A limit at the number of refused agents leaves the loop as it was."""
    server = Server()
    actor = MlsActor(client=server, config_dir=device(tmp_path, "m", MEMBER), agent_id=MEMBER)
    handle = _Roll(ADDED, FOUNDER)

    assert admit_refused_peers(actor, handle, handle.call, limit=2) == "done"

    assert server.key_reads == [[ADDED], [FOUNDER]]
