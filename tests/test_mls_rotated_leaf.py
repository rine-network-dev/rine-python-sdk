"""A rotated agent's seat: resync and reseat report a typed refusal, not a string.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` is seated in a
closed group and then rotates its key, so the tree still holds its generation-0
leaf while its disk holds generation 1. Resyncing on that leaf is refused, and
the refusal is surfaced as :class:`MlsRotatedLeafError` rather than a free-string
failure naming the agent's own id as an unadmitted peer.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine import MLS_ERR_ROTATED_LEAF, MlsRotatedLeafError, ReseatStatus
from rine._mls.actor import MlsActor
from rine._mls.binding import ResyncChangesKeyError
from rine._mls.resync import recover_mls_group
from rine._mls.rotated_leaf import admit_refused_peers_for_resync
from rine._recover_reseat import reseat_closed_groups
from rine.errors import ConflictError
from tests.rotation_world import G1, A, fresh_process, rotate, world


def _refuse_replay(server: Any) -> None:
    """Make the server refuse every replay, so recovery must take the resync rung."""
    served = server.get

    def get(path: str, **kwargs: Any) -> dict[str, Any]:
        if path.endswith("/mls/handshakes"):
            raise ConflictError(
                "replay cannot bridge that gap", '{"error": "mls_resync_required"}'
            )
        return served(path, **kwargs)

    server.get = get


def _message(agent_id: str, group_id: str) -> str:
    """The exact sentence a rotated agent's refusal carries."""
    return (
        f"Agent {agent_id}'s leaf in group {group_id} still carries a key it has since "
        "rotated away from, and this device holds no group state that can move it; "
        "a member must remove the agent and invite it again before it can resync."
    )


@pytest.mark.usefixtures("real_roster_read")
def test_recover_mls_group_when_the_agent_rotated_then_raises_the_rotated_leaf_error(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A rotated agent's resync refusal is the typed rotated-leaf error."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A])
    rotate(server, d1, A)
    fresh_process()
    _refuse_replay(server)
    with pytest.raises(MlsRotatedLeafError) as caught:
        recover_mls_group(server, d1, A, G1)
    err = caught.value
    assert err.code == MLS_ERR_ROTATED_LEAF
    assert err.agent_id == A
    assert err.group_id == G1
    assert str(err) == _message(A, G1)


@pytest.mark.usefixtures("real_roster_read")
def test_reseat_closed_groups_when_the_agent_rotated_then_reports_needs_readd_with_the_message(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A rotated agent's reseat is reported as needing a remove and re-invite."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A])
    rotate(server, d1, A)
    fresh_process()
    reseats = reseat_closed_groups(server, d1, [A])
    assert len(reseats) == 1
    outcome = reseats[0]
    assert outcome.status is ReseatStatus.NEEDS_READD
    assert outcome.status.value == "needs_readd"
    assert outcome.reason == _message(A, G1)
    assert outcome.group_id == G1
    assert outcome.agent_id == A


@pytest.mark.usefixtures("real_roster_read")
def test_reseat_closed_groups_when_the_agent_did_not_rotate_then_reseats(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """An unrotated agent still retakes its seat, with no reason reported."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A])
    fresh_process()
    reseats = reseat_closed_groups(server, d1, [A])
    assert len(reseats) == 1
    outcome = reseats[0]
    assert outcome.status is ReseatStatus.RESEATED
    assert outcome.reason is None


def test_rotated_leaf_error_is_exported_at_the_package_root() -> None:
    """The rotated-leaf error and its code are reachable from the package root."""
    import rine

    assert rine.MlsRotatedLeafError is MlsRotatedLeafError
    assert rine.MLS_ERR_ROTATED_LEAF == "mls_rotated_leaf"


def _refuse_with(monkeypatch: pytest.MonkeyPatch, err: Exception) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise err

    monkeypatch.setattr("rine._mls.rotated_leaf.admit_refused_peers", refuse)


def test_admit_refused_peers_for_resync_when_the_core_refuses_a_key_change_then_rotated_leaf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resync that would change the acting agent's own key is the rotated-leaf outcome."""
    refusal = ResyncChangesKeyError(f"resync would change the key of {A.lower()}")
    _refuse_with(monkeypatch, refusal)
    with pytest.raises(MlsRotatedLeafError) as caught:
        admit_refused_peers_for_resync(MlsActor(None, "/x", A.upper()), None, lambda: None, G1)
    assert caught.value.__cause__ is refusal
    assert str(caught.value) == _message(A.upper(), G1)


def test_admit_refused_peers_for_resync_when_the_key_change_names_another_agent_then_it_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key change that is not the acting agent's is not this agent's remedy."""
    _refuse_with(monkeypatch, ResyncChangesKeyError("resync would change the key of someone-else"))
    with pytest.raises(ResyncChangesKeyError):
        admit_refused_peers_for_resync(MlsActor(None, "/x", A), None, lambda: None, G1)
