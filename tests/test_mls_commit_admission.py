"""A member catching up admits the peers a commit adds, verified like any other peer.

These drive the real ``rine-mls`` core: the group, the commits and the refusal are
genuine, and only the server is a stand-in. The shape under test is the one a
roster cannot see: a peer Added and then Removed while a member was offline is in
neither the roster nor the allowed set, so the core refuses the Add and, without
this, the member NACKs it and stays behind for good.

The catch-up cases live here; the helper's own contract is in
``test_mls_commit_admission_helper`` and the recovery rungs in
``test_mls_commit_admission_recovery``. The TypeScript twin is
``rine-core/test/mls-commit-admission.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.binding import (
    PeerNotAdmittedError,
    open_mls_client,
)
from rine._mls.group_access import open_mls_group
from rine.errors import RineApiError
from rine.testing import WORLD
from tests.mls_admission_world import (
    ADDED,
    FOUNDER,
    GROUP_ID,
    MEMBER,
    SECOND_ADDED,
    build_world,
    device,
)

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")


@pytest.fixture(autouse=True)
def _no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up out of the request counts this file measures."""
    for module in ("sync", "commit"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)


def test_sync_when_a_peer_was_added_then_removed_while_away_then_it_catches_up_without_a_nack(
    tmp_path: Any,
) -> None:
    """Add C, remove C, member offline: two epochs, no NACK, and the next message reads."""
    edges = build_world(tmp_path)
    start = edges.member_epoch()
    edges.add_then_remove_added()
    payload = edges.founder_group.encrypt_application_message(b"after the churn")
    edges.founder_group.save()

    result = edges.sync()

    assert (result.epoch, result.processed) == (start + 2, 2)
    assert edges.server.nacks == []
    assert edges.server.key_reads == [[ADDED]]
    assert edges.member_allows(ADDED)
    assert (
        open_mls_group(edges.config_dir, MEMBER, GROUP_ID)
        .decrypt_application_message(payload)
        .envelope
        == b"after the churn"
    )


def test_sync_when_the_commit_names_a_peer_already_admitted_then_it_reads_no_keys(
    tmp_path: Any,
) -> None:
    """A leaf the member already allows costs no key read."""
    edges = build_world(tmp_path, member_knows_added=True)
    edges.add_then_remove_added()

    result = edges.sync()

    assert result.processed == 2
    assert edges.server.key_reads == []


def test_sync_when_there_is_nothing_to_apply_then_it_reads_no_keys(tmp_path: Any) -> None:
    """An ordinary idle sync makes no request beyond the handshake listing."""
    edges = build_world(tmp_path)

    assert edges.sync().processed == 0
    assert edges.server.key_reads == []


def test_sync_when_one_commit_adds_two_unknown_peers_then_each_is_verified_once(
    tmp_path: Any,
) -> None:
    """The retry is bounded by the distinct agents the commit names."""
    edges = build_world(tmp_path)
    second_dir = device(tmp_path, "second", SECOND_ADDED, (FOUNDER, 0))
    second_package = open_mls_client(second_dir, SECOND_ADDED).generate_key_package()
    edges.post(edges.founder_group.add_members([edges.added_package, second_package]))
    edges.founder_group.save()

    result = edges.sync()

    assert result.processed == 1
    assert sorted(r[0] for r in edges.server.key_reads) == sorted([ADDED, SECOND_ADDED])
    assert edges.server.nacks == []


@pytest.mark.parametrize("shape", ["broken_chain", "deleted"])
def test_sync_when_the_added_peer_does_not_verify_then_it_is_nacked_once_and_refused(
    tmp_path: Any, shape: str
) -> None:
    """A leaf that does not chain-verify stays refused, is NACKed once and surfaces typed."""
    edges = build_world(tmp_path)
    start = edges.member_epoch()
    edges.add_then_remove_added()
    if shape == "deleted":
        edges.server.absent.add(ADDED)
    else:
        edges.server.tamper = lambda body: {
            **body,
            "agent_certificate": WORLD.keys_response(FOUNDER)["agent_certificate"],
        }

    with pytest.raises(PeerNotAdmittedError) as refusal:
        edges.sync()

    assert refusal.value.code == "RINE_MLS_PEER_NOT_ADMITTED"
    assert edges.server.nacks == ["h0"]
    assert edges.server.key_reads == [[ADDED]]
    assert not edges.member_allows(ADDED)
    assert edges.member_epoch() == start


def test_sync_when_the_peer_verifies_with_another_key_then_the_refusal_is_final(
    tmp_path: Any,
) -> None:
    """A verified agent whose leaf key differs is read once, then refused for good."""
    # The leaf carries ADDED's second-generation key; the chain only vouches for the first.
    edges = build_world(tmp_path, added_gen=1)
    edges.add_then_remove_added()

    with pytest.raises(PeerNotAdmittedError):
        edges.sync()

    assert edges.server.key_reads == [[ADDED]]
    assert edges.server.nacks == ["h0"]
    assert edges.member_allows(ADDED)


def test_sync_when_the_key_read_fails_then_nothing_is_nacked_and_the_next_sync_catches_up(
    tmp_path: Any,
) -> None:
    """A transport failure while verifying is not a refusal: no NACK, retried next sync."""
    edges = build_world(tmp_path)
    start = edges.member_epoch()
    edges.add_then_remove_added()
    edges.server.outage = RineApiError(503, "unavailable", "")

    with pytest.raises(RineApiError):
        edges.sync()
    assert edges.server.nacks == []

    edges.server.outage = None
    assert edges.sync().epoch == start + 2
