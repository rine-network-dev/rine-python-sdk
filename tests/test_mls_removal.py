"""Python side — a Remove commit declares its target, and a target holding no
leaf still gets one.

These drive the real ``rine-mls`` core: the group, the ratchet tree and the
commits are genuine, and only the HTTP boundary is stubbed. That is the point of
the file. The declaration and the path-only rescue both live in
:mod:`rine._mls.removal`, and if this SDK drifted from its TypeScript twin a
mixed-surface group would kick correctly from one surface and refuse from the
other — the same divergence the sender-key path is guarded against, and it is
just as available here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from rine._crypto.keys import generate_agent_keys, save_agent_keys
from rine._mls.binding import open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.removal import MlsRemovalCommit, remove_mls_group_member
from rine._mls.tree import leaf_index
from rine.types import GroupRead

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit

ADMIN = "11111111-1111-1111-1111-111111111111"
MEMBER = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
STRANGER = "44444444-4444-4444-4444-444444444444"


def _group_read() -> GroupRead:
    return GroupRead.model_validate(
        {
            "id": GROUP_ID,
            "name": "standup",
            "handle": "#standup@acme.rine.network",
            "org_id": "55555555-5555-5555-5555-555555555555",
            "visibility": "private",
            "created_at": "2026-04-11T12:00:00Z",
            "mls_group_id": "latched",
        }
    )


@pytest.fixture
def commits(monkeypatch) -> list[MlsCommit]:
    """Accept every commit, recording it, and answer with its own epoch."""
    posted: list[MlsCommit] = []

    def _commit(_actor: Any, _group_id: str, commit: MlsCommit, _headers: dict[str, str]) -> int:
        posted.append(commit)
        return commit.epoch

    # The seam that publishes a commit AND beats the acting agent's key-package
    # heartbeat behind it. Stubbed here rather than the inner ``mls_commit``:
    # this fixture stands in for the whole server, so leaving the heartbeat live
    # would have it publish key packages at one that is not there.
    monkeypatch.setattr("rine._mls.removal.post_mls_commit", _commit)
    monkeypatch.setattr("rine._mls.removal.read_group", lambda *_a: _group_read())
    return posted


@pytest.fixture
def seated(tmp_config_dir, monkeypatch) -> bytes:
    """Found the group with ADMIN and MEMBER in it, and publish MEMBER's key."""
    save_agent_keys(tmp_config_dir, ADMIN, generate_agent_keys())
    save_agent_keys(tmp_config_dir, MEMBER, generate_agent_keys())
    member_identity = open_mls_client(tmp_config_dir, MEMBER).public_key()
    key_package = open_mls_client(tmp_config_dir, MEMBER).generate_key_package()
    group = open_mls_client(tmp_config_dir, ADMIN).create_group(mls_group_id_bytes(GROUP_ID))
    group.add_member(key_package)
    group.save()

    monkeypatch.setattr(
        "rine._mls.removal.fetch_agent_identities",
        lambda _client, ids: {
            agent_id.lower(): member_identity
            for agent_id in ids
            if agent_id.lower() == MEMBER.lower()
        },
    )
    return member_identity


class TestARemoveCommitDeclaresItsTarget:
    def test_the_commit_names_the_agent_it_removes(self, tmp_config_dir, seated, commits):
        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        # The DELETE spends this declaration. Without it the server refuses
        # the removal and the member row can never be dropped.
        assert commits[-1].removes == (MEMBER,)
        assert result == MlsRemovalCommit(epoch=commits[-1].epoch, removed_leaf=True)

    def test_the_leaf_is_actually_taken(self, tmp_config_dir, seated, commits):
        remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        group = open_mls_group(tmp_config_dir, ADMIN, GROUP_ID)
        assert leaf_index(group, seated) is None

    def test_the_commit_carries_no_welcome(self, tmp_config_dir, seated, commits):
        remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        assert commits[-1].welcomes == ()


class TestAStrandedRemovalIsRescued:
    def test_a_second_removal_of_the_same_member_still_names_an_epoch(
        self, tmp_config_dir, seated, commits
    ):
        """A stranded removal is rescued rather than refused.

        The first removal's commit landed and its DELETE did not, so the leaf is
        already out of the tree and no second Remove can be built for it. Before
        the rescue this raised — the epoch came only from a commit that could no
        longer be made — and the member row was stuck for good.
        """
        remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        assert result.removed_leaf is False
        assert result.epoch > commits[0].epoch
        # Path-only, but still declared: the declaration is what the DELETE
        # spends, and a commit naming nobody authorises no removal at all.
        assert commits[-1].removes == (MEMBER,)
        assert commits[-1].welcomes == ()

    def test_an_agent_with_no_published_key_is_removable_rather_than_stuck(
        self, tmp_config_dir, seated, commits
    ):
        """A revoked or erased agent publishes no signing key, so it has no
        basic-credential identity and no leaf can be named for it. It is still a
        member row somebody has to be able to drop."""
        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, STRANGER)

        assert result.removed_leaf is False
        assert commits[-1].removes == (STRANGER,)

    def test_the_rescue_leaves_every_other_leaf_alone(self, tmp_config_dir, seated, commits):
        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, STRANGER)

        group = open_mls_group(tmp_config_dir, ADMIN, GROUP_ID)
        # The member the pass did not name keeps its seat — a path-only commit
        # rekeys, it does not evict.
        assert leaf_index(group, seated) is not None
        assert group.epoch() == result.epoch
