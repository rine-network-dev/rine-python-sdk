"""Python side — a Remove commit declares its target, and a target no leaf names
still gets one.

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

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._mls.binding import allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.removal import MlsRemovalCommit, remove_mls_group_member
from rine._mls.tree import leaf_index
from rine.testing import WORLD
from tests.escrow_outcomes import DEFERRED, DEFERRED_REPORT
from tests.mls_peers import RefusesOnce
from tests.test_crypto.world import KeyServer

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit

ADMIN = "11111111-1111-1111-1111-111111111111"
MEMBER = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
STRANGER = "44444444-4444-4444-4444-444444444444"
REFUSED = "55555555-6666-7777-8888-999999999999"


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
    return posted


class KeyReads:
    """A server that serves the key history but omits every agent from the batch key read.

    The batch read leaves out a revoked agent and an agent on a revoked branch, so a
    removal that needed a published key to find the leaf would find none.
    """

    def __init__(self) -> None:
        self.keys = KeyServer(WORLD)
        self.key_pins = self.keys.key_pins

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        if path == "/agents/keys":
            return {"keys": {}}
        return self.keys.get(path, **kwargs)


@pytest.fixture
def seated(tmp_config_dir) -> bytes:
    """Found the group with ADMIN and MEMBER in it."""
    save_agent_keys(tmp_config_dir, ADMIN, WORLD.keys(ADMIN))
    save_agent_keys(tmp_config_dir, MEMBER, WORLD.keys(MEMBER))
    key_package = open_mls_client(tmp_config_dir, MEMBER).generate_key_package()
    group = open_mls_client(tmp_config_dir, ADMIN).create_group(mls_group_id_bytes(GROUP_ID))
    group.add_member(key_package)
    group.save()

    return credential_identity(MEMBER)


class TestARemoveCommitDeclaresItsTarget:
    def test_the_commit_names_the_agent_it_removes(self, tmp_config_dir, seated, commits):
        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        # The DELETE spends this declaration. Without it the server refuses
        # the removal and the member row can never be dropped.
        assert commits[-1].removes == (MEMBER,)
        assert result == MlsRemovalCommit(epoch=commits[-1].epoch, removed_leaf=True)

    def test_the_leaf_is_actually_taken(self, tmp_config_dir, seated, commits, mls_escrow_stub):
        remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        group = open_mls_group(tmp_config_dir, ADMIN, GROUP_ID)
        assert leaf_index(group, seated) is None
        assert mls_escrow_stub[-1] == (GROUP_ID, group.epoch())

    def test_the_drain_of_the_commit_is_carried_into_the_result(
        self, tmp_config_dir, seated, commits, monkeypatch
    ):
        monkeypatch.setattr("rine._mls.removal.drain_escrow", lambda *_a, **_k: DEFERRED)

        result = remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        assert result.escrow == DEFERRED_REPORT

    def test_the_commit_carries_no_welcome(self, tmp_config_dir, seated, commits):
        remove_mls_group_member(None, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        assert commits[-1].welcomes == ()


class TestAMemberIsFoundByItsAgentId:
    """The leaf is resolved from the agent id, never from a key the server publishes."""

    def test_a_member_whose_keys_the_server_omits_is_removed_from_the_tree(
        self, tmp_config_dir, seated, commits
    ):
        """A revoked agent or an agent on a revoked branch has no row in the batch key read."""
        result = remove_mls_group_member(KeyReads(), tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        group = open_mls_group(tmp_config_dir, ADMIN, GROUP_ID)
        assert result.removed_leaf is True
        assert leaf_index(group, seated) is None
        assert commits[-1].removes == (MEMBER,)

    def test_a_member_that_rotated_its_key_is_removed_from_the_tree(
        self, tmp_config_dir, seated, commits
    ):
        """The leaf still carries the key the member was seated under, not the current one."""
        save_agent_keys(tmp_config_dir, MEMBER, WORLD.keys(MEMBER, 1))
        client = KeyReads()
        client.keys.publish(MEMBER, 1)

        result = remove_mls_group_member(client, tmp_config_dir, ADMIN, GROUP_ID, MEMBER)

        group = open_mls_group(tmp_config_dir, ADMIN, GROUP_ID)
        assert result.removed_leaf is True
        assert leaf_index(group, seated) is None


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

    def test_an_agent_that_was_never_seated_is_removable_rather_than_stuck(
        self, tmp_config_dir, seated, commits
    ):
        """No leaf names an agent that was never seated, but its member row is
        still something somebody has to be able to drop."""
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


class TestARefusedPeerIsVerifiedAndTheBuildRetried:
    """A removal commit the core refuses for an unadmitted peer is verified and built again."""

    @respx.mock
    def test_a_build_the_core_refuses_for_an_unadmitted_peer_verifies_it_and_builds_again(
        self, sync_client, tmp_config_dir, seated, commits, monkeypatch
    ):
        """The refused agent is chain-verified once and the same removal is built again."""
        real_open = open_mls_group
        monkeypatch.setattr(
            "rine._mls.removal.open_mls_group",
            lambda *args: RefusesOnce(real_open(*args), REFUSED),
        )
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        reads = respx.get("https://rine.network/agents/keys").mock(
            return_value=httpx.Response(
                200, json={"keys": {REFUSED: WORLD.keys_response(REFUSED)}}
            )
        )

        result = remove_mls_group_member(
            sync_client._http, tmp_config_dir, ADMIN, GROUP_ID, MEMBER
        )

        assert result.removed_leaf is True
        assert reads.call_count == 1
        assert allowed_for(tmp_config_dir, ADMIN).contains(
            credential_identity(REFUSED), WORLD.keys(REFUSED).mls.public_key
        )
