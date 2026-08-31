"""What a removal reports, and what an evicted agent is told.

Three obligations meet here, all of them about what a surface says rather than
about what it does:

* One sentence per group type and per verb, decided in the SDK, because the
  earlier one ("rejoining the group is the only way back in") was false in both
  halves for every open group and three wrapper packages had nothing to
  delegate to.
* An evicted agent is told it was removed from a group, not handed the MLS
  core's ratchet-tree invariant.
* A skip reason reads as a sentence, and ``not_applicable`` above all: an open
  group's roster comes back entirely skipped while the same call notifies every
  one of those agents.
"""

from __future__ import annotations

import pytest

from rine import (
    GROUP_EVICTED_CODE,
    GroupAdmissionEntry,
    GroupAdmissionReport,
    GroupEvictedError,
    MlsError,
    admission_headline,
    admitted_agent_ids,
    describe_admission_entry,
    group_admission_skip_sentence,
)
from rine._mls.binding import GroupInactiveError, MlsProtocolError, MlsStoreError
from rine._mls.failures import group_failures
from rine._mls.tree import leaf_index
from rine._sender_key_ops import sender_key_state_exists
from rine.group_admission import GroupAdmissionSkipReason
from rine.group_removal import removal_message

GROUP = "#standup@acme.rine.network"
AGENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "cccccccc-dddd-eeee-ffff-000000000000"


class TestRemovalMessageTellsTheGroupTypesApart:
    def test_leaving_an_mls_group_reports_what_the_wipe_cost(self):
        text = removal_message(GROUP, AGENT, left=True, encryption="mls", epoch=None)

        assert GROUP in text
        assert "epoch secret" in text
        # Accepted and stated, never softened into "still opens".
        assert "including the ones that arrived before you left" in text

    def test_leaving_an_open_group_never_claims_a_cryptographic_eviction(self):
        text = removal_message(GROUP, AGENT, left=True, encryption="sender-key", epoch=None)

        assert "no cryptographic eviction" in text
        assert "rotating their sender key" in text
        # The false half of the shipped sentence. An open group needs no rejoin.
        assert "only way back in" not in text

    def test_leaving_with_nothing_held_does_not_claim_a_wipe(self):
        text = removal_message(GROUP, AGENT, left=True, encryption=None, epoch=None)

        assert "held no local key material" in text
        assert "nothing to retire" in text

    def test_a_kick_that_committed_names_the_epoch_it_landed_at(self):
        text = removal_message(GROUP, AGENT, left=False, encryption="mls", epoch=47)

        assert "epoch 47" in text
        assert "ratchet-tree leaf" in text

    def test_a_rescue_names_its_epoch_without_claiming_a_leaf_went(self):
        """A commit that landed no longer implies a leaf that left."""
        text = removal_message(
            GROUP, AGENT, left=False, encryption="mls", epoch=47, removed_leaf=False
        )

        assert "epoch 47" in text
        assert "carries the signing key they publish now" in text
        assert "rotated their signing key" in text
        assert "took their ratchet-tree leaf" not in text

    def test_a_kick_from_an_open_group_says_what_actually_bounds_their_reach(self):
        text = removal_message(GROUP, AGENT, left=False, encryption="sender-key", epoch=None)

        assert "no cryptographic eviction" in text
        assert "rotating their sender key" in text

    def test_an_unattributed_kick_claims_nothing_about_the_crypto(self):
        text = removal_message(GROUP, AGENT, left=False, encryption=None, epoch=None)

        assert text == f"Removed {AGENT} from group {GROUP}."


class TestEvictionIsStatedAsAMembershipFact:
    def test_group_failures_turns_the_cores_invariant_into_rines_refusal(self):
        with pytest.raises(GroupEvictedError) as caught, group_failures("group-7"):
            raise GroupInactiveError("this member was removed from the group at epoch 47")

        assert caught.value.code == GROUP_EVICTED_CODE
        assert "You were removed from group group-7" in str(caught.value)
        assert "invite you again" in str(caught.value)

    def test_an_eviction_is_still_catchable_as_the_mls_error_it_replaces(self):
        """Callers already writing ``except MlsError`` keep catching it."""
        assert issubclass(GroupEvictedError, MlsError)

    def test_a_store_failure_is_never_reported_as_an_eviction(self):
        """This process's own problem must not read as something it can fix."""
        with pytest.raises(MlsStoreError), group_failures("group-7"):
            raise MlsStoreError("disk unwritable")

    def test_leaf_index_answers_none_for_an_identity_that_holds_no_leaf(self):
        assert leaf_index(_UnseatedGroup(), b"identity") is None

    def test_leaf_index_refuses_to_report_an_eviction_as_an_empty_seat(self):
        """Answering ``None`` would send removal down the nothing-to-remove path."""
        with pytest.raises(GroupInactiveError):
            leaf_index(_EvictedGroup(), b"identity")


class _UnseatedGroup:
    """The compiled core's answer for an identity that holds no leaf."""

    def member_index(self, identity: bytes) -> int:
        raise MlsProtocolError("no leaf for this identity")


class _EvictedGroup:
    """The compiled core's answer once a Remove commit took this member's leaf."""

    def member_index(self, identity: bytes) -> int:
        raise GroupInactiveError("this member was removed from the group at epoch 47")


class TestSkipReasonsReadAsSentences:
    def test_every_reason_the_server_can_send_has_a_sentence(self):
        for reason in GroupAdmissionSkipReason.__args__:
            text = group_admission_skip_sentence(reason)
            assert text == text.lstrip().rstrip("."), reason
            assert reason not in text, reason

    def test_not_applicable_says_the_group_needs_no_voucher(self):
        text = group_admission_skip_sentence("not_applicable")

        assert "open enrollment" in text
        assert "may join whenever it likes" in text
        assert "mints no invitation because none is needed" in text

    def test_an_unstated_reason_says_so_rather_than_inventing_one(self):
        assert group_admission_skip_sentence(None) == "no reason given"

    def test_an_open_groups_entry_is_not_described_as_skipped(self):
        """The same call DMs these agents; calling them skipped says the opposite."""
        entry = GroupAdmissionEntry(agent_id=AGENT, status="skipped", reason="not_applicable")

        line = describe_admission_entry(entry)

        assert line == f"{AGENT}: {group_admission_skip_sentence('not_applicable')}"
        assert "skipped" not in line

    def test_a_real_refusal_still_reads_as_one(self):
        entry = GroupAdmissionEntry(agent_id=AGENT, status="skipped", reason="agent_revoked")

        line = describe_admission_entry(entry)

        assert line.startswith(f"{AGENT}: ")
        assert "revoked" in line

    def test_an_invited_entry_says_only_that(self):
        entry = GroupAdmissionEntry(agent_id=AGENT, status="invited")

        assert describe_admission_entry(entry) == f"{AGENT}: invited"


class TestANominationIsNotAnInvitation:
    """An invite to a voting group settles nothing on its own.

    A nomination is a third outcome, not a spelling of ``invited``. It reserves
    a ratchet-tree seat, so it counts as reached; it is decided by the
    electorate, so calling it an invitation to accept tells an operator the
    admission is finished when it has not begun.
    """

    def test_a_nominated_entry_says_the_electorate_has_yet_to_decide(self):
        entry = GroupAdmissionEntry(agent_id=AGENT, status="nominated")

        assert describe_admission_entry(entry) == f"{AGENT}: nominated, awaiting a vote"

    def test_a_nominee_counts_as_reached_because_it_holds_a_seat(self):
        report = GroupAdmissionReport(
            invited=0,
            skipped=0,
            entries=[GroupAdmissionEntry(agent_id=AGENT, status="nominated")],
        )

        assert admitted_agent_ids(report) == [AGENT]

    def test_a_headline_of_nominations_alone_never_calls_them_invitations(self):
        report = GroupAdmissionReport(
            invited=0,
            skipped=0,
            entries=[
                GroupAdmissionEntry(agent_id=AGENT, status="nominated"),
                GroupAdmissionEntry(agent_id=OTHER, status="nominated"),
            ],
        )

        assert admission_headline(report) == ("2 of 2 reached; 2 new nominations awaiting a vote.")

    def test_a_headline_of_invitations_alone_is_the_sentence_it_always_was(self):
        report = GroupAdmissionReport(
            invited=1,
            skipped=0,
            entries=[GroupAdmissionEntry(agent_id=AGENT, status="invited")],
        )

        assert admission_headline(report) == "1 of 1 reached; 1 new invitation to accept."

    def test_a_headline_of_both_names_both_with_the_invitations_first(self):
        report = GroupAdmissionReport(
            invited=1,
            skipped=0,
            entries=[
                GroupAdmissionEntry(agent_id=AGENT, status="invited"),
                GroupAdmissionEntry(agent_id=OTHER, status="nominated"),
            ],
        )

        assert admission_headline(report) == (
            "2 of 2 reached; 1 new invitation to accept; 1 new nomination awaiting a vote."
        )

    def test_an_open_groups_headline_still_reports_no_invitations(self):
        """The counters read "0 invited, N skipped" here and always have.

        Deriving the clause from the entries rather than the counters must not
        change what an open group says: nothing was minted because nothing was
        needed, and all N were still reached.
        """
        report = GroupAdmissionReport(
            invited=0,
            skipped=1,
            entries=[
                GroupAdmissionEntry(agent_id=AGENT, status="skipped", reason="not_applicable")
            ],
        )

        assert admission_headline(report) == "1 of 1 reached; 0 new invitations to accept."


class TestSenderKeyStateIsFoundUnderEitherSpelling:
    def test_no_state_file_means_no_material(self, tmp_config_dir, agent_id):
        assert sender_key_state_exists(tmp_config_dir, agent_id, GROUP_UUID) is False

    def test_state_written_lower_case_is_found_when_asked_upper_case(
        self, tmp_config_dir, agent_id
    ):
        """The SDK passes an ``is_uuid`` argument through without normalising it."""
        _write_state(tmp_config_dir, agent_id, GROUP_UUID)

        assert sender_key_state_exists(tmp_config_dir, agent_id, GROUP_UUID.upper()) is True


GROUP_UUID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


def _write_state(config_dir: str, agent_id: str, group_id: str) -> None:
    from rine._crypto.sender_keys import generate_sender_key
    from rine._crypto.sender_keys_helpers import save_sender_key_state

    save_sender_key_state(
        config_dir, agent_id, group_id, [generate_sender_key(group_id, agent_id)]
    )
