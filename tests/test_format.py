"""The group predicates, and the lines between them.

``group_is_mls`` answers "does this group have MLS state?" and ``mls_group_id``
is the only field that says so; ``group_accepts_mls_send_only`` answers "will the
server refuse a sender-key send here?" and adds the in-flight init window.
Reading either flag for the other's question is the defect these tests pin.
``group_mls_init_in_flight`` names the window the two disagree over, and the
three together partition every group into exactly one of three renderable states.
``group_mls_never_founded`` splits the last of those three, from the one thing
the MLS columns cannot say: what the group was created FOR.
"""

from __future__ import annotations

from typing import Any, get_args

import pytest

from rine._mls.admission import MlsAdmissionResult
from rine.format import (
    _ENCRYPTION_WORDS,
    MLS_NEVER_FOUNDED_NOTE,
    _join_lines,
    GroupEncryption,
    describe_group_encryption,
    group_accepts_mls_send_only,
    group_encryption,
    group_is_mls,
    group_mls_init_in_flight,
    group_mls_never_founded,
    mls_never_founded_sync,
    unfounded_group_note,
)
from rine.group_admission import GroupCreateWithRoster
from rine.types import GroupRead

_BASE: dict[str, Any] = {
    "id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": False,
    "mls_group_id": None,
    "mls_pending": False,
    "mls_cipher_suite": None,
}


def _group(**over: Any) -> GroupRead:
    return GroupRead.model_validate({**_BASE, **over})


def _created(**over: Any) -> GroupCreateWithRoster:
    """The same row as :func:`_group`, on the type ``groups.create`` returns.

    Only this type carries ``mls_init`` and ``mls_admission``, the two fields a
    plain ``GroupRead`` cannot: they record what the calling client watched
    happen and are recoverable from no re-read.
    """
    return GroupCreateWithRoster.model_validate({**_BASE, **over})


class TestGroupIsMls:
    def test_group_is_mls_when_group_has_an_mls_latch_returns_true(self):
        assert group_is_mls(_group(mls_group_id="mls-latch-abc")) is True

    def test_group_is_mls_when_open_group_with_mls_enabled_returns_false(self):
        """The intent flag is not the state.

        Open enrollment runs on sender keys by design — the server refuses MLS
        there — yet the group still carries the ``mls_enabled`` intent flag.
        """
        group = _group(enrollment_policy="open", mls_enabled=True, mls_group_id=None)

        assert group_is_mls(group) is False

    def test_group_is_mls_when_init_is_still_pending_returns_false(self):
        """An init in flight is not state: nothing can be decrypted with it yet."""
        assert group_is_mls(_group(mls_enabled=True, mls_pending=True)) is False

    def test_group_is_mls_when_group_is_sender_key_returns_false(self):
        assert group_is_mls(_group()) is False


class TestGroupAcceptsMlsSendOnly:
    def test_group_accepts_mls_send_only_when_init_is_pending_returns_true(self):
        """The server's ``is_mls_frozen`` mirror.

        A sender-key send into a group whose init is in flight is refused with a 409.
        """
        pending = _group(mls_enabled=True, mls_pending=True)

        assert group_accepts_mls_send_only(pending) is True
        assert group_is_mls(pending) is False

    def test_group_accepts_mls_send_only_when_group_has_an_mls_latch_returns_true(self):
        assert group_accepts_mls_send_only(_group(mls_group_id="mls-abc")) is True

    def test_group_accepts_mls_send_only_when_open_group_with_mls_enabled_returns_false(self):
        group = _group(enrollment_policy="open", mls_enabled=True)

        assert group_accepts_mls_send_only(group) is False


class TestGroupMlsInitInFlight:
    def test_group_mls_init_in_flight_when_init_is_pending_returns_true(self):
        assert group_mls_init_in_flight(_group(mls_enabled=True, mls_pending=True)) is True

    def test_group_mls_init_in_flight_when_group_has_an_mls_latch_returns_false(self):
        """The latch ends the window, even before the server clears the flag.

        There is MLS state to render, so the group is simply MLS.
        """
        latched = _group(mls_group_id="mls-abc", mls_pending=True)

        assert group_mls_init_in_flight(latched) is False

    def test_group_mls_init_in_flight_when_open_group_with_mls_enabled_returns_false(self):
        """The case the window must never swallow.

        Open enrollment runs on sender keys by design and no init is, or will
        be, in flight for it.
        """
        group = _group(enrollment_policy="open", mls_enabled=True)

        assert group_mls_init_in_flight(group) is False

    def test_group_mls_init_in_flight_when_group_is_sender_key_returns_false(self):
        assert group_mls_init_in_flight(_group()) is False

    def test_group_predicates_when_asked_together_place_a_group_in_exactly_one_state(self):
        """The three renderable states are mutually exclusive and total.

        That is what lets a renderer branch on them without a fourth fallback.
        """
        groups = [
            _group(mls_group_id="mls-abc"),
            _group(mls_enabled=True, mls_pending=True),
            _group(enrollment_policy="open", mls_enabled=True),
            _group(),
        ]

        for g in groups:
            states = [
                group_is_mls(g),
                group_mls_init_in_flight(g),
                not group_is_mls(g) and not group_mls_init_in_flight(g),
            ]
            assert sum(states) == 1


class TestGroupMlsNeverFounded:
    def test_group_mls_never_founded_when_closed_group_has_no_latch_returns_true(self):
        # 🔴 The founding never landed, and the server's 15-minute self-heal
        # put ``mls_pending`` back to false — so the four MLS columns are field
        # for field an open group's.
        assert group_mls_never_founded(_group(mls_enabled=True)) is True

    def test_group_mls_never_founded_when_group_is_open_returns_false(self):
        # The regression this predicate most plausibly causes: an open group has
        # the same null latch and carries ``mls_enabled`` from birth.
        assert group_mls_never_founded(_group(enrollment_policy="open", mls_enabled=True)) is False

    def test_group_mls_never_founded_when_closed_group_opted_out_of_mls_returns_false(self):
        assert group_mls_never_founded(_group(mls_enabled=False)) is False

    def test_group_mls_never_founded_when_group_is_latched_returns_false(self):
        assert group_mls_never_founded(_group(mls_enabled=True, mls_group_id="mls-abc")) is False

    def test_group_mls_never_founded_when_init_is_in_flight_returns_false(self):
        # Its own refusal already, with its own remedy: that one clears itself.
        assert group_mls_never_founded(_group(mls_enabled=True, mls_pending=True)) is False

    def test_group_mls_never_founded_when_true_then_the_other_two_states_are_false(self):
        g = _group(mls_enabled=True)
        assert group_mls_never_founded(g) is True
        assert group_is_mls(g) is False
        assert group_mls_init_in_flight(g) is False


class TestMlsNeverFoundedSync:
    """The warning's words. Byte for byte the TypeScript twin's
    (``rine-core/src/mls-recovery-format.ts::mlsNeverFoundedSync``) — two stacks
    describing one event differently is the drift this pinning exists to stop, so
    a wording change lands in both files together.
    """

    def test_mls_never_founded_sync_when_called_then_it_names_the_state(self):
        said = mls_never_founded_sync()
        assert "was created to run MLS" in said
        assert "ratchet tree was never founded" in said
        assert "sealed with sender keys" in said

    def test_mls_never_founded_sync_when_called_then_it_claims_no_failure(self):
        # A founding that died and one that was never attempted leave identical
        # rows; and the group carries messages fine, on sender keys.
        said = mls_never_founded_sync()
        assert "failed" not in said
        assert "cannot carry" not in said
        assert "holds no keys" not in said

    def test_mls_never_founded_sync_when_called_then_it_names_no_group(self):
        # It is appended to a sentence that already named one — the eviction
        # sentence's shape. A second identifier in one answer is what makes two
        # stacks' output differ, and this warning is rendered by two callers that
        # name the group in different words.
        assert mls_never_founded_sync().startswith(MLS_NEVER_FOUNDED_NOTE)
        assert "#ops" not in mls_never_founded_sync()

    def test_mls_never_founded_sync_when_no_repair_is_named_then_it_names_no_verb(self):
        said = mls_never_founded_sync()
        assert "No verb on this surface founds it" in said
        assert "resume" not in said

    def test_mls_never_founded_sync_when_a_repair_is_named_then_it_uses_that_spelling(self):
        assert "Run rine group resume-admission on it to found its MLS state" in (
            mls_never_founded_sync("cli-resume-admission")
        )
        assert "Run resume_admission() on it to found its MLS state" in mls_never_founded_sync(
            "sdk-resume-admission"
        )
        assert "Run rine_group_reclaim on it to found its MLS state" in mls_never_founded_sync(
            "tool-group-reclaim"
        )

    def test_mls_never_founded_sync_when_the_repair_is_unknown_then_it_refuses(self):
        # Named rather than left to a bare ``KeyError`` — and refused on the
        # TypeScript side too, which used to concatenate ``undefined`` onto the
        # end of the operator's warning for the same input. One event, one
        # behaviour: a near-miss of the union is a caller bug and says so.
        with pytest.raises(ValueError, match="Unknown repair verb"):
            mls_never_founded_sync("resume-admission")  # type: ignore[arg-type]

    def test_mls_never_founded_sync_when_repairs_differ_then_only_the_remedy_does(self):
        for repair in (
            "cli-resume-admission",
            "sdk-resume-admission",
            "tool-group-reclaim",
            "none",
        ):
            assert mls_never_founded_sync(repair).startswith(MLS_NEVER_FOUNDED_NOTE)

    def test_unfounded_group_note_when_a_repair_is_named_then_it_uses_that_spelling(self):
        # The same fact and the same remedy as the sync note, from the caller
        # that is describing the group rather than reporting a sync over it.
        assert "Run rine group resume-admission on it to found its MLS state." in (
            unfounded_group_note("cli-resume-admission")
        )
        assert "Run resume_admission() on it to found its MLS state." in unfounded_group_note(
            "sdk-resume-admission"
        )
        assert "Run rine_group_reclaim on it to found its MLS state." in unfounded_group_note(
            "tool-group-reclaim"
        )
        assert "No verb on this surface founds it" in unfounded_group_note()

    def test_unfounded_group_note_when_called_then_it_never_asks_for_a_sync_nobody_ran(self):
        # The one thing that separates the two notes. Its caller is answering
        # "what is this group encrypted with", so telling the reader to "run the
        # sync again" names an operation they never started.
        for repair in (
            "cli-resume-admission",
            "sdk-resume-admission",
            "tool-group-reclaim",
            "none",
        ):
            assert "sync" not in unfounded_group_note(repair)
            assert "sync" in mls_never_founded_sync(repair)


class TestGroupEncryptionWord:
    """The word a surface renders, and the sentence it maps to.

    Five words, not four. ``rine group show`` calling a never-founded group
    post-quantum MLS while ``rine group sync`` called it sender-key was one
    operator, one group, two stacks and two answers; this is the Python half of
    closing that.
    """

    def test_group_encryption_when_group_is_latched_returns_mls(self):
        assert group_encryption(_group(mls_enabled=True, mls_group_id="mls-abc")) == "mls"

    def test_group_encryption_when_founding_landed_and_the_re_read_failed_returns_mls(self):
        # 🔴 The founding LANDED and only the re-read after it was refused, so
        # the row this is asked about is the PRE-init one: no latch, no pending,
        # and every predicate below the admission arm reads it as a group whose
        # tree was never founded. ``mls_admission`` is what the founding
        # returned and exists nowhere else — ``_resources/group_ops.py`` carries
        # it across the failure on both the sync and the async path for exactly
        # this reason, and until this arm existed nothing read it, so the SDK
        # and all three Python connectors told the caller their founded, latched
        # group had never been founded.
        landed = _created(mls_enabled=True).model_copy(
            update={"mls_admission": MlsAdmissionResult(epoch=1, commits=1, added=0, outcomes=())}
        )

        assert group_encryption(landed) == "mls"
        # The control that makes the assertion above mean something: the same
        # row without the admission is still the never-founded diagnosis.
        assert group_encryption(_created(mls_enabled=True)) == "mls-never-founded"

    def test_group_encryption_when_init_is_in_flight_returns_mls_pending(self):
        assert group_encryption(_group(mls_enabled=True, mls_pending=True)) == "mls-pending"

    def test_group_encryption_when_tree_was_never_founded_returns_its_own_word(self):
        # 🔴 It used to fall to ``"sender-key"`` — true of this group, and half
        # the answer: nothing told the operator the group had not got the
        # encryption it was created for.
        assert group_encryption(_group(mls_enabled=True)) == "mls-never-founded"

    def test_group_encryption_when_group_is_open_returns_sender_key(self):
        # The regression this word most plausibly causes: an open group carries
        # ``mls_enabled`` from birth and has the same null latch.
        assert group_encryption(_group(enrollment_policy="open", mls_enabled=True)) == "sender-key"

    def test_group_encryption_when_closed_group_opted_out_of_mls_returns_sender_key(self):
        assert group_encryption(_group(mls_enabled=False)) == "sender-key"

    def test_describe_group_encryption_when_tree_was_never_founded_says_both_halves(self):
        said = describe_group_encryption(_group(mls_enabled=True))

        assert "Sender Keys" in said
        assert "NOT post-quantum" in said
        assert MLS_NEVER_FOUNDED_NOTE in said

    def test_describe_group_encryption_when_the_caller_has_a_verb_then_it_names_that_one(self):
        # The remedy is one operation spelled differently per surface, so the
        # caller names its own: the Python SDK's ``resume_admission()``, never
        # the CLI's, and never a tool name a library caller cannot invoke.
        said = describe_group_encryption(_group(mls_enabled=True), "sdk-resume-admission")

        assert "Run resume_admission() on it to found its MLS state." in said
        assert "rine group" not in said
        assert "rine_group_reclaim" not in said

    def test_describe_group_encryption_when_the_caller_has_no_verb_then_it_names_none(self):
        # An answer rather than a silence, for a caller that says it has no
        # founding verb: it says so instead of sending a reader after somebody
        # else's. Asked for by name — it is NOT the default here, see below.
        said = describe_group_encryption(_group(mls_enabled=True), "none")

        assert "No verb on this surface founds it" in said
        assert "resume" not in said
        assert "reclaim" not in said

    def test_describe_group_encryption_when_the_caller_takes_the_default_then_it_names_this_sdk(
        self,
    ):
        # 🔴 The default is this SDK's own method, not ``"none"``. This function
        # ships inside ``rine``, so every caller that can import it can call
        # ``client.groups.resume_admission()`` — and ``"none"`` renders "No verb
        # on this surface founds it", which is true of no Python caller. It went
        # out that way once: the harness's py-sdk driver calls this one-arg and
        # published that surface declaring it had no founding verb, while the
        # method sat on the same client. Every surface for which ``"none"`` IS
        # true is TypeScript and reads ``groupEncryption`` instead.
        said = describe_group_encryption(_group(mls_enabled=True))

        assert "Run resume_admission() on it to found its MLS state." in said
        assert "No verb on this surface founds it" not in said

    def test_describe_group_encryption_when_tree_was_never_founded_claims_no_outage(self):
        # 🔴 The three claims that shipped and were all false: the server does
        # not freeze this group, ``POST /messages`` succeeds on it, and its send
        # path mints and fans out sender keys. The defect is a silent downgrade.
        said = describe_group_encryption(_group(mls_enabled=True))

        for lie in ("broken", "frozen", "cannot carry", "holds no keys", "None yet"):
            assert lie not in said

    def test_describe_group_encryption_when_init_failed_claims_no_traffic_it_cannot_see(self):
        # The same group from the one vantage point that saw the attempt, and the
        # one word that must promise NOTHING about the traffic. Two sentences
        # shipped here and both were false: "holds no keys and cannot carry a
        # message", then "carries sender-key traffic". ``mls_init`` is set for an
        # attempt that never reached the server AND for one whose init POST
        # landed before a later step failed; the second leaves ``mls_pending``
        # set, which is ``is_mls_frozen``, and the server then refuses every
        # non-MLS send for up to 900 s. The object this renders from is the
        # create response, minted before the init, so it cannot tell them apart.
        said = _ENCRYPTION_WORDS["mls-failed"]

        assert "did not land" in said
        assert "NOT post-quantum" in said
        assert "refuses every non-MLS send" in said
        for lie in ("cannot carry", "holds no keys", "carries sender-key traffic"):
            assert lie not in said

    def test_describe_group_encryption_when_init_failed_names_no_verb(self):
        # Rendered by crewai, langchain and hermes, none of which has a
        # ``resume_admission`` — it named one anyway. Its sibling word names none
        # for the same reason, and ``UnfoundedGroupRepair`` is where a surface
        # that HAS the verb says so, in its own spelling.
        assert "resume_admission" not in _ENCRYPTION_WORDS["mls-failed"]

    def test_describe_group_encryption_when_group_is_open_blames_no_never_founded_state(self):
        said = describe_group_encryption(_group(enrollment_policy="open", mls_enabled=True))

        assert MLS_NEVER_FOUNDED_NOTE not in said
        assert "open enrollment off the MLS path" in said

    def test_group_encryption_when_every_word_is_asked_for_then_each_has_a_sentence(self):
        # A word with no sentence is a ``KeyError`` in front of an operator, so
        # the words are taken from the union itself rather than retyped here — a
        # sixth word added to the union with no sentence behind it fails this.
        for word in get_args(GroupEncryption):
            if word == "mls-never-founded":
                # This one alone has no fixed sentence: its repair clause names
                # the calling surface's own founding verb, so it is rendered
                # rather than looked up, and rendering it is the assertion. The
                # verb is named on both sides rather than defaulted, because the
                # two functions default differently and only one of them can.
                said = describe_group_encryption(_group(mls_enabled=True), "none")
                assert unfounded_group_note("none") in said
            else:
                assert _ENCRYPTION_WORDS[word]


class TestJoinLines:
    """The seam four sites used to hand-roll, and the case none of them asserted.

    The recorded failure mode of a hand-rolled copy is getting the empty case
    backwards, which emits a LEADING BLANK LINE into an operator's answer — and
    ``driver_framework_ts_admin.mjs`` and ``container_admin.py`` match these
    answers' heads with ``^``-anchored regexes, so a blank first line is read as
    the surface refusing: a successful recovery graded as a broken one. Nothing
    asserted it before this class. The TypeScript twin is the ``joinLines``
    block in ``rine-core/test/mls-recovery-format.test.ts``.
    """

    def test_join_lines_when_there_is_no_tail_then_the_head_comes_back_alone(self):
        assert _join_lines("head", "") == "head"
        assert _join_lines("head", None) == "head"

    def test_join_lines_when_there_is_no_head_then_no_leading_newline(self):
        assert _join_lines("", "tail") == "tail"

    def test_join_lines_when_both_halves_are_empty_then_the_answer_is_empty(self):
        assert _join_lines("", "") == ""
        assert _join_lines("", None) == ""

    def test_join_lines_when_both_halves_are_present_then_exactly_one_newline(self):
        assert _join_lines("head", "tail") == "head\ntail"

    def test_join_lines_when_any_half_is_absent_then_no_blank_first_or_last_line(self):
        for first in ("", "head"):
            for second in ("", None, "tail"):
                said = _join_lines(first, second)
                assert not said.startswith("\n")
                assert not said.endswith("\n")

    def test_join_lines_when_a_half_carries_its_own_spacing_then_it_is_untouched(self):
        # It joins; it never normalises. Every tail it appends is a sentence two
        # matrix drivers match, so rewriting one is the thing it may not do.
        assert _join_lines("head.", " tail ") == "head.\n tail "
