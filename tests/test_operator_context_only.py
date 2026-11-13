"""A row the server marks `context_only` is context, whatever its value, and spends the nonce."""

from __future__ import annotations

from datetime import timedelta

import pytest

from rine import OperatorVerdict, classify_message, classify_operator_row
from tests.operator_world import STRANGER_ID, OperatorWorld, hours_ago, instant
from tests.test_operator_message import console_payload, message

CONTEXT = OperatorVerdict("operator_history", "context_only")
MARKS = ["held", "sender_held", "recipient_held", "a_value_a_newer_server_adds"]


@pytest.fixture
def w(tmp_config_dir: str) -> OperatorWorld:
    """W."""
    return OperatorWorld(tmp_config_dir)


class TestContextOnly:
    """Context only."""

    @pytest.mark.parametrize("mark", MARKS)
    def test_classify_when_the_row_is_marked_context_only_then_operator_history(self, w, mark):
        """Classify when the row is marked context only then operator history."""
        row = w.console_row(row_over={"context_only": mark})
        assert classify_operator_row(w.context(), row) == CONTEXT

    def test_classify_when_the_mark_is_empty_or_absent_then_operator(self, w):
        """Classify when the mark is empty or absent then operator."""
        assert classify_operator_row(
            w.context(), w.console_row(row_over={"context_only": ""})
        ) == OperatorVerdict("operator", "new")

    def test_classify_when_marked_and_older_than_the_window_then_context_not_expired(self, w):
        """A held row can be older than the 24 h window at the resume: context, not expiry."""
        row = w.console_row(issued_at=hours_ago(30), row_over={"context_only": "held"})
        assert classify_operator_row(w.context(), row) == CONTEXT

    def test_classify_when_a_marked_row_spent_the_nonce_then_the_replay_is_refused(self, w):
        """Classify when a marked row spent the nonce then the replay is refused."""
        classify_operator_row(w.context(), w.console_row(row_over={"context_only": "held"}))
        replay = w.console_row(row_over={"row_id": "row-2"})
        assert classify_operator_row(w.context(), replay) == OperatorVerdict("other", "replay")

    def test_classify_when_the_marked_row_is_from_a_stranger_then_wrong_sender_stands(self, w):
        """Classify when the marked row is from a stranger then wrong sender stands."""
        row = w.console_row(signer=STRANGER_ID, row_over={"context_only": "held"})
        assert classify_operator_row(w.context(), row) == OperatorVerdict("other", "wrong_sender")

    def test_classify_when_the_marked_row_is_in_the_future_then_future_stands(self, w):
        """Classify when the marked row is in the future then future stands."""
        row = w.console_row(
            issued_at=instant(timedelta(hours=1)), row_over={"context_only": "held"}
        )
        assert classify_operator_row(w.context(), row) == OperatorVerdict("other", "future")


class TestClassifyMessageContextOnly:
    """The mark rides from the typed message into the classifier."""

    @pytest.mark.parametrize("mark", MARKS)
    def test_classify_message_when_the_message_is_marked_then_operator_history(self, w, mark):
        """Classify message when the message is marked then operator history."""
        msg = message(w, console_payload(), context_only=mark)
        assert classify_message(w.context(), msg, renders_text=True) == CONTEXT

    def test_classify_message_when_the_message_is_unmarked_then_operator(self, w):
        """Classify message when the message is unmarked then operator."""
        msg = message(w, console_payload())
        assert classify_message(w.context(), msg, renders_text=True) == OperatorVerdict(
            "operator", "new"
        )
