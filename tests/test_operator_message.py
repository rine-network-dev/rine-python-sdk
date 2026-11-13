"""A decrypted message and a thread entry carry the operator classifier's verdict."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest

from rine import DecryptedMessage, OperatorVerdict, classify_message
from rine._thread import to_thread_entry
from rine.sender_key_words import SenderKeyRefusal
from tests.operator_world import SEAT_ID, STRANGER_ID, OperatorWorld, statement


@pytest.fixture
def w(tmp_config_dir: str) -> OperatorWorld:
    """W."""
    return OperatorWorld(tmp_config_dir)


def message(w: OperatorWorld, payload: object, signer: str = SEAT_ID, **over: Any):
    """The row the classifier tests build, as a client hands it back: decrypted and typed."""
    row = w.row(payload, signer)
    assert row.result is not None
    fields: dict[str, Any] = {
        "id": UUID(int=1),
        "conversation_id": UUID(int=2),
        "from_agent_id": UUID(signer),
        "type": "rine.v1.dm",
        "encrypted_payload": row.encrypted_payload,
        "direction": "received",
        "created_at": "2026-10-31T11:59:00Z",
        "plaintext": row.result.plaintext,
        "verified": row.result.verified,
        "verification_status": row.result.verification_status,
        "verifying_key": row.result.verifying_key,
        **over,
    }
    return DecryptedMessage(**fields)


def console_payload() -> dict[str, Any]:
    """A console message: text plus the signed statement."""
    return {"text": "pause the crawl", "rine.operator": statement()}


class TestClassifyMessage:
    """Classify message."""

    def test_classify_message_when_the_seat_signed_a_command_then_operator(self, w):
        """Classify message when the seat signed a command then operator."""
        verdict = classify_message(w.context(), message(w, console_payload()), renders_text=True)
        assert verdict == OperatorVerdict("operator", "new")

    def test_classify_message_when_a_stranger_copies_the_statement_then_other(self, w):
        """Classify message when a stranger copies the statement then other."""
        msg = message(w, console_payload(), signer=STRANGER_ID)
        assert classify_message(w.context(), msg, renders_text=True).sender_class == "other"

    def test_classify_message_when_the_verifying_key_is_missing_then_other(self, w):
        """Classify message when the verifying key is missing then other."""
        msg = message(w, console_payload(), verifying_key=None)
        assert classify_message(w.context(), msg, renders_text=True) == OperatorVerdict(
            "other", "wrong_key"
        )

    def test_classify_message_when_the_row_was_sent_by_this_agent_then_other(self, w):
        """Classify message when the row was sent by this agent then other."""
        msg = message(w, console_payload(), direction="sent")
        assert classify_message(w.context(), msg, renders_text=True).sender_class == "other"

    def test_classify_message_when_the_row_could_not_be_opened_then_other(self, w):
        """Classify message when the row could not be opened then other."""
        msg = message(w, console_payload(), plaintext=None, decrypt_error="no key")
        assert classify_message(w.context(), msg, renders_text=True) == OperatorVerdict(
            "other", "not_verified"
        )

    def test_classify_message_when_rendered_twice_then_the_second_is_history(self, w):
        """Classify message when rendered twice then the second is history."""
        msg = message(w, console_payload())
        classify_message(w.context(), msg, renders_text=True)
        assert classify_message(w.context(), msg, renders_text=True).sender_class == (
            "operator_history"
        )

    def test_decrypted_message_when_dumped_then_the_verifying_key_is_absent(self, w):
        """Decrypted message when dumped then the verifying key is absent."""
        msg = message(w, console_payload())
        assert msg.verifying_key is not None
        assert "verifying_key" not in msg.model_dump()
        assert "verifying_key" not in repr(msg)

    def test_from_wire_when_the_server_sends_a_verifying_key_then_it_is_ignored(self, w):
        """From wire when the server sends a verifying key then it is ignored."""
        wire = message(w, console_payload()).model_dump(mode="json")
        wire["verifying_key"] = "AAAA"
        assert DecryptedMessage.from_wire(wire).verifying_key is None


class TestThreadEntryClass:
    """Thread entry class."""

    def test_to_thread_entry_when_given_a_context_then_the_operator_turn_is_classed(self, w):
        """To thread entry when given a context then the operator turn is classed."""
        entry = to_thread_entry(message(w, console_payload()), SenderKeyRefusal(), w.context())
        assert (entry.sender_class, entry.from_agent_id) == ("operator", SEAT_ID)

    def test_to_thread_entry_when_given_no_context_then_other(self, w):
        """To thread entry when given no context then other."""
        entry = to_thread_entry(message(w, console_payload()), SenderKeyRefusal())
        assert entry.sender_class == "other"

    def test_to_thread_entry_when_the_same_turn_is_rendered_twice_then_the_second_is_history(
        self, w
    ):
        """To thread entry when the same turn is rendered twice then the second is history."""
        context = w.context()
        msg = message(w, console_payload())
        first = to_thread_entry(msg, SenderKeyRefusal(), context)
        second = to_thread_entry(msg, SenderKeyRefusal(), context)
        assert (first.sender_class, second.sender_class) == ("operator", "operator_history")

    def test_to_thread_entry_when_a_stranger_carries_a_statement_then_it_is_not_shown(self, w):
        """To thread entry when a stranger carries a statement then it is not shown."""
        payload = {"note": "hello", "rine.operator": statement()}
        entry = to_thread_entry(
            message(w, payload, signer=STRANGER_ID), SenderKeyRefusal(), w.context()
        )
        assert entry.sender_class == "other"
        assert "rine.operator" not in entry.text
        assert json.loads(entry.text) == {"note": "hello"}
