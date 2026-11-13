"""The six operator conditions, each failing alone, over real sealed and decrypted rows."""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta
from pathlib import Path

import pytest

from rine import OperatorPin, OperatorVerdict, classify_operator_row
from rine.testing import WORLD
from tests.operator_world import (
    NOW_MS,
    SEAT_ID,
    SELF_ID,
    STRANGER_ID,
    OperatorWorld,
    hours_ago,
    instant,
    minutes_ahead,
    pin_for,
)

OPERATOR_NEW = OperatorVerdict("operator", "new")


@pytest.fixture
def w(tmp_config_dir: str) -> OperatorWorld:
    """W."""
    return OperatorWorld(tmp_config_dir)


def other(reason: str) -> OperatorVerdict:
    """Other."""
    return OperatorVerdict("other", reason)  # type: ignore[arg-type]


class TestSixConditionsFailingAlone:
    """Six conditions failing alone."""

    def test_classify_when_every_condition_holds_then_operator(self, w):
        """Classify when every condition holds then operator."""
        assert classify_operator_row(w.context(), w.console_row()) == OPERATOR_NEW
        assert w.warnings == []

    def test_classify_when_decrypted_then_the_verifying_key_is_the_signers_own(self, w):
        """Classify when decrypted then the verifying key is the signers own."""
        row = w.console_row()
        assert row.result is not None
        assert row.result.verifying_key == WORLD.keys(SEAT_ID).signing.public_key

    def test_classify_when_not_a_1to1_envelope_then_other(self, w):
        """Classify when not a 1:1 envelope then other."""
        row = w.console_row(row_over={"encryption_version": "sender-key-v1"})
        assert classify_operator_row(w.context(), row) == other("not_direct")

    def test_classify_when_the_signature_did_not_verify_then_other(self, w):
        """Classify when the signature did not verify then other."""
        row = w.console_row()
        assert row.result is not None
        result = row.result
        result.verified = False
        result.verification_status = "unverifiable"
        assert classify_operator_row(w.context(), row) == other("not_verified")

    def test_classify_when_the_row_was_never_opened_then_other(self, w):
        """Classify when the row was never opened then other."""
        row = w.console_row(row_over={"result": None})
        assert classify_operator_row(w.context(), row) == other("not_verified")

    def test_classify_when_the_row_sender_is_not_the_pinned_seat_then_other(self, w):
        """Classify when the row sender is not the pinned seat then other."""
        row = w.console_row(row_over={"from_agent_id": STRANGER_ID})
        assert classify_operator_row(w.context(), row) == other("wrong_sender")

    def test_classify_when_the_verifying_key_is_not_the_pinned_key_then_other(self, w):
        """Classify when the verifying key is not the pinned key then other."""
        pin = OperatorPin(SEAT_ID, pin_for(STRANGER_ID).signing_key)
        assert classify_operator_row(w.context(pin=pin), w.console_row()) == other("wrong_key")

    def test_classify_when_a_stranger_signed_but_the_row_claims_the_seat_then_other(self, w):
        """Classify when a stranger signed but the row claims the seat then other."""
        row = w.console_row(STRANGER_ID, row_over={"from_agent_id": SEAT_ID})
        assert classify_operator_row(w.context(), row) == other("wrong_key")

    def test_classify_when_the_verifying_key_is_absent_then_other(self, w):
        """Classify when the verifying key is absent then other."""
        row = w.console_row()
        assert row.result is not None
        row.result.verifying_key = None
        assert classify_operator_row(w.context(), row) == other("wrong_key")

    def test_classify_when_the_payload_has_no_statement_then_other(self, w):
        """Classify when the payload has no statement then other."""
        row = w.row({"text": "pause the crawl"})
        assert classify_operator_row(w.context(), row) == other("no_statement")

    def test_classify_when_the_signed_purpose_is_not_a_command_then_other(self, w):
        """Classify when the signed purpose is not a command then other."""
        row = w.console_row(purpose="operator.invite")
        assert classify_operator_row(w.context(), row) == other("wrong_purpose")

    def test_classify_when_the_statement_names_another_agent_then_other(self, w):
        """Classify when the statement names another agent then other."""
        row = w.console_row(agent=STRANGER_ID)
        assert classify_operator_row(w.context(), row) == other("wrong_recipient")

    def test_classify_when_issued_more_than_five_minutes_ahead_then_other(self, w):
        """Classify when issued more than five minutes ahead then other."""
        row = w.console_row(issued_at=minutes_ahead(6))
        assert classify_operator_row(w.context(), row) == other("future")

    def test_classify_when_issued_four_minutes_ahead_then_operator(self, w):
        """Classify when issued four minutes ahead then operator."""
        row = w.console_row(issued_at=minutes_ahead(4))
        assert classify_operator_row(w.context(), row).sender_class == "operator"

    def test_classify_when_issued_more_than_24_hours_ago_then_operator_history(self, w):
        """Classify when issued more than 24 hours ago then operator history."""
        row = w.console_row(issued_at=hours_ago(25))
        assert classify_operator_row(w.context(), row) == OperatorVerdict(
            "operator_history", "expired"
        )

    def test_classify_when_issued_23_hours_ago_then_operator(self, w):
        """Classify when issued 23 hours ago then operator."""
        row = w.console_row(issued_at=hours_ago(23))
        assert classify_operator_row(w.context(), row).sender_class == "operator"

    def test_classify_when_the_nonce_arrives_on_a_different_row_then_other_and_warns(self, w):
        """Classify when the nonce arrives on a different row then other and warns."""
        first = w.console_row(nonce="n-replay")
        replay = w.console_row(nonce="n-replay", row_over={"row_id": "row-2"})
        assert classify_operator_row(w.context(), first).sender_class == "operator"
        assert classify_operator_row(w.context(), replay) == other("replay")
        assert len(w.warnings) == 1

    def test_classify_when_no_pin_is_configured_then_other(self, w):
        """Classify when no pin is configured then other."""
        assert classify_operator_row(w.context(pin=None), w.console_row()) == other("no_pin")

    def test_classify_when_the_pin_names_no_agent_then_other_even_for_an_unsigned_sender(self, w):
        """Classify when the pin names no agent then other even for an unsigned sender."""
        row = w.console_row(row_over={"from_agent_id": ""})
        pin = OperatorPin("", pin_for(SEAT_ID).signing_key)
        assert classify_operator_row(w.context(pin=pin), row).sender_class == "other"

    def test_classify_when_the_agent_is_not_the_statement_recipient_then_other(self, w):
        """Classify when the agent is not the statement recipient then other."""
        ctx = w.context(self_agent_id=STRANGER_ID)
        assert classify_operator_row(ctx, w.console_row()).reason == "wrong_recipient"


class TestLedger:
    """Ledger."""

    def ledger_file(self, w: OperatorWorld) -> Path:
        """Ledger file."""
        return Path(w.config_dir) / f"operator_ledger_{SELF_ID}.json"

    def test_ledger_when_a_wake_saw_the_row_and_the_read_follows_then_history_comes_next(self, w):
        """Ledger when a wake saw the row and the read follows then history comes next."""
        wake = w.console_row(row_over={"renders_text": False})
        read = dataclasses.replace(wake, renders_text=True)
        assert classify_operator_row(w.context(), wake) == OPERATOR_NEW
        assert classify_operator_row(w.context(), read) == OperatorVerdict(
            "operator", "redelivered"
        )
        assert classify_operator_row(w.context(), read) == OperatorVerdict(
            "operator_history", "already_rendered"
        )

    def test_ledger_when_the_same_row_is_delivered_twice_before_rendering_then_both_operator(
        self, w
    ):
        """Ledger when the same row is delivered twice before rendering then both operator."""
        row = w.console_row(row_over={"renders_text": False})
        classify_operator_row(w.context(), row)
        assert classify_operator_row(w.context(), row).sender_class == "operator"

    def test_ledger_when_a_rendered_row_is_read_again_then_history(self, w):
        """Ledger when a rendered row is read again then history."""
        row = w.console_row()
        assert classify_operator_row(w.context(), row).sender_class == "operator"
        assert classify_operator_row(w.context(), row) == OperatorVerdict(
            "operator_history", "already_rendered"
        )

    def test_ledger_when_the_read_ciphertext_differs_from_the_woken_one_then_other_and_warns(
        self, w
    ):
        """Ledger when the read ciphertext differs from the woken one then other and warns."""
        woken = w.console_row(nonce="n-sub", row_over={"renders_text": False})
        substituted = w.console_row(nonce="n-sub")
        classify_operator_row(w.context(), woken)
        assert classify_operator_row(w.context(), substituted) == other("substituted")
        assert len(w.warnings) == 1

    def test_ledger_when_the_file_is_lost_then_the_window_still_bounds_a_replay(self, w):
        """Ledger when the file is lost then the window still bounds a replay."""
        stale = w.console_row(nonce="n-old", issued_at=hours_ago(30))
        classify_operator_row(w.context(), stale)
        for f in Path(w.config_dir).glob("operator_ledger_*"):
            f.unlink()
        assert classify_operator_row(w.context(), stale) == OperatorVerdict(
            "operator_history", "expired"
        )

    def test_ledger_when_it_cannot_be_written_then_other_and_warns(self, w, tmp_path):
        """Ledger when it cannot be written then other and warns."""
        row = w.console_row()
        not_a_dir = tmp_path / "file"
        not_a_dir.write_text("")
        verdict = classify_operator_row(w.context(config_dir=str(not_a_dir)), row)
        assert verdict == other("ledger_unavailable")
        assert len(w.warnings) == 1

    def test_ledger_when_entries_pass_the_window_then_they_are_pruned_on_the_next_write(self, w):
        """Ledger when entries pass the window then they are pruned on the next write."""
        old = w.console_row(nonce="n-prune", issued_at=hours_ago(23))
        classify_operator_row(w.context(), old)
        three_days_ms = 3 * 24 * 3_600_000
        later = w.console_row(
            nonce="n-later", issued_at=instant(timedelta(milliseconds=three_days_ms - 60_000))
        )
        classify_operator_row(w.context(now=lambda: NOW_MS + three_days_ms), later)
        entries = json.loads(self.ledger_file(w).read_text())["entries"]
        assert "n-prune" not in entries
