"""The operator ledger fails closed, has one file per agent and keeps a live holder's lock."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from rine import OperatorVerdict, classify_operator_row
from tests.operator_world import SELF_ID, OperatorWorld


@pytest.fixture
def w(tmp_config_dir: str) -> OperatorWorld:
    """The seat, the agent and a stranger over a fresh config dir."""
    return OperatorWorld(tmp_config_dir)


def ledger(w: OperatorWorld, agent_id: str = SELF_ID) -> Path:
    """Where the ledger of ``agent_id`` lives."""
    return Path(w.config_dir) / f"operator_ledger_{agent_id}.json"


def hold_lock(w: OperatorWorld, age_ms: int = 0) -> Path:
    """A lock another process took ``age_ms`` ago and has not released."""
    lock = Path(f"{ledger(w)}.lock")
    held = {"pid": 1, "acquired_at": int(time.time() * 1000) - age_ms, "token": "other"}
    lock.write_text(json.dumps(held) + "\n")
    return lock


def test_ledger_when_the_file_is_torn_then_the_row_is_data_the_file_is_kept_and_it_warns(w):
    """A torn file is never read as empty and overwritten."""
    ledger(w).write_text("{not json")
    verdict = classify_operator_row(w.context(), w.console_row())
    assert verdict == OperatorVerdict("other", "ledger_unavailable")
    assert len(w.warnings) == 1
    assert str(ledger(w)) in w.warnings[0]
    assert ledger(w).read_text() == "{not json"


def test_ledger_when_an_entry_is_malformed_then_the_row_is_data_and_the_file_is_kept(w):
    """A well-formed file with a bad entry is not repaired by dropping the entry."""
    body = json.dumps({"v": 1, "entries": {"n": {"row_id": 7}}})
    ledger(w).write_text(body)
    verdict = classify_operator_row(w.context(), w.console_row())
    assert verdict.reason == "ledger_unavailable"
    assert ledger(w).read_text() == body


def test_ledger_when_the_agent_id_differs_only_in_case_then_both_share_one_ledger(w):
    """Two surfaces typing one id in different case see the same record."""
    row = w.console_row()
    assert classify_operator_row(w.context(self_agent_id=SELF_ID.upper()), row).reason == "new"
    assert classify_operator_row(w.context(), row) == OperatorVerdict(
        "operator_history", "already_rendered"
    )
    assert ledger(w).exists()


def test_ledger_when_a_holder_is_six_seconds_old_then_its_lock_is_waited_for_not_taken(w):
    """A slow holder is waited for; only a lock past the acquire budget is stale."""
    lock = hold_lock(w, age_ms=6_000)
    held = lock.read_text()
    verdicts: list[OperatorVerdict] = []
    worker = threading.Thread(
        target=lambda: verdicts.append(classify_operator_row(w.context(), w.console_row()))
    )
    worker.start()
    time.sleep(0.3)
    assert lock.read_text() == held
    lock.unlink()
    worker.join(timeout=5)
    assert verdicts[0].sender_class == "operator"
