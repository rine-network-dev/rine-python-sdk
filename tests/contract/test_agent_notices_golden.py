"""The Python half of the agent-notices parity gate.

The sentences a model reads about rine text and control frames are pinned byte for
byte to ``rine-core``'s through one committed fixture, replayed here and by
``rine-core/test/agent-notices-golden.test.ts``. It lives under ``tests/contract``
because ``ci.sh`` stage 4 runs that directory and nothing else of this package.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from rine import (
    HIDDEN_CONTROL_FRAME_READ,
    OPERATOR_CONTENT_NOTICE,
    OPERATOR_HISTORY_NOTICE,
    UNTRUSTED_CONTENT_NOTICE,
    OperatorStatement,
    control_frame_reply_refusal,
    group_invite_notice,
    is_control_frame_type,
    is_group_invite,
    is_hidden_from_model,
    neutralise_notices,
    notice_for_class,
    parse_operator_statement,
    wrap_third_party_text,
)

#: The fixture lives with the TypeScript half, inside ``rine-core``, which ships in no
#: sdist of this package: its directory's absence is a checkout shape and skips, while
#: a directory without the file means the goldens were deleted and fails loudly.
FIXTURE_DIR = Path(__file__).resolve().parents[3] / "rine-core" / "test" / "fixtures"
FIXTURE = FIXTURE_DIR / "agent-notices.json"

REGENERATE = os.environ.get("RINE_NOTICES_REGEN") == "1"

needs_the_goldens = pytest.mark.skipif(
    not FIXTURE_DIR.is_dir(),
    reason="the golden vectors are not in this checkout (published sdist or mirror)",
)


def _parsed(statement: OperatorStatement | None) -> dict[str, Any] | None:
    if statement is None:
        return None
    return {
        "purpose": statement.purpose,
        "agent": statement.agent,
        "nonce": statement.nonce,
        "issued_at_ms": statement.issued_at_ms,
    }


def _fixture() -> dict[str, Any]:
    if not FIXTURE.exists():
        raise AssertionError(
            f"agent notices missing at {FIXTURE} — restore them (git checkout) or "
            "regenerate with RINE_NOTICES_REGEN=1 on BOTH stacks."
        )
    return json.loads(FIXTURE.read_text())


@needs_the_goldens
@pytest.mark.skipif(not REGENERATE, reason="regeneration is explicit: RINE_NOTICES_REGEN=1")
def test_the_fixture_when_regeneration_is_asked_for_then_this_stacks_half_is_rewritten() -> None:
    """Rewrite this stack's fields of the fixture; the TypeScript half must be run too."""
    doc = _fixture()
    doc["notice"] = UNTRUSTED_CONTENT_NOTICE
    doc["hidden_read"] = HIDDEN_CONTROL_FRAME_READ
    for row in doc["invite_notices"]:
        row["expected"] = group_invite_notice(row["handle"])
    for row in doc["reply_refusals"]:
        row["expected"] = control_frame_reply_refusal(row["type"])
    doc["operator_notice"] = OPERATOR_CONTENT_NOTICE
    doc["operator_history_notice"] = OPERATOR_HISTORY_NOTICE
    for row in doc["class_notices"]:
        row["expected"] = notice_for_class(row["class"])
    for row in doc["statements"]:
        row["expected"] = _parsed(parse_operator_statement(row["plaintext"]))
    for row in doc["neutralise"]:
        row["expected"] = neutralise_notices(row["text"])
    for row in doc["wrap"]:
        row["expected"] = wrap_third_party_text(row["text"], row["delimiter"])
    FIXTURE.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


@needs_the_goldens
def test_untrusted_notice_when_compared_to_golden_then_bytes_equal() -> None:
    """The untrusted-content notice is the same bytes on both stacks."""
    assert _fixture()["notice"] == UNTRUSTED_CONTENT_NOTICE


@needs_the_goldens
def test_hidden_read_when_compared_to_golden_then_bytes_equal() -> None:
    """The hidden-frame read result is the same bytes on both stacks."""
    assert _fixture()["hidden_read"] == HIDDEN_CONTROL_FRAME_READ


@needs_the_goldens
def test_message_type_when_classified_then_matches_golden() -> None:
    """Both stacks hide and invite-classify the same types."""
    for row in _fixture()["types"]:
        assert {
            "type": row["type"],
            "hidden": is_hidden_from_model(row["type"]),
            "invite": is_group_invite(row["type"]),
            "control": is_control_frame_type(row["type"]),
        } == row


@needs_the_goldens
def test_group_invite_notice_when_handle_given_or_null_then_matches_golden() -> None:
    """Both invite sentences are the same bytes on both stacks."""
    rows = _fixture()["invite_notices"]
    assert len(rows) > 1
    for row in rows:
        assert group_invite_notice(row["handle"]) == row["expected"]


@needs_the_goldens
def test_control_frame_reply_refusal_when_compared_to_golden_then_bytes_equal() -> None:
    """Both reply refusals are the same bytes on both stacks."""
    rows = _fixture()["reply_refusals"]
    assert len(rows) > 1
    for row in rows:
        assert control_frame_reply_refusal(row["type"]) == row["expected"]


@needs_the_goldens
def test_operator_notices_when_compared_to_golden_then_bytes_equal() -> None:
    """The operator and operator-history notices are the same bytes on both stacks."""
    doc = _fixture()
    assert doc["operator_notice"] == OPERATOR_CONTENT_NOTICE
    assert doc["operator_history_notice"] == OPERATOR_HISTORY_NOTICE


@needs_the_goldens
def test_notice_for_class_when_each_class_is_asked_then_matches_golden() -> None:
    """Each sender class maps to the same notice bytes on both stacks."""
    rows = _fixture()["class_notices"]
    assert len(rows) == 3
    for row in rows:
        assert notice_for_class(row["class"]) == row["expected"]


@needs_the_goldens
def test_operator_statement_when_parsed_then_matches_golden() -> None:
    """Both stacks accept and refuse the very same statements, and read the same instant."""
    rows = _fixture()["statements"]
    assert len(rows) > 30
    assert any(row["expected"] is not None for row in rows)
    for row in rows:
        assert {
            "name": row["name"],
            "parsed": _parsed(parse_operator_statement(row["plaintext"])),
        } == {
            "name": row["name"],
            "parsed": row["expected"],
        }


@needs_the_goldens
def test_neutralise_notices_when_applied_then_matches_golden() -> None:
    """Both stacks remove the very same copies of a notice from third-party text."""
    for row in _fixture()["neutralise"]:
        assert {"name": row["name"], "out": neutralise_notices(row["text"])} == {
            "name": row["name"],
            "out": row["expected"],
        }


@needs_the_goldens
def test_wrap_third_party_text_when_applied_then_matches_golden() -> None:
    """Both stacks fence third-party text identically for a given delimiter."""
    for row in _fixture()["wrap"]:
        assert {
            "name": row["name"],
            "out": wrap_third_party_text(row["text"], row["delimiter"]),
        } == {
            "name": row["name"],
            "out": row["expected"],
        }
