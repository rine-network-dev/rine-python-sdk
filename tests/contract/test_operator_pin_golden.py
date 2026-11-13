"""The Python half of the operator pin parity gate.

The id and full-key comparison that decides operator authority is replayed from one
hand-written fixture shared with ``rine-core/test/operator-pin-golden.test.ts``. Neither
stack regenerates it, so a stack cannot move its own goalposts. It lives under
``tests/contract`` because ``ci.sh`` stage 4 runs that directory and nothing else of this
package.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rine import OperatorPin, looks_like_seat, pin_matches_key, pin_matches_sender
from rine._utils import from_base64url

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "rine-core" / "test" / "fixtures"
FIXTURE = FIXTURE_DIR / "operator-pin.json"

needs_the_goldens = pytest.mark.skipif(
    not FIXTURE_DIR.is_dir(),
    reason="the golden vectors are not in this checkout (published sdist or mirror)",
)


def _fixture() -> dict[str, Any]:
    if not FIXTURE.exists():
        raise AssertionError(
            f"operator pin cases missing at {FIXTURE} — restore them (git checkout)."
        )
    return json.loads(FIXTURE.read_text())


def _cases() -> list[dict[str, Any]]:
    return _fixture()["cases"]


def _pin(case: dict[str, Any]) -> OperatorPin:
    return OperatorPin(case["pin_agent_id"], case["pin_signing_key"], case.get("pin_handle"))


@needs_the_goldens
def test_pin_when_cases_are_loaded_then_both_outcomes_are_covered() -> None:
    """Pin when cases are loaded then both outcomes are covered."""
    cases = _cases()
    assert len(cases) > 10
    assert any(c["matches_sender"] and c["matches_key"] for c in cases)
    assert any(not c["matches_sender"] for c in cases)
    assert any(not c["matches_key"] for c in cases)


@needs_the_goldens
def test_pin_matches_sender_when_compared_to_golden_then_agrees() -> None:
    """Pin matches sender when compared to golden then agrees."""
    for case in _cases():
        got = pin_matches_sender(_pin(case), case["from_agent_id"])
        assert (case["name"], got) == (case["name"], case["matches_sender"])


@needs_the_goldens
def test_pin_matches_key_when_compared_to_golden_then_agrees() -> None:
    """Pin matches key when compared to golden then agrees."""
    for case in _cases():
        key = None if case["verifying_key"] is None else from_base64url(case["verifying_key"])
        got = pin_matches_key(_pin(case), key)
        assert (case["name"], got) == (case["name"], case["matches_key"])


@needs_the_goldens
def test_pin_when_the_handle_varies_then_authority_still_follows_the_golden() -> None:
    """Pin when the handle varies then authority still follows the golden."""
    for case in _cases():
        key = None if case["verifying_key"] is None else from_base64url(case["verifying_key"])
        handles = (None, case["from_agent_id"], "ops@acme.rine.network", case.get("pin_handle"))
        for handle in handles:
            pin = OperatorPin(case["pin_agent_id"], case["pin_signing_key"], handle)
            got = (pin_matches_sender(pin, case["from_agent_id"]), pin_matches_key(pin, key))
            assert (case["name"], got) == (
                case["name"],
                (case["matches_sender"], case["matches_key"]),
            )


@needs_the_goldens
def test_looks_like_seat_when_compared_to_golden_then_agrees() -> None:
    """Looks like seat when compared to golden then agrees."""
    table = _fixture()["seat_lookalike"]
    assert any(c["looks_like_seat"] for c in table)
    assert any(not c["looks_like_seat"] for c in table)
    base = _cases()[0]
    for case in table:
        pin = (
            None
            if case["pin"] is None
            else OperatorPin(
                base["pin_agent_id"], base["pin_signing_key"], case["pin"].get("handle")
            )
        )
        got = looks_like_seat(pin, case["handle"])
        assert (case["name"], got) == (case["name"], case["looks_like_seat"])
