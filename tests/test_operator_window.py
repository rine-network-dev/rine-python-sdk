"""The operator window and the future skew are exclusive limits, pinned at their exact instants."""

from __future__ import annotations

from datetime import timedelta

import pytest

from rine import (
    OPERATOR_FUTURE_SKEW_MS,
    OPERATOR_WINDOW_MS,
    OperatorVerdict,
    classify_operator_row,
)
from tests.operator_world import OperatorWorld, instant

OPERATOR_NEW = OperatorVerdict("operator", "new")


@pytest.fixture
def w(tmp_config_dir: str) -> OperatorWorld:
    """W."""
    return OperatorWorld(tmp_config_dir)


class TestExactInstants:
    """Exact instants."""

    def test_classify_when_issued_exactly_at_the_future_skew_then_operator(self, w):
        """Classify when issued exactly at the future skew then operator."""
        row = w.console_row(issued_at=instant(timedelta(milliseconds=OPERATOR_FUTURE_SKEW_MS)))
        assert classify_operator_row(w.context(), row) == OPERATOR_NEW

    def test_classify_when_issued_one_millisecond_past_the_future_skew_then_other(self, w):
        """Classify when issued one millisecond past the future skew then other."""
        skew = timedelta(milliseconds=OPERATOR_FUTURE_SKEW_MS + 1)
        row = w.console_row(issued_at=instant(skew))
        assert classify_operator_row(w.context(), row) == OperatorVerdict("other", "future")

    def test_classify_when_issued_exactly_at_the_window_then_operator(self, w):
        """Classify when issued exactly at the window then operator."""
        row = w.console_row(issued_at=instant(-timedelta(milliseconds=OPERATOR_WINDOW_MS)))
        assert classify_operator_row(w.context(), row) == OPERATOR_NEW

    def test_classify_when_issued_one_millisecond_past_the_window_then_operator_history(self, w):
        """Classify when issued one millisecond past the window then operator history."""
        age = timedelta(milliseconds=OPERATOR_WINDOW_MS + 1)
        row = w.console_row(issued_at=instant(-age))
        assert classify_operator_row(w.context(), row) == OperatorVerdict(
            "operator_history", "expired"
        )
