"""The neutraliser sees every format character this Python knows."""

from __future__ import annotations

import sys
import unicodedata

import pytest

from rine import NEUTRALISED_NOTICE, OPERATOR_HISTORY_NOTICE, neutralise_notices


def _format_characters() -> list[str]:
    return [
        char for char in map(chr, range(sys.maxunicode + 1)) if unicodedata.category(char) == "Cf"
    ]


@pytest.mark.parametrize("hidden", _format_characters(), ids=lambda c: f"U+{ord(c):04X}")
def test_neutralise_notices_when_a_format_character_sits_inside_a_word_then_it_is_replaced(
    hidden: str,
) -> None:
    """A format character hidden inside a notice does not save it from being replaced."""
    disguised = OPERATOR_HISTORY_NOTICE.replace("operator", f"oper{hidden}ator", 1)
    assert neutralise_notices(disguised) == NEUTRALISED_NOTICE
