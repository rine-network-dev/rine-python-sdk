"""Read ``rine-core``'s TypeScript source, for the tests that bind a value across both stacks.

The two deployables cannot import each other, so a cross-stack constant is held equal by a
test reading the twin's own source. Outside the monorepo the twin is absent and the test skips.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_CORE_SRC = pathlib.Path(__file__).resolve().parents[2] / "rine-core" / "src"


def core_source(rel_path: str) -> str:
    """Return the text of ``rine-core/src/<rel_path>``, or skip when it is not present."""
    twin = _CORE_SRC / rel_path
    if not twin.is_file():
        pytest.skip("rine-core source not present — SDK tested outside the monorepo")
    return twin.read_text()


def ts_number(source: str, name: str) -> int:
    """One ``export const <name> = …;`` from the twin, as an integer.

    Accepts a plain literal or a product of them, which is how both stacks spell
    a byte bound. Anything else is a source shape this helper has no reading of,
    and it says so rather than answering ``0``.
    """
    match = re.search(rf"\b{name} = ([\d ]+(?:\* *[\d ]+)*);", source)
    assert match, f"no readable {name} literal in the twin's source"
    product = 1
    for factor in match.group(1).split("*"):
        product *= int(factor.strip())
    return product


def ts_text(source: str, anchor: str) -> str:
    """The string literals of the TS expression that follows ``anchor``, joined.

    Reads from ``anchor`` to the next ``;`` or ``)`` that closes the statement
    and concatenates every backtick or double-quoted literal in it, which is
    how a twin spells a sentence it wraps over several lines. ``${name}``
    holes stay in the text for the caller to bind.
    """
    start = source.index(anchor) + len(anchor)
    tail = source[start:]
    end = re.search(r";\s*\n|\n\s*\);?\s*\n", tail)
    expression = tail[: end.start()] if end else tail
    return "".join(
        a or b for a, b in re.findall(r'`((?:[^`\\]|\\.)*)`|"((?:[^"\\]|\\.)*)"', expression)
    )
