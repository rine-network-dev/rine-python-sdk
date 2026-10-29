"""The published dependency pins that are correctness constraints, not caution.

Most version bounds in ``pyproject.toml`` are ordinary caution and belong to
whoever next edits them. One is not: ``rine-mls`` carries an upper bound because
this SDK and the Node stack (``@rine-network/mls``, which ``rewrite-file-deps.py``
publishes as ``^0.2.0``) read and write the *same* on-disk group state, and our
own docs bless a shared config directory between a Python agent and a Node one.
The two runtimes have to agree on that encoding byte for byte, so an unbounded
floor would let Python pick up a ``0.3.0`` that changed it while Node refuses
that release — a corrupt shared state with no error on either side.

That reasoning is eight lines of comment in ``pyproject.toml`` and, until this
file existed, was enforced by nothing: neither ``ci.sh`` nor the ``--python``
publish gate reads the pin (for ``rine-sdk`` that gate is pytest alone), so a
hand-edit widening the ceiling back had nothing to fail. These tests are what
makes the rationale a rule. **Widening the bound is a deliberate act**: when the
Node pin moves to a new minor series, move both together and update this test in
the same commit.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _split_requirement(requirement: str) -> tuple[str, str]:
    """A requirement string as (distribution name, the version clauses after it)."""
    cut = min(
        (requirement.index(c) for c in "<>=!~" if c in requirement), default=len(requirement)
    )
    return requirement[:cut].split("[")[0].strip(), requirement[cut:]


def _bounds(name: str) -> dict[str, str]:
    """Map each comparison operator pinning *name* to the version it bounds by.

    Read from ``pyproject.toml`` itself, not from installed metadata: the pin as
    PUBLISHED is what the test is about, and an already-resolved environment
    satisfies a bound it no longer declares.
    """
    data = tomllib.loads(_PYPROJECT.read_text())
    matches = [
        clauses
        for dep in data["project"]["dependencies"]
        for dep_name, clauses in [_split_requirement(dep)]
        if dep_name == name
    ]
    assert len(matches) == 1, f"expected exactly one {name} requirement, got {matches}"
    out: dict[str, str] = {}
    for clause in matches[0].split(","):
        clause = clause.strip()
        for op in (">=", "<=", "==", "!=", "~=", ">", "<"):
            if clause.startswith(op):
                out[op] = clause[len(op) :].strip()
                break
        else:  # pragma: no cover — a malformed pin should fail loudly, not silently
            pytest.fail(f"unparsable version clause {clause!r} on {name}")
    return out


class TestRineMlsStaysInOneMinorSeries:
    def test_the_pin_has_both_a_floor_and_a_ceiling(self):
        bounds = _bounds("rine-mls")
        assert ">=" in bounds, "rine-mls lost its version floor — see pyproject.toml's comment"
        assert "<" in bounds, (
            "rine-mls lost its upper bound. It is not caution: Python and Node share the "
            "on-disk group-state encoding, and only matching bounds keep them on one "
            "encoding. Widen it only together with @rine-network/mls."
        )

    def test_the_ceiling_is_the_minor_after_the_floor(self):
        # A ceiling that has drifted away from the floor no longer says "one minor
        # series" — it says "some range", which is the claim the comment refuses.
        # Missing bounds are the sibling test's business, so they are reported here
        # rather than raising a bare KeyError out of a subscript.
        bounds = _bounds("rine-mls")
        floor, ceiling = bounds.get(">="), bounds.get("<")
        assert floor and ceiling, f"rine-mls needs both bounds to be compared; has {bounds}"
        major, minor, *_ = (int(part) for part in floor.split("."))
        assert ceiling == f"{major}.{minor + 1}.0", (
            f"floor {floor} and ceiling {ceiling} do not describe one minor series; "
            "the shared on-disk encoding is only guaranteed within one"
        )
