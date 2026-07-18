"""Golden-envelope loader for the SDK-side contract tests.

Loads fixtures from ``Path(__file__).parent / "fixtures"`` — portable, ships in
the sdist (REQ-C1/C7), never reaches up to the monorepo ``../tests``. Skips
cleanly if the dir/file is absent so a standalone-sdist consumer running the
suite in isolation is not broken (REQ-C4); fixtures always ship, so in-repo this
skip never fires.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load(name: str) -> dict[str, Any]:
    """Return the ``{endpoint, scenario, status, body}`` envelope for ``name``."""
    if not FIXTURES_DIR.is_dir():
        pytest.skip(f"contract fixtures dir absent (standalone sdist?): {FIXTURES_DIR}")
    path = FIXTURES_DIR / f"{name}.json"
    if not path.exists():
        pytest.skip(f"contract fixture missing: {path.name}")
    return json.loads(path.read_text())
