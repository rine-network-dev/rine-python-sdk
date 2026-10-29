"""The org-root known-answer vectors, read from the file ``rine-core`` owns.

One fixture serves the TypeScript and Python stacks, so it is read and never
restated. A mirror or sdist without the ``rine-core`` checkout skips the replay;
a checkout that has the fixtures directory but not the file fails it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parents[3] / "rine-core" / "test" / "fixtures"
FIXTURE = FIXTURES / "org-root-v1.json"


def load_kat() -> dict[str, Any]:
    """Return the parsed vectors, skipping when the sibling package is absent."""
    if not FIXTURE.exists():
        if FIXTURES.is_dir():
            pytest.fail(f"fixtures directory present but {FIXTURE.name} is missing")
        pytest.skip(f"org-root vectors absent (mirror or sdist?): {FIXTURE}")
    return json.loads(FIXTURE.read_text())  # type: ignore[no-any-return]
