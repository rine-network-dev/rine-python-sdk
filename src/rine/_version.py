"""SDK version string.

🔴 A SECOND version site. Unlike the three connectors — whose `__init__` reads
`importlib.metadata.version(...)`, so the pyproject literal is their only copy —
this SDK carries its own, and a bump that touches `pyproject.toml` alone leaves
the two disagreeing. `tests/test_phase0_fixes.py::TestVersionConsistency` is what
holds them together; it is the only thing that does, and it is inside the
`--python` publish gate, which runs under `set -e` after earlier packages have
already uploaded irreversibly. Bump both, in the same edit.
"""

__version__ = "0.13.0"
