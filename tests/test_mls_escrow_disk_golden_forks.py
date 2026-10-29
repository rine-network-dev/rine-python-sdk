"""The queued-range sidecar that names forks, pinned to the golden bytes the TypeScript SDK also reads.

The fixtures and the skip rule are those of ``test_mls_escrow_disk_golden``; this file adds the
``forkSidecars`` rows, so the key order, compact JSON and ascending epochs of ``fps`` are held
by this stack's own suite as well as the TypeScript one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rine._mls.escrow_queued import lost_epochs, recorded_forks, write_queued
from tests.test_mls_escrow_disk_golden import AGENT, GOLDEN, GROUP, MANIFEST, _install, _names

FORK_SIDECARS: list[dict[str, Any]] = MANIFEST["forkSidecars"]
FORKS_DIR = GOLDEN / "backlog-forks"


def _forks(entry: dict[str, Any]) -> dict[int, bytes]:
    return {int(epoch): bytes.fromhex(fp) for epoch, fp in entry["fps"].items()}


def test_manifest_when_read_then_it_names_exactly_the_golden_fork_backlog_files() -> None:
    named = [name for entry in FORK_SIDECARS for name in (entry["snapshot"], entry["sidecar"])]

    assert sorted(named) == _names(FORKS_DIR)


def test_recorded_forks_when_the_golden_is_installed_then_it_names_the_manifest_forks_and_range(
    tmp_path: Path,
) -> None:
    _install(FORKS_DIR, tmp_path)

    for entry in FORK_SIDECARS:
        snapshot = str(tmp_path / entry["snapshot"])
        assert recorded_forks(snapshot, entry["epoch"]) == _forks(entry)
        epochs = lost_epochs(str(tmp_path), AGENT, GROUP, snapshot, entry["epoch"])
        assert list(epochs) == list(range(entry["firstLost"], entry["lastLost"] + 1))


def test_write_queued_when_the_fork_golden_is_written_back_then_name_and_bytes_are_identical(
    tmp_path: Path,
) -> None:
    for entry in FORK_SIDECARS:
        write_queued(
            str(tmp_path / entry["snapshot"]),
            entry["epoch"],
            entry["queued"],
            entry["dropped"],
            _forks(entry),
        )

        written = (tmp_path / entry["sidecar"]).read_bytes()
        assert written == (FORKS_DIR / entry["sidecar"]).read_bytes()
