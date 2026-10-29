"""The escrow files on disk, pinned to golden bytes shared with the TypeScript SDK.

``rine-core`` owns the directory: every gap marker reason, a fork-less and a fork-named
marker, a second group, the files that sit beside markers without being one, the
queued-range sidecar beside a parked snapshot and a corrupt one. Each golden
must parse to what ``manifest.json`` says, and writing it back must reproduce the golden's
name and bytes, so a drift in either stack's writer or reader shows in that stack's own
suite. A checkout without ``rine-core`` (a mirror or sdist) skips; a ``rine-core`` that has
the fixtures directory but not these goldens fails.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_gap import DrainGap, EscrowLoss, write_gap
from rine._mls.escrow_gap_list import list_gap_markers
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_queued import lost_epochs, write_queued
from rine._mls.escrow_store import pending_dir
from tests.test_mls_escrow_sweep import NO_FORK_FP

FIXTURES = Path(__file__).resolve().parents[2] / "rine-core" / "test" / "fixtures"
GOLDEN = FIXTURES / "escrow-disk"
AGENT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
GROUP = "c3d4e5f6-a7b8-9012-cdef-123456789012"

if not FIXTURES.is_dir():
    pytest.skip(f"golden fixtures are not in this checkout: {FIXTURES}", allow_module_level=True)
if not GOLDEN.is_dir():
    pytest.fail(f"fixtures directory present but {GOLDEN.name} is missing", pytrace=False)

MANIFEST: dict[str, Any] = json.loads((GOLDEN / "manifest.json").read_text())
MARKERS: list[dict[str, Any]] = MANIFEST["markers"]
SIDECARS: list[dict[str, Any]] = MANIFEST["sidecars"]
STRAY: list[str] = MANIFEST["stray"]
OTHER_GROUP: dict[str, Any] = MANIFEST["otherGroup"]


def _names(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.iterdir())


def _install(source: Path, target: Path) -> None:
    shutil.copytree(source, target, dirs_exist_ok=True)


def test_manifest_when_read_then_it_names_exactly_the_golden_marker_files() -> None:
    assert [m["name"] for m in MARKERS] == _names(GOLDEN / "pending")


def test_list_gap_markers_when_the_goldens_are_installed_then_each_parses_as_the_manifest_says(
    tmp_path: Path,
) -> None:
    _install(GOLDEN / "pending", Path(pending_dir(str(tmp_path), AGENT, GROUP)))

    listed = [
        (m.agent_id, m.group_id, m.epoch, m.fork, m.reason.value)
        for m in list_gap_markers(str(tmp_path), AGENT)
    ]

    assert listed == [(AGENT, GROUP, m["epoch"], m.get("fork"), m["reason"]) for m in MARKERS]


def _install_stray(root: Path) -> Path:
    group = Path(pending_dir(str(root), AGENT, GROUP))
    _install(GOLDEN / "pending", group)
    _install(GOLDEN / "stray", group)
    return group


def _row(marker: dict[str, Any], group: str) -> tuple[str, int, str | None, str]:
    return (group, marker["epoch"], marker.get("fork"), marker["reason"])


def test_manifest_when_read_then_it_names_exactly_the_stray_files_and_every_gap_reason() -> None:
    assert sorted(STRAY) == _names(GOLDEN / "stray")
    native = {m.value for m in vars(EscrowGapReason).values() if isinstance(m, EscrowGapReason)}

    assert {m["reason"] for m in MARKERS} == native | {loss.value for loss in EscrowLoss}


def test_list_gap_markers_when_strays_and_a_second_group_are_installed_then_only_markers_list(
    tmp_path: Path,
) -> None:
    _install_stray(tmp_path)
    _install(GOLDEN / "pending-other", Path(pending_dir(str(tmp_path), AGENT, OTHER_GROUP["id"])))

    listed = [
        (m.group_id, m.epoch, m.fork, m.reason.value)
        for m in list_gap_markers(str(tmp_path), AGENT)
    ]

    assert listed == [
        *(_row(m, OTHER_GROUP["id"]) for m in OTHER_GROUP["markers"]),
        *(_row(m, GROUP) for m in MARKERS),
    ]


def test_read_gap_when_the_goldens_and_strays_are_installed_then_each_epoch_reads_its_reason(
    tmp_path: Path,
) -> None:
    _install_stray(tmp_path)

    for marker in MARKERS:
        fp = bytes.fromhex(marker["fork"]) if "fork" in marker else NO_FORK_FP
        assert read_gap(str(tmp_path), AGENT, GROUP, marker["epoch"], fp).value == marker["reason"]  # type: ignore[union-attr]
    for epoch in (12, 13, 14, 15, 16, 1234567890123456):
        assert read_gap(str(tmp_path), AGENT, GROUP, epoch, NO_FORK_FP) is None


def test_read_gap_when_the_goldens_are_installed_then_a_fork_reads_only_its_own_and_fork_less_markers(
    tmp_path: Path,
) -> None:
    _install_stray(tmp_path)
    foreign = bytes.fromhex("0c" * 16)

    for marker in MARKERS:
        read = read_gap(str(tmp_path), AGENT, GROUP, marker["epoch"], foreign)
        if "fork" in marker:
            assert read is None
            assert read_gap(str(tmp_path), AGENT, GROUP, marker["epoch"], NO_FORK_FP) is None
        else:
            assert read is not None and read.value == marker["reason"]


def test_list_gap_markers_when_links_pipes_and_misnamed_dirs_are_planted_then_none_is_listed(
    tmp_path: Path,
) -> None:
    group = _install_stray(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("refused")
    (group / "21.gap").symlink_to(outside)
    os.mkfifo(group / "22.gap")
    (group / "23.gap").write_text("refused".ljust(4096, "x"))
    real = tmp_path / "real"
    real.mkdir()
    (real / "3.gap").write_text("refused")
    (group.parent / OTHER_GROUP["id"]).symlink_to(real, target_is_directory=True)
    for name in ("ABCDEFAB-0000-4000-8000-000000000000", "not-a-group"):
        _install(GOLDEN / "pending-other", group.parent / name)

    listed = [(m.group_id, m.epoch) for m in list_gap_markers(str(tmp_path), AGENT)]

    assert listed == [(GROUP, m["epoch"]) for m in MARKERS]


def test_write_gap_when_each_golden_marker_is_written_back_then_name_and_bytes_are_identical(
    tmp_path: Path,
) -> None:
    installed = Path(pending_dir(str(tmp_path), AGENT, GROUP))
    _install(GOLDEN / "pending", installed)
    markers = list_gap_markers(str(tmp_path), AGENT)
    other = tmp_path / "rewritten"

    for marker in markers:
        fork = None if marker.fork is None else bytes.fromhex(marker.fork)
        write_gap(str(other), AGENT, GROUP, DrainGap(marker.epoch, marker.reason), fork)

    written = Path(pending_dir(str(other), AGENT, GROUP))
    assert _names(written) == _names(GOLDEN / "pending")
    for name in _names(written):
        assert (written / name).read_bytes() == (GOLDEN / "pending" / name).read_bytes()


def test_manifest_when_read_then_it_names_exactly_the_golden_backlog_files() -> None:
    named = [name for entry in SIDECARS for name in (entry["snapshot"], entry["sidecar"])]

    assert sorted(named) == _names(GOLDEN / "backlog")


def test_lost_epochs_when_the_golden_sidecars_are_installed_then_each_names_the_manifest_range(
    tmp_path: Path,
) -> None:
    _install(GOLDEN / "backlog", tmp_path)

    for entry in SIDECARS:
        epochs = lost_epochs(
            str(tmp_path), AGENT, GROUP, str(tmp_path / entry["snapshot"]), entry["epoch"]
        )
        assert list(epochs) == list(range(entry["firstLost"], entry["lastLost"] + 1))


def test_write_queued_when_each_readable_golden_is_written_back_then_name_and_bytes_are_identical(
    tmp_path: Path,
) -> None:
    for entry in (e for e in SIDECARS if not e.get("corrupt")):
        write_queued(
            str(tmp_path / entry["snapshot"]), entry["epoch"], entry["queued"], entry["dropped"]
        )

        written = (tmp_path / entry["sidecar"]).read_bytes()
        assert written == (GOLDEN / "backlog" / entry["sidecar"]).read_bytes()
