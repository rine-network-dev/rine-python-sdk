"""The pending-escrow store: sealed bytes on disk, and the head a sender reads.

The store is the crash-safe half of the escrow drain: the native
group hands its exports over exactly once, so the sealed bytes have to land here
before anything else touches them, and the newest drained epoch's fingerprint is
remembered beside them because the group has no accessor for it.

The TypeScript twin is ``rine-core/test/mls-escrow-pending.test.ts``.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from rine._config import mls_store_dir
from rine._mls.escrow_head import EscrowHead, read_head, write_head
from rine._mls.escrow_store import (
    PendingEscrow,
    delete_pending,
    list_pending,
    write_pending,
)
from rine.errors import CryptoError

GROUP_A = "11111111-2222-3333-4444-555555555555"
GROUP_B = "66666666-7777-8888-9999-aaaaaaaaaaaa"
FP_A = bytes(range(16))
FP_B = bytes(range(16, 32))


def _pending(group_id: str, epoch: int, fp: bytes, sealed: bytes) -> PendingEscrow:
    """One sealed escrow keyed by its slot."""
    return PendingEscrow(group_id=group_id, epoch=epoch, fp=fp, sealed=sealed)


def _pending_path(tmp_config_dir: str, agent_id: str, group_id: str, epoch: int, fp: bytes) -> str:
    """The on-disk path of one pending escrow, built by hand from the store root."""
    return os.path.join(
        mls_store_dir(tmp_config_dir, agent_id),
        "escrow-pending",
        group_id,
        f"{epoch}-{fp.hex()}.bin",
    )


def _head_path(tmp_config_dir: str, agent_id: str, group_id: str) -> str:
    """The on-disk path of one group's head record, built by hand from the store root."""
    return os.path.join(mls_store_dir(tmp_config_dir, agent_id), "escrow-head", f"{group_id}.json")


def _write_raw_head(tmp_config_dir: str, agent_id: str, raw: str) -> None:
    """Write a head file by hand, bypassing the store's own writer."""
    path = _head_path(tmp_config_dir, agent_id, GROUP_A)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w") as handle:
        handle.write(raw)


def test_write_pending_when_two_groups_and_epochs_then_lists_sorted(
    tmp_config_dir: str, agent_id: str
) -> None:
    """Every slot round-trips its group, epoch, fp and sealed bytes, sorted by (group, epoch)."""
    for row in (
        _pending(GROUP_B, 2, FP_B, b"b2"),
        _pending(GROUP_A, 5, FP_A, b"a5"),
        _pending(GROUP_B, 1, FP_B, b"b1"),
        _pending(GROUP_A, 3, FP_A, b"a3"),
    ):
        write_pending(tmp_config_dir, agent_id, row)

    listed = list_pending(tmp_config_dir, agent_id)

    assert [(p.group_id, p.epoch, p.fp, p.sealed) for p in listed] == [
        (GROUP_A, 3, FP_A, b"a3"),
        (GROUP_A, 5, FP_A, b"a5"),
        (GROUP_B, 1, FP_B, b"b1"),
        (GROUP_B, 2, FP_B, b"b2"),
    ]


def test_write_pending_when_same_slot_written_twice_then_keeps_first_bytes(
    tmp_config_dir: str, agent_id: str
) -> None:
    """The first sealing of a slot wins; a second write leaves the bytes alone."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, FP_A, b"first"))
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, FP_A, b"second"))

    assert [p.sealed for p in list_pending(tmp_config_dir, agent_id)] == [b"first"]


def test_write_pending_when_written_then_file_is_0600_and_group_dir_is_0700(
    tmp_config_dir: str, agent_id: str
) -> None:
    """The sealed bytes are private to the agent, and so is the dir holding them."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, FP_A, b"sealed"))
    path = _pending_path(tmp_config_dir, agent_id, GROUP_A, 1, FP_A)

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


def test_list_pending_when_stray_entries_present_then_ignores_them(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A temp file, a badly named .bin and a non-uuid dir are all skipped."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, FP_A, b"sealed"))
    directory = os.path.dirname(_pending_path(tmp_config_dir, agent_id, GROUP_A, 1, FP_A))
    for name in ("x.tmp", "not-a-slot.bin", "1-ABCDEF.bin"):
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(b"junk")
    stray_dir = os.path.join(os.path.dirname(directory), "not-a-uuid")
    os.makedirs(stray_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(stray_dir, f"1-{FP_A.hex()}.bin"), "wb") as handle:
        handle.write(b"junk")

    assert [p.sealed for p in list_pending(tmp_config_dir, agent_id)] == [b"sealed"]


def test_list_pending_when_epoch_is_not_canonical_then_ignores_it(
    tmp_config_dir: str, agent_id: str
) -> None:
    """An epoch with a leading zero or over 15 digits is not a slot name, as in the TS twin."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 0, FP_A, b"zero"))
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 10**14, FP_B, b"widest"))
    directory = os.path.dirname(_pending_path(tmp_config_dir, agent_id, GROUP_A, 0, FP_A))
    for epoch in ("01", "00", f"{10**15}"):
        with open(os.path.join(directory, f"{epoch}-{FP_B.hex()}.bin"), "wb") as handle:
            handle.write(b"junk")

    listed = list_pending(tmp_config_dir, agent_id)

    assert [(p.epoch, p.sealed) for p in listed] == [(0, b"zero"), (10**14, b"widest")]


def test_list_pending_when_group_id_given_then_filters(tmp_config_dir: str, agent_id: str) -> None:
    """A group id limits the listing to that group's slots."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, FP_A, b"a"))
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_B, 1, FP_B, b"b"))

    assert [p.group_id for p in list_pending(tmp_config_dir, agent_id, GROUP_B)] == [GROUP_B]


def test_list_pending_when_store_missing_then_returns_empty(
    tmp_config_dir: str, agent_id: str
) -> None:
    """Nothing has ever been written, so there is nothing to list."""
    assert list_pending(tmp_config_dir, agent_id) == []


def test_delete_pending_when_called_twice_then_second_does_not_raise(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A delete drops the file, and a repeat delete is a no-op rather than an error."""
    row = _pending(GROUP_A, 1, FP_A, b"sealed")
    write_pending(tmp_config_dir, agent_id, row)
    path = _pending_path(tmp_config_dir, agent_id, GROUP_A, 1, FP_A)

    delete_pending(tmp_config_dir, agent_id, row)
    assert not os.path.exists(path)

    delete_pending(tmp_config_dir, agent_id, row)


def test_write_pending_when_written_then_file_name_is_epoch_fp_hex_bin(
    tmp_config_dir: str, agent_id: str
) -> None:
    """The file is exactly ``<epoch>-<fp hex>.bin`` under the group's pending dir."""
    write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 7, FP_A, b"sealed"))
    expected = _pending_path(tmp_config_dir, agent_id, GROUP_A, 7, FP_A)

    assert os.path.isfile(expected)
    with open(expected, "rb") as handle:
        assert handle.read() == b"sealed"


def test_write_head_when_read_back_then_round_trips(tmp_config_dir: str, agent_id: str) -> None:
    """The head round-trips, and on disk it is the documented two-key JSON object."""
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=4, fp=FP_A))

    with open(_head_path(tmp_config_dir, agent_id, GROUP_A)) as handle:
        assert json.load(handle) == {"epoch": 4, "fp": FP_A.hex()}
    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=4, fp=FP_A)


def test_write_head_when_lower_epoch_then_ignored(tmp_config_dir: str, agent_id: str) -> None:
    """A stale drain finishing late must not rewind what a sender reads."""
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=5, fp=FP_A))
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=4, fp=FP_B))

    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=5, fp=FP_A)


def test_write_head_when_live_and_a_lower_epoch_then_the_head_moves_back(
    tmp_config_dir: str, agent_id: str
) -> None:
    """The drain proves the live pair, so the head may follow a fork below it."""
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=5, fp=FP_A))
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=4, fp=FP_B), live=True)

    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=4, fp=FP_B)


def test_write_head_when_equal_or_higher_epoch_then_replaces(
    tmp_config_dir: str, agent_id: str
) -> None:
    """An equal epoch still moves the fp, and a higher epoch always wins."""
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=5, fp=FP_A))
    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=5, fp=FP_B))
    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=5, fp=FP_B)

    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=6, fp=FP_A))
    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=6, fp=FP_A)


CORRUPT_HEADS = {
    "corrupt_json": "{not json",
    "json_list": "[1, 2]",
    "short_fp": json.dumps({"epoch": 1, "fp": "ab"}),
    "uppercase_fp": json.dumps({"epoch": 1, "fp": FP_A.hex().upper()}),
    "negative_epoch": json.dumps({"epoch": -1, "fp": FP_A.hex()}),
    "bool_epoch": json.dumps({"epoch": True, "fp": FP_A.hex()}),
    "string_epoch": json.dumps({"epoch": "1", "fp": FP_A.hex()}),
}


@pytest.mark.parametrize("raw", CORRUPT_HEADS.values(), ids=CORRUPT_HEADS.keys())
def test_read_head_when_the_file_is_malformed_then_returns_none(
    tmp_config_dir: str, agent_id: str, raw: str
) -> None:
    """Anything that is not the documented shape reads as absent, never as a head."""
    _write_raw_head(tmp_config_dir, agent_id, raw)

    assert read_head(tmp_config_dir, agent_id, GROUP_A) is None


def test_read_head_when_the_file_is_missing_then_returns_none(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A group that has never drained has no head."""
    assert read_head(tmp_config_dir, agent_id, GROUP_A) is None


def test_write_head_when_the_existing_head_is_corrupt_then_replaces_it(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A corrupt head is replaced rather than blocking the write forever."""
    _write_raw_head(tmp_config_dir, agent_id, "{not json")

    write_head(tmp_config_dir, agent_id, GROUP_A, EscrowHead(epoch=2, fp=FP_A))

    assert read_head(tmp_config_dir, agent_id, GROUP_A) == EscrowHead(epoch=2, fp=FP_A)


def test_write_pending_when_group_id_is_invalid_then_raises_crypto_error(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A group id that is not a canonical UUID never reaches the filesystem."""
    with pytest.raises(CryptoError):
        write_pending(tmp_config_dir, agent_id, _pending("not-a-uuid", 1, FP_A, b"sealed"))


def test_write_head_when_group_id_is_invalid_then_raises_crypto_error(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A group id that is not a canonical UUID never reaches the filesystem."""
    with pytest.raises(CryptoError):
        write_head(tmp_config_dir, agent_id, "not-a-uuid", EscrowHead(epoch=1, fp=FP_A))


def test_write_pending_when_fp_is_15_bytes_then_raises_and_writes_nothing(
    tmp_config_dir: str, agent_id: str
) -> None:
    """A fingerprint that is not 16 bytes is refused before any file is created."""
    with pytest.raises(CryptoError):
        write_pending(tmp_config_dir, agent_id, _pending(GROUP_A, 1, bytes(15), b"sealed"))

    assert list_pending(tmp_config_dir, agent_id) == []
