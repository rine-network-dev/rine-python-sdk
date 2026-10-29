"""The host-local marker of the last key generation settled, and the store probe."""

from __future__ import annotations

import json
import os
from typing import Any

from rine._config import keys_dir, mls_store_dir
from rine._mls.rotation_marker import RotationMarker, read_rotation_marker, write_rotation_marker
from rine._mls.store_probe import holds_mls_store
from tests.rotation_world import A


def _marker_path(config_dir: str) -> str:
    return os.path.join(keys_dir(config_dir, A), "mls-rotation.json")


def _write_raw(config_dir: str, text: str) -> None:
    os.makedirs(keys_dir(config_dir, A), exist_ok=True)
    with open(_marker_path(config_dir), "w", encoding="utf-8") as f:
        f.write(text)


def test_read_rotation_marker_when_no_file_exists_then_both_generations_are_zero(
    tmp_path: Any,
) -> None:
    """A generation-0 agent is never behind."""
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(0, 0)


def test_write_rotation_marker_when_written_then_it_reads_back_as_compact_json(
    tmp_path: Any,
) -> None:
    """The file is the one both stacks share: compact JSON of the two fields."""
    config = str(tmp_path)
    os.makedirs(keys_dir(config, A), exist_ok=True)
    write_rotation_marker(config, A, RotationMarker(key_packages=3, seats=2))
    assert read_rotation_marker(config, A) == RotationMarker(3, 2)
    with open(_marker_path(config), encoding="utf-8") as f:
        assert f.read() == '{"key_packages":3,"seats":2}'


def test_read_rotation_marker_when_the_file_is_not_json_then_it_reads_as_zero(
    tmp_path: Any,
) -> None:
    """A torn or foreign file is treated as nothing settled."""
    _write_raw(str(tmp_path), "{not json")
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(0, 0)


def test_read_rotation_marker_when_the_file_is_not_an_object_then_it_reads_as_zero(
    tmp_path: Any,
) -> None:
    """A JSON value that is not an object carries no generations."""
    _write_raw(str(tmp_path), "[1, 2]")
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(0, 0)


def test_read_rotation_marker_when_one_field_is_malformed_then_the_other_survives(
    tmp_path: Any,
) -> None:
    """Each field is read on its own, and only a non-negative integer counts."""
    _write_raw(str(tmp_path), json.dumps({"key_packages": 4, "seats": "2"}))
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(4, 0)
    _write_raw(str(tmp_path), json.dumps({"key_packages": -1, "seats": 5}))
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(0, 5)
    _write_raw(str(tmp_path), json.dumps({"key_packages": True, "seats": 1.5}))
    assert read_rotation_marker(str(tmp_path), A) == RotationMarker(0, 0)


def test_holds_mls_store_when_the_directory_exists_then_it_is_true(tmp_path: Any) -> None:
    """The store root being a directory is the whole answer."""
    config = str(tmp_path)
    os.makedirs(mls_store_dir(config, A))
    assert holds_mls_store(config, A) is True


def test_holds_mls_store_when_nothing_exists_then_it_is_false(tmp_path: Any) -> None:
    """A host that never held the agent's MLS state holds no store."""
    assert holds_mls_store(str(tmp_path), A) is False


def test_holds_mls_store_when_the_path_is_a_file_then_it_is_false(tmp_path: Any) -> None:
    """A file at the store path is not a store."""
    config = str(tmp_path)
    path = mls_store_dir(config, A)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("x")
    assert holds_mls_store(config, A) is False


def test_holds_mls_store_when_a_parent_is_a_file_then_it_is_false(tmp_path: Any) -> None:
    """A path under a file is absent, not an error."""
    config = str(tmp_path)
    path = mls_store_dir(config, A)
    parent = os.path.dirname(path)
    os.makedirs(os.path.dirname(parent), exist_ok=True)
    with open(parent, "w", encoding="utf-8") as f:
        f.write("x")
    assert holds_mls_store(config, A) is False
