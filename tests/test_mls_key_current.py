"""A device holding an earlier key generation must not publish key packages.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` rotates to generation 1 on
device ``d1``, and a later rotation to generation 2 elsewhere leaves ``d1`` stale.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.api import upload_key_packages
from rine._mls.binding import open_mls_client
from rine._mls.key_current import disk_key_is_current
from rine._mls.key_not_current import MlsKeyNotCurrentError
from rine._mls.key_package_cutover import drain_and_republish_mls_key_packages
from rine._mls.rotation_marker import read_rotation_marker
from rine._mls.seat_sweep import KeyPackageRotation, settle_rotation
from rine.errors import RineApiError
from tests.hold_world import HoldServer, rotated
from tests.rotation_world import A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def _superseded(tmp_path: Any) -> tuple[HoldServer, str, Any]:
    """``d1`` holds generation 1 while the agent has since published generation 2."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.publish(A, 2)
    return server, d1, actor


def test_disk_key_is_current_when_the_disk_key_is_the_published_one_then_it_is_true(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    _server, _d1, _dr, actor = rotated(tmp_path)
    assert disk_key_is_current(actor) is True


def test_disk_key_is_current_when_a_later_generation_is_published_then_it_is_false(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    _server, _d1, actor = _superseded(tmp_path)
    assert disk_key_is_current(actor) is False


def test_disk_key_is_current_when_the_read_fails_then_the_failure_propagates(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller that cannot tell not-current from an outage must not report either."""
    server, _d1, _dr, actor = rotated(tmp_path)

    def down(path: str, **_kw: Any) -> dict[str, Any]:
        raise RineApiError(503, "unavailable")

    monkeypatch.setattr(server, "get", down)
    with pytest.raises(RineApiError):
        disk_key_is_current(actor)


def test_upload_key_packages_when_the_server_names_the_key_not_current_then_it_is_typed(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    server, _d1, _dr, _actor = rotated(tmp_path)
    server.fail_upload = RineApiError(422, "stale", '{"error": "mls_key_not_current"}')
    with pytest.raises(MlsKeyNotCurrentError):
        upload_key_packages(server, A, [b"pkg"])


def test_upload_key_packages_when_any_other_refusal_comes_back_then_it_propagates(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    server, _d1, _dr, _actor = rotated(tmp_path)
    server.fail_upload = RineApiError(422, "no", '{"error": "something_else"}')
    with pytest.raises(RineApiError) as caught:
        upload_key_packages(server, A, [b"pkg"])
    assert not isinstance(caught.value, MlsKeyNotCurrentError)


def test_drain_when_the_device_key_is_not_current_then_nothing_is_minted_or_claimed(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The check runs first: a refused upload after the claim would leave an empty pool."""
    server, d1, actor = _superseded(tmp_path)
    held = open_mls_client(d1, A).key_package_count()
    calls = len(server.calls)
    with pytest.raises(MlsKeyNotCurrentError):
        drain_and_republish_mls_key_packages(actor.client, d1, A)
    assert not [c for c in server.calls[calls:] if "key-packages" in c]
    assert server.uploads == []
    assert open_mls_client(d1, A).key_package_count() == held


def test_settle_rotation_when_the_device_key_is_not_current_then_it_says_so_and_the_package_marker_holds(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    _server, d1, actor = _superseded(tmp_path)
    settled = settle_rotation(actor)
    assert settled.key_packages is KeyPackageRotation.KEY_NOT_CURRENT
    assert read_rotation_marker(d1, A).key_packages == 0
