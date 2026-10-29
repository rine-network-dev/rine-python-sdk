"""SDK-side stale-key refusal contract: the server's own 422 body becomes the typed error.

A device on an earlier key generation is refused with a 422 whose ``error`` is a code. The
SDK matches the code, never the sentence, so a server that renamed it would turn the outcome
back into a generic failure with every stubbed suite still green. The golden is the real
router's body, run through the SDK's own response parser.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from rine._http import _check_response
from rine._mls.api import upload_key_packages
from rine._mls.key_not_current import MLS_ERR_KEY_NOT_CURRENT, MlsKeyNotCurrentError
from rine._mls.seat_sweep import KeyPackageRotation, settle_rotation
from rine.errors import RineApiError
from tests.contract._loader import load
from tests.hold_world import rotated
from tests.rotation_world import A


def _refusal() -> RineApiError:
    """The error the SDK's parser raises for the golden's status and body."""
    golden = load("mls_key_packages_422_not_current")
    with pytest.raises(RineApiError) as caught:
        _check_response(httpx.Response(golden["status"], content=json.dumps(golden["body"])))
    return caught.value


def test_golden_when_the_server_refuses_a_stale_key_then_its_error_is_the_shared_code():
    assert load("mls_key_packages_422_not_current")["body"]["error"] == MLS_ERR_KEY_NOT_CURRENT


def test_upload_key_packages_when_the_server_golden_is_replayed_then_it_is_typed(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    server, _d1, _dr, _actor = rotated(tmp_path)
    server.fail_upload = _refusal()

    with pytest.raises(MlsKeyNotCurrentError):
        upload_key_packages(server, A, [b"pkg"])


@pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")
def test_settle_rotation_when_the_upload_is_refused_after_the_pre_check_then_it_says_not_current(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A rotation lands after the pre-check passed: the refusal, not a generic failure, reports."""
    server, _d1, _dr, actor = rotated(tmp_path)
    server.fail_upload = _refusal()

    settled = settle_rotation(actor)

    assert settled.key_packages is KeyPackageRotation.KEY_NOT_CURRENT
