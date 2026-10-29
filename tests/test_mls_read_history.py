"""Reading a message sealed before its sender rotated, from a process that never synced.

The real ``rine-mls`` core runs; only the server is a stub. ``R`` founds the group from
its own device and ``A`` joins from ``d1``. The reader's allowed set is emptied after its
sync, as a new process would start, so the only way it can open a prior-epoch message is
by admitting the sender's history before the read.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from rine._mls.actor import MlsActor
from rine._mls.group_access import open_mls_group
from rine._mls.messages import decrypt_mls_group_message, encrypt_mls_group_message
from rine._mls.self_update import self_update_group
from rine._mls.sync import sync_mls_group
from rine._utils import to_base64url
from rine.errors import MlsError
from rine.types import GroupRead
from tests.hold_world import HoldServer
from tests.rotation_world import G1, A, B, R, fresh_process, rotate, world

pytestmark = pytest.mark.usefixtures("mls_escrow_stub", "heartbeat_settles_nothing")

BEFORE_ROTATION = datetime(2020, 1, 1, tzinfo=UTC)
GROUP = GroupRead.model_validate(
    {
        "id": G1,
        "name": "g",
        "handle": "#g@acme",
        "created_at": "2024-01-01T00:00:00Z",
        "mls_enabled": True,
        "mls_group_id": "latched",
    }
)


def _send(server: HoldServer, config_dir: str, agent: str, text: str) -> str:
    sealed = encrypt_mls_group_message(server, config_dir, agent, GROUP, {"text": text})
    return sealed.encrypted_payload


def _read(server: HoldServer, config_dir: str, reader: str, sealed: str, sender: str) -> Any:
    result = decrypt_mls_group_message(
        server, config_dir, reader, G1, sealed, sender, BEFORE_ROTATION
    )
    return json.loads(result.plaintext)


def _rotate_and_commit(server: HoldServer, d1: str) -> None:
    rotate(server, d1, A)
    fresh_process()
    self_update_group(MlsActor(client=server, config_dir=d1, agent_id=A), G1)


def test_read_when_the_sender_rotated_after_sending_then_a_fresh_process_opens_it(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    sealed = _send(server, d1, A, "before the rotation")
    _rotate_and_commit(server, d1)
    sync_mls_group(server, dr, R, G1)
    fresh_process()

    assert _read(server, dr, R, sealed, A) == {"text": "before the rotation"}


def test_read_when_the_message_is_at_the_current_epoch_then_no_history_is_fetched(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    sealed = _send(server, d1, A, "current")
    fresh_process()
    server.calls.clear()

    assert _read(server, dr, R, sealed, A) == {"text": "current"}
    assert not [call for call in server.calls if call.startswith("GET /agents/keys")]


def test_read_when_the_sender_was_removed_after_sending_then_it_is_refused(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A, B], server)
    sealed = _send(server, d1, B, "from a member about to be removed")
    founder = open_mls_group(dr, R, G1)
    bundle = founder.remove_member(founder.member_index(B.encode()))
    founder.save()
    server.post_commit(G1, bundle)
    sync_mls_group(server, d1, A, G1)
    fresh_process()

    with pytest.raises(MlsError):
        _read(server, d1, A, sealed, B)


def test_read_when_the_payload_is_not_an_mls_message_then_no_history_is_fetched(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, _d1, dr, _dc = world(tmp_path, G1, [A], server)
    fresh_process()
    server.calls.clear()

    with pytest.raises(MlsError):
        _read(server, dr, R, to_base64url(b"\x04not an mls message"), A)

    assert not [call for call in server.calls if call.startswith("GET /agents/keys")]
