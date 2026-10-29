"""Reading prior-epoch messages from one rotated sender reads its history keys once.

The real ``rine-mls`` core runs; only the server is a stub. A process that never synced
admits the sender's history before each prior-epoch read, and a generation is immutable, so
the client's key cache answers every read after the first. The current key is read fresh
each time, so a later rotation by the sender is always admitted.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._crypto._key_cache import KeyCache
from rine._crypto.keys import save_agent_keys
from rine._mls.actor import MlsActor
from rine._mls.self_update import self_update_group
from rine._mls.sync import sync_mls_group
from rine.errors import MlsError
from rine.testing import WORLD
from tests.hold_world import HoldServer
from tests.rotation_world import G1, A, C, R, fresh_process, world
from tests.test_mls_read_history import _read, _send

pytestmark = pytest.mark.usefixtures("mls_escrow_stub", "heartbeat_settles_nothing")


def _history_reads(server: HoldServer, gen: int) -> list[str]:
    return [call for call in server.calls if call.endswith(f"/keys {{'gen': {gen}}}")]


def _new_process(server: HoldServer) -> None:
    """Forget the allowed sets and the key cache, as a new process would."""
    fresh_process()
    server.keys._keys_cache = KeyCache(600.0, 256)


def _rotate_to(server: HoldServer, d1: str, gen: int) -> None:
    save_agent_keys(d1, A, WORLD.keys(A, gen))
    server.publish(A, gen)
    fresh_process()
    self_update_group(MlsActor(client=server, config_dir=d1, agent_id=A), G1)


def test_read_when_many_prior_epoch_messages_come_from_one_sender_then_history_is_read_once(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    sealed = [_send(server, d1, A, f"m{n}") for n in range(3)]
    _rotate_to(server, d1, 1)
    _rotate_to(server, d1, 2)
    sync_mls_group(server, dr, R, G1)
    _new_process(server)
    server.calls.clear()

    for n, payload in enumerate(sealed):
        assert _read(server, dr, R, payload, A) == {"text": f"m{n}"}

    assert len(_history_reads(server, 1)) == 1


def test_read_when_the_sender_rotates_again_after_cached_reads_then_the_new_message_opens(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    first = _send(server, d1, A, "first")
    _rotate_to(server, d1, 1)
    sync_mls_group(server, dr, R, G1)
    _new_process(server)
    assert _read(server, dr, R, first, A) == {"text": "first"}
    second = _send(server, d1, A, "second")
    _rotate_to(server, d1, 2)
    sync_mls_group(server, dr, R, G1)
    fresh_process()

    assert _read(server, dr, R, second, A) == {"text": "second"}


def test_read_when_the_history_generation_it_needs_fails_the_chain_then_it_is_refused(
    tmp_path: Any,
) -> None:
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    old = _send(server, d1, A, "sealed under the unverifiable generation")
    _rotate_to(server, d1, 1)
    newer = _send(server, d1, A, "sealed under a verifiable generation")
    _rotate_to(server, d1, 2)
    sync_mls_group(server, dr, R, G1)
    _new_process(server)
    server.keys.tamper = lambda body: (
        {**body, "agent_certificate": WORLD.keys_response(C)["agent_certificate"]}
        if body["key_gen"] == 0
        else body
    )

    assert _read(server, dr, R, newer, A) == {"text": "sealed under a verifiable generation"}
    with pytest.raises(MlsError):
        _read(server, dr, R, old, A)
