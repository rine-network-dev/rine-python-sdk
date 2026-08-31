"""The Python send path refuses a downgraded group.

The guard sits between the group resolve and the encryption branch, and the
placement is the whole requirement: ``get_or_create_sender_key_sync`` fans this
agent's sender key out to whatever membership the server returns, so by the time
the sender-key branch has run the key is already gone. These tests therefore
assert two things about one refusal — that it is the typed
:class:`MlsDowngradeError`, and that the sender-key helper was never reached.

Local MLS state is real state in the real ``rine-mls`` core, not a fake, so a
refusal asserted here is the refusal a member would actually get.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from rine._crypto.keys import generate_agent_keys, save_agent_keys
from rine._crypto.sender_keys import generate_sender_key
from rine._group_send import encrypt_for_group_sync
from rine._mls.binding import open_mls_client
from rine._mls.group_access import mls_group_id_bytes, note_mls_state_changed
from rine.errors import DOWNGRADE_REFUSED_CODE, MlsDowngradeError

SENDER = "11111111-1111-1111-1111-111111111111"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
GROUP_HANDLE = "#billboard@acme.rine.network"
PAYLOAD = {"announcement": "open enrolment, all welcome"}


def _group(**overrides: Any) -> dict[str, Any]:
    """One ``/groups`` row as the server serves it."""
    return {
        "id": GROUP_ID,
        "name": "billboard",
        "handle": GROUP_HANDLE,
        "created_at": "2024-01-01T00:00:00Z",
        "mls_enabled": False,
        "mls_group_id": None,
        "mls_pending": False,
        **overrides,
    }


class _Server:
    """A stand-in HTTP client that resolves one group and records every GET."""

    def __init__(self, group: dict[str, Any]) -> None:
        self.group = group
        self.paths: list[str] = []

    def get(self, path: str, **_kwargs: Any) -> dict[str, Any]:
        self.paths.append(path)
        if path == "/groups":
            return {"items": [self.group]}
        return {"items": []}


class _SenderKeySpy:
    """Stands in for ``get_or_create_sender_key_sync`` and remembers being called."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _client: Any, _config_dir: str, agent_id: str, group: dict[str, Any]):
        self.calls += 1
        return generate_sender_key(str(group["id"]), agent_id)


@pytest.fixture
def sender_keys(tmp_config_dir):
    save_agent_keys(tmp_config_dir, SENDER, generate_agent_keys())
    return tmp_config_dir


@pytest.fixture
def sender_key_spy(monkeypatch) -> _SenderKeySpy:
    spy = _SenderKeySpy()
    monkeypatch.setattr("rine._group_send.get_or_create_sender_key_sync", spy)
    return spy


def _plant_mls_state(config_dir: str, agent_id: str, group_id: str = GROUP_ID) -> None:
    """Give this agent real local MLS state for the group, as a Welcome would.

    Including the invalidation the production establisher does at its own
    mutation site — the memo is keyed by config dir, and every test gets a fresh
    one, so nothing else is needed to keep tests independent.
    """
    open_mls_client(config_dir, agent_id).create_group(mls_group_id_bytes(group_id)).save()
    note_mls_state_changed(config_dir, agent_id, group_id)


class TestSendRefusesADowngrade:
    """Server says sender-key, this agent holds MLS state: the one refusing cell."""

    def test_encrypt_for_group_sync_when_server_contradicts_local_mls_state_refuses(
        self, sender_keys, sender_key_spy
    ):
        _plant_mls_state(sender_keys, SENDER)
        server = _Server(_group())

        with pytest.raises(MlsDowngradeError) as caught:
            encrypt_for_group_sync(server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD)

        assert caught.value.code == DOWNGRADE_REFUSED_CODE
        assert caught.value.group_id == GROUP_ID

    def test_encrypt_for_group_sync_when_server_contradicts_local_mls_state_never_makes_a_sender_key(
        self, sender_keys, sender_key_spy
    ):
        """The assertion that matters: the key never leaves, so nothing leaks."""
        _plant_mls_state(sender_keys, SENDER)
        server = _Server(_group())

        with pytest.raises(MlsDowngradeError):
            encrypt_for_group_sync(server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD)

        assert sender_key_spy.calls == 0
        assert server.paths == ["/groups"], "the refusal must land before any membership fan-out"

    def test_encrypt_for_group_sync_when_refused_does_not_retry_as_sender_key(
        self, sender_keys, sender_key_spy
    ):
        """No fallback: a second call refuses again rather than degrading."""
        _plant_mls_state(sender_keys, SENDER)
        server = _Server(_group())

        for _ in range(2):
            with pytest.raises(MlsDowngradeError):
                encrypt_for_group_sync(server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD)

        assert sender_key_spy.calls == 0


class TestSendKeepsWorkingWhereItShould:
    """The other three cells of the truth table are ordinary sends."""

    def test_encrypt_for_group_sync_when_billboard_group_has_no_mls_state_uses_sender_keys(
        self, sender_keys, sender_key_spy
    ):
        """The converse: an open billboard group holds no MLS state and sends."""
        server = _Server(_group())

        result, group = encrypt_for_group_sync(
            server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD
        )

        assert sender_key_spy.calls == 1
        assert result.encryption_version == "sender-key-v1"
        assert str(group.id) == GROUP_ID

    def test_encrypt_for_group_sync_when_mls_state_is_another_groups_uses_sender_keys(
        self, sender_keys, sender_key_spy
    ):
        _plant_mls_state(sender_keys, SENDER, "44444444-4444-4444-4444-444444444444")
        server = _Server(_group())

        result, _ = encrypt_for_group_sync(server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD)

        assert sender_key_spy.calls == 1
        assert result.encryption_version == "sender-key-v1"


class TestSendPredicateDrivesTheBranch:
    """The send question is ``group_accepts_mls_send_only``, not the latch."""

    @pytest.mark.parametrize(
        ("overrides", "why"),
        [
            ({"mls_group_id": "opaque-latch"}, "latched"),
            ({"mls_pending": True}, "init in flight"),
        ],
    )
    def test_encrypt_for_group_sync_when_group_accepts_mls_only_never_makes_a_sender_key(
        self, sender_keys, sender_key_spy, monkeypatch, overrides, why
    ):
        seen: dict[str, Any] = {}

        def _fake_mls_encrypt(_client, _config_dir, agent_id, group, payload):
            seen["agent_id"] = agent_id
            seen["group_id"] = str(group.id)
            seen["payload"] = payload
            return _MlsResult()

        monkeypatch.setattr("rine._mls.messages.encrypt_mls_group_message", _fake_mls_encrypt)
        server = _Server(_group(**overrides))

        result, group = encrypt_for_group_sync(
            server, sender_keys, SENDER, GROUP_HANDLE, PAYLOAD
        )

        assert sender_key_spy.calls == 0, f"a group that is {why} must not fan out a sender key"
        assert result.encryption_version == "mls-v1"
        assert str(group.id) == GROUP_ID
        assert seen["group_id"] == GROUP_ID
        assert json.loads(json.dumps(seen["payload"])) == PAYLOAD


class _MlsResult:
    """The shape ``encrypt_mls_group_message`` returns, stubbed at the boundary."""

    encrypted_payload = "AAAA"
    encryption_version = "mls-v1"
    sender_signing_kid = "kid"
