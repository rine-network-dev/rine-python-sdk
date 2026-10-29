"""Every message decrypt tells the verifier when the server stamped the row."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from rine._crypto.message import DecryptResult
from rine.types import DecryptedMessage

SENDER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
STAMPED = datetime(2024, 1, 1, tzinfo=UTC)


GROUP_ID = "99999999-8888-7777-6666-555555555555"


def _row(version: str = "hpke-hybrid-v2", group_id: str | None = None) -> DecryptedMessage:
    return DecryptedMessage(
        id="11111111-2222-3333-4444-555555555555",
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="opaque",
        encryption_version=version,
        created_at=STAMPED,
        direction="received",
        from_agent_id=SENDER,
        group_id=group_id,
    )


def _result() -> DecryptResult:
    return DecryptResult("{}", "kid", True, "verified", False)


def test_decrypt_message_when_a_dm_is_read_then_the_row_stamp_reaches_the_verifier(
    sync_client, agent_id, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    def capture(*args: object, **kwargs: object) -> DecryptResult:
        seen.extend(args[6:])
        return _result()

    monkeypatch.setattr("rine._sync_client.decrypt_message_sync", capture)

    sync_client._decrypt_message(agent_id, _row())

    assert seen == [STAMPED]


async def test_decrypt_message_when_a_dm_is_read_async_then_the_row_stamp_reaches_the_verifier(
    async_client, agent_id, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    async def capture(*args: object, **kwargs: object) -> DecryptResult:
        seen.extend(args[6:])
        return _result()

    monkeypatch.setattr("rine._client.decrypt_message_async", capture)

    await async_client._decrypt_message(agent_id, _row())

    assert seen == [STAMPED]


def test_decrypt_message_when_a_group_row_is_read_then_the_row_stamp_reaches_the_verifier(
    sync_client, agent_id, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    def capture(*args: object, **kwargs: object) -> DecryptResult:
        seen.extend(args[6:])
        return _result()

    monkeypatch.setattr("rine._sync_client.decrypt_group_message_sync", capture)

    sync_client._decrypt_message(agent_id, _row("sender-key-v1", GROUP_ID))

    assert seen == [STAMPED]


async def test_decrypt_message_when_a_group_row_is_read_async_then_the_stamp_reaches_the_verifier(
    async_client, agent_id, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    async def capture(*args: object, **kwargs: object) -> DecryptResult:
        seen.extend(args[6:])
        return _result()

    monkeypatch.setattr("rine._client.decrypt_group_message_async", capture)

    await async_client._decrypt_message(agent_id, _row("sender-key-v1", GROUP_ID))

    assert seen == [STAMPED]
