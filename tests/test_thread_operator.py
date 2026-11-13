"""thread() hands each received direct turn its operator class, on the async and sync clients."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import respx

from rine import OperatorContext, OperatorPin
from rine._crypto.keys import load_agent_keys
from rine._crypto.message import encrypt_message
from rine._utils import to_base64url
from rine.testing import WORLD
from tests.conftest import recipient_view
from tests.test_thread import (
    AGENT_ID,
    CONVERSATION_ID,
    PEER_ID,
    _build_rows,
    _mock_agents,
    _mock_keys,
    _mock_thread_endpoint,
    _mock_token,
)

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)


def _operator_rows(config_dir: str) -> list[dict]:
    """The standard transcript, its received turn replaced by a signed console message."""
    rows = _build_rows(config_dir, WORLD.keys(PEER_ID))
    statement = {
        "v": 1,
        "purpose": "operator.command",
        "agent": AGENT_ID,
        "nonce": "nonce-thread",
        "issued_at": "2026-10-31T11:59:00Z",
    }
    sealed = encrypt_message(
        config_dir,
        PEER_ID,
        recipient_view(load_agent_keys(config_dir, AGENT_ID), AGENT_ID),
        {"text": "pause the crawl", "rine.operator": statement},
    )
    rows[1]["encrypted_payload"] = sealed.encrypted_payload
    return rows


def _context(config_dir: str, signing_key: bytes | None) -> OperatorContext:
    pin = OperatorPin(PEER_ID, to_base64url(signing_key)) if signing_key else None
    return OperatorContext(
        pin=pin,
        self_agent_id=AGENT_ID,
        config_dir=config_dir,
        now=lambda: int(NOW.timestamp() * 1000),
        warn=lambda _message: None,
    )


class TestThreadOperatorClass:
    """Thread operator class."""

    @respx.mock
    async def test_async_thread_when_the_seat_sent_a_command_then_the_turn_is_operator(
        self, async_client, tmp_config_dir
    ):
        """Async thread when the seat sent a command then the turn is operator."""
        _mock_token()
        _mock_agents()
        _mock_keys()
        _mock_thread_endpoint(_operator_rows(tmp_config_dir))
        context = _context(tmp_config_dir, WORLD.keys(PEER_ID).signing.public_key)

        entries = await async_client.thread(CONVERSATION_ID, operator=context)

        assert [e.sender_class for e in entries] == ["other", "operator", "other"]
        assert entries[1].from_agent_id == PEER_ID
        assert "rine.operator" not in entries[1].text
        await async_client.close()

    @respx.mock
    def test_sync_thread_when_the_seat_sent_a_command_then_the_turn_is_operator(
        self, sync_client, tmp_config_dir
    ):
        """Sync thread when the seat sent a command then the turn is operator."""
        _mock_token()
        _mock_agents()
        _mock_keys()
        _mock_thread_endpoint(_operator_rows(tmp_config_dir))
        context = _context(tmp_config_dir, WORLD.keys(PEER_ID).signing.public_key)

        entries = sync_client.thread(CONVERSATION_ID, operator=context)

        assert [e.sender_class for e in entries] == ["other", "operator", "other"]

    @respx.mock
    async def test_async_thread_when_no_context_is_given_then_every_turn_is_other(
        self, async_client, tmp_config_dir
    ):
        """Async thread when no context is given then every turn is other."""
        _mock_token()
        _mock_agents()
        _mock_keys()
        _mock_thread_endpoint(_operator_rows(tmp_config_dir))

        entries = await async_client.thread(CONVERSATION_ID)

        assert {e.sender_class for e in entries} == {"other"}
        await async_client.close()

    @respx.mock
    async def test_async_thread_when_no_seat_is_pinned_then_every_turn_is_other(
        self, async_client, tmp_config_dir
    ):
        """Async thread when no seat is pinned then every turn is other."""
        _mock_token()
        _mock_agents()
        _mock_keys()
        _mock_thread_endpoint(_operator_rows(tmp_config_dir))

        entries = await async_client.thread(
            CONVERSATION_ID, operator=_context(tmp_config_dir, None)
        )

        assert {e.sender_class for e in entries} == {"other"}
        await async_client.close()

    @respx.mock
    async def test_async_thread_when_the_ledger_lock_is_held_then_the_loop_keeps_running(
        self, async_client, tmp_config_dir
    ):
        """Async thread when the ledger lock is held then the loop keeps running."""
        _mock_token()
        _mock_agents()
        _mock_keys()
        _mock_thread_endpoint(_operator_rows(tmp_config_dir))
        context = _context(tmp_config_dir, WORLD.keys(PEER_ID).signing.public_key)
        lock = Path(tmp_config_dir) / f"operator_ledger_{AGENT_ID}.json.lock"
        held = {"pid": 1, "acquired_at": int(time.time() * 1000), "token": "other"}
        lock.write_text(json.dumps(held) + "\n")
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        ticker = asyncio.create_task(tick())
        reading = asyncio.create_task(async_client.thread(CONVERSATION_ID, operator=context))
        await asyncio.sleep(0.3)
        lock.unlink()
        entries = await reading
        ticker.cancel()

        assert ticks > 5
        assert entries[1].sender_class == "operator"
        await async_client.close()
