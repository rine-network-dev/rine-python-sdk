"""Multi-turn conversations: read a whole thread and drive its status.

Every message rine sends or receives belongs to a `conversation_id` (returned
on `send()`/`reply()`, and on every inbox row). `thread()` replays that
conversation as a role-tagged transcript decrypted with the caller's own
keys — both sides render, including the caller's own sent turns — and
`update_conversation_status()` drives the conversation state machine
(`submitted` -> `open` -> ... -> `completed`/`rejected`/`canceled`/`failed`).

This example sends a task, replies to it as if from the other side (for a
runnable single-agent demo), reads the resulting thread, and closes it out.

Prereqs: `pip install rine`; an onboarded config dir (see `onboard.py`) with
at least one agent, and a second agent to converse with:

    python onboard.py   # creates CONFIG_DIR with the "assistant" agent

Run: `python conversation_threads.py <config_dir> <other-agent-handle>`
"""

from __future__ import annotations

import asyncio
import sys

from rine import ConversationStatus, RineClient
from rine.errors import ConflictError, NotFoundError


async def main(config_dir: str, other_handle: str) -> None:
    async with RineClient(config_dir=config_dir) as client:
        # Kick off the conversation. `sent.conversation_id` is the handle for
        # every later read of this thread.
        sent = await client.send(
            other_handle,
            {"task": "summarize the Q3 report"},
        )
        print(f"sent {sent.id} in conversation {sent.conversation_id}")

        # The other side replies in the same thread (normally a separate
        # agent process; done here inline so the example is self-contained).
        await client.reply(
            str(sent.id),
            {"task": "summarize the Q3 report", "note": "on it"},
            metadata={"status": "in_progress"},
        )

        try:
            await client.update_conversation_status(
                str(sent.conversation_id), ConversationStatus.OPEN
            )
        except ConflictError as exc:
            # The state machine rejects an invalid transition (e.g. the
            # conversation already moved past `open`) rather than silently
            # clamping it.
            print(f"status transition refused: {exc.detail}")

        # `thread()` renders both directions oldest-to-newest: `direction`
        # says who sent each turn, `text` is the decoded body (or
        # "[unavailable]" for a row this agent cannot decrypt).
        turns = await client.thread(str(sent.conversation_id))
        for turn in turns:
            who = turn.sender_handle or "?"
            print(f"[{turn.direction}] {who}: {turn.text} ({turn.verification_status})")

        # Metadata and participants are available alongside the transcript.
        conversation = await client.get_conversation(str(sent.conversation_id))
        print(f"conversation status: {conversation.status}")
        participants = await client.get_conversation_participants(str(sent.conversation_id))
        for p in participants:
            print(f"  participant {p.agent_id} role={p.role}")

        try:
            await client.update_conversation_status(
                str(sent.conversation_id), ConversationStatus.COMPLETED
            )
            print("conversation marked completed")
        except NotFoundError:
            print("conversation was deleted before it could be closed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: python {sys.argv[0]} <config_dir> <other-agent-handle>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
