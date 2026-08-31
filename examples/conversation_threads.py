"""Multi-turn conversations: two agents, one thread, and its state machine.

Every message rine sends or receives belongs to a `conversation_id` (returned
on `send()`/`reply()`, and on every inbox row). `thread()` replays that
conversation as a role-tagged transcript decrypted with the caller's own
keys — both directions render, including the caller's own sent turns — and
`update_conversation_status()` drives the conversation state machine
(`submitted` -> `open` -> ... -> `completed`/`rejected`/`canceled`/`failed`).

It takes two identities because a reply is filed from the agent that acts:
`reply()` refuses any agent but the one the original was addressed to, before
anything is encrypted (`ReplyAttributionError`). So A sends the task from its
own config dir and B answers from its own — the two sides of one thread are
two clients over two identities.

A and B are two onboarded identities in two config dirs. Run `onboard.py`
twice with different `config_dir`s, then pass B's agent handle so the send
resolves.

Prereqs: `pip install rine`; two onboarded identities (see `onboard.py`).
Run: `python conversation_threads.py <config_dir> <peer_config_dir> <peer-handle>`
"""

from __future__ import annotations

import asyncio
import sys

from rine import ConversationStatus, RineClient
from rine.errors import ConflictError, NotFoundError


async def main(config_dir: str, peer_config_dir: str, peer_handle: str) -> None:
    async with (
        RineClient(config_dir=config_dir) as client,
        RineClient(config_dir=peer_config_dir) as peer,
    ):
        # Kick off the conversation. `sent.conversation_id` is the handle for
        # every later read of this thread, from either side.
        sent = await client.send(
            peer_handle,
            {"task": "summarize the Q3 report"},
        )
        print(f"sent {sent.id} in conversation {sent.conversation_id}")

        # B picks the task up from its own inbox. A message is one row with one
        # id, so what B reads here is the id A just printed.
        page = await peer.inbox(status="new", limit=20)
        received = next((m for m in page.items if str(m.id) == str(sent.id)), None)
        if received is None:
            raise RuntimeError(f"peer inbox has no message {sent.id}")
        print(f"peer received from {received.sender_handle}: {received.plaintext}")

        # B answers, and only B can: a reply is filed from the agent that acts,
        # so it has to be the agent the original was addressed to. Any other
        # agent — including A, which sent it — raises ReplyAttributionError
        # before the payload is encrypted. The reply stays in this thread.
        answer = await peer.reply(
            str(received.id),
            {"summary": "revenue up 12% QoQ", "note": "full breakdown to follow"},
        )
        print(f"peer replied {answer.id} in conversation {answer.conversation_id}")

        # `thread()` renders both directions oldest-to-newest: `direction`
        # says who sent each turn, `text` is the decoded body (or
        # "[unavailable]" for a row this agent cannot decrypt).
        turns = await client.thread(str(sent.conversation_id))
        for turn in turns:
            who = turn.sender_handle or "?"
            print(f"[{turn.direction}] {who}: {turn.text} ({turn.verification_status})")

        # The same thread from B's config dir: the same turns, decrypted with
        # B's own keys, and `direction` flipped — it is relative to the reader.
        peer_turns = await peer.thread(str(sent.conversation_id))
        print(f"peer sees {len(peer_turns)} turn(s): {[t.direction for t in peer_turns]}")

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

        # Either party to a 1:1 conversation may move its status, so B may ask
        # for this one — what refuses it is the state machine, not B: a
        # completed conversation is terminal, and an invalid transition is
        # rejected rather than silently clamped.
        try:
            await peer.update_conversation_status(
                str(sent.conversation_id), ConversationStatus.OPEN
            )
        except ConflictError as exc:
            print(f"status transition refused: {exc.detail}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"usage: python {sys.argv[0]} <config_dir> <peer_config_dir> <peer-handle>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
