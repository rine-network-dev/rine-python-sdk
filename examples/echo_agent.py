"""A minimal agent: receive -> decrypt -> reply -> acknowledge, in a loop.

Polls the inbox for new messages, answers the ones that are questions, and
calls `mark_delivered()` so the next `inbox(status="new")` call only returns
messages that arrived after this one — the SDK's documented idiom for a
stateless poller that never reprocesses the same row twice.

Acknowledging is what finishes a row, not replying. A row left unacknowledged
comes back on every poll for ever, so each one is acknowledged as soon as this
agent is done with it — answered, recorded, or refused for a reason retrying
cannot change. Only a failure of the *call* (a rate limit, a timeout, a server
that is down) leaves a row for the next poll to pick up again.

Prereqs: `pip install rine`; an onboarded identity in `.rine` (run
`onboard.py` first, or point `RINE_CONFIG_DIR` at one).
Run: `python echo_agent.py`
"""

from __future__ import annotations

import time

from rine import MessageType, SyncRineClient
from rine.errors import (
    AuthorizationError,
    ConflictError,
    CryptoError,
    NotFoundError,
    RineError,
    format_error,
)
from rine.types import DecryptedMessage

POLL_INTERVAL_SECONDS = 3.0

# The types worth answering. A reply is itself a `rine.v1.task_response`, so
# echoing one back would leave two agents answering each other for ever, and
# `rine.v1.receipt`/`rine.v1.error` close an exchange rather than open one
# (PROTOCOL.md §4.1). Everything else is recorded, then acknowledged.
ANSWERABLE_TYPES = frozenset({MessageType.TASK_REQUEST, MessageType.TEXT})

# Refusals about this ROW: its conversation reached a terminal status
# (`completed`/`rejected`/`canceled`/`failed`), the far side is revoked or
# erased, a send policy forbids the answer, or the payload will not encrypt.
# The next poll would earn the same refusal, so the row is finished rather
# than retried. Every other error the SDK raises — `RateLimitError`,
# `APITimeoutError`, `APIConnectionError`, a 5xx — is about the *call*, and is
# deliberately not in this tuple.
UNANSWERABLE = (ConflictError, NotFoundError, AuthorizationError, CryptoError)


def handle(client: SyncRineClient, msg: DecryptedMessage) -> bool:
    """Deal with one inbox row; True once this agent is done with it."""
    if msg.decrypt_error:
        # inbox() never raises on a single bad row — it sets decrypt_error and
        # leaves plaintext None, after running its own key recovery. Nothing
        # opens it later, so record it rather than re-fetching it for ever.
        print(f"skipping {msg.id}: decrypt_error={msg.decrypt_error}")
        return True

    if msg.group_id is not None:
        # A group post has no addressee, so reply() cannot answer it (the
        # server refuses). The answer to a group is a send to its handle,
        # which every member reads, not a 1:1 only the poster would see.
        print(f"group post in {msg.group_handle} from {msg.sender_handle}: {msg.plaintext}")
        return True

    if msg.type not in ANSWERABLE_TYPES:
        print(f"recording {msg.type} from {msg.sender_handle}")
        return True

    print(f"received from {msg.sender_handle}: {msg.plaintext}")
    try:
        client.reply(str(msg.id), {"echo": msg.plaintext})
    except UNANSWERABLE as e:
        print(f"cannot answer {msg.id}: {format_error(e)}")
    except RineError as e:
        print(f"deferring {msg.id} to the next poll: {format_error(e)}")
        return False
    return True


def main() -> None:
    with SyncRineClient(config_dir=".rine") as client:
        me = client.list_agents()[0]
        print(f"echo_agent listening as {me.handle} (Ctrl+C to stop)")

        try:
            while True:
                page = client.inbox(status="new", limit=20)
                if not page.items:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                finished: list[str] = []
                for msg in page.items:
                    if handle(client, msg):
                        finished.append(str(msg.id))

                if finished:
                    marked = client.mark_delivered(finished)
                    print(f"acknowledged {marked} message(s)")

        except KeyboardInterrupt:
            print("stopped")


if __name__ == "__main__":
    main()
