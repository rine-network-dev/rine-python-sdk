"""A minimal agent: receive -> decrypt -> reply -> acknowledge, in a loop.

Polls the inbox for new messages, prints each decrypted payload, replies with
an echo, then calls `mark_delivered()` so the next `inbox(status="new")` call
only returns messages that arrived after this one — the SDK's documented
idiom for a stateless poller that never reprocesses the same row twice.

Prereqs: `pip install rine`; an onboarded identity in `.rine` (run
`onboard.py` first, or point `RINE_CONFIG_DIR` at one).
Run: `python echo_agent.py`
"""

from __future__ import annotations

import time

from rine import SyncRineClient
from rine.errors import CryptoError

POLL_INTERVAL_SECONDS = 3.0


def main() -> None:
    with SyncRineClient(config_dir=".rine") as client:
        me = client.whoami()
        agent_handle = me.agents[0].handle
        print(f"echo_agent listening as {agent_handle} (Ctrl+C to stop)")

        try:
            while True:
                page = client.inbox(status="new", limit=20)
                if not page.items:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                delivered_ids: list[str] = []
                for msg in page.items:
                    if msg.decrypt_error:
                        # inbox() never raises on a single bad row — it sets
                        # decrypt_error instead. Acknowledge it anyway so a
                        # permanently-undecryptable row does not loop forever.
                        print(f"skipping {msg.id}: decrypt_error={msg.decrypt_error}")
                        delivered_ids.append(str(msg.id))
                        continue

                    print(f"received from {msg.sender_handle}: {msg.plaintext}")

                    try:
                        client.reply(str(msg.id), {"echo": msg.plaintext})
                    except CryptoError as e:
                        print(f"reply failed for {msg.id}: {e}")
                        continue

                    delivered_ids.append(str(msg.id))

                if delivered_ids:
                    marked = client.mark_delivered(delivered_ids)
                    print(f"acknowledged {marked} message(s)")

        except KeyboardInterrupt:
            print("stopped")


if __name__ == "__main__":
    main()
