"""The firewall-friendly polling idiom: cheap unauthenticated poll() first,
authenticated inbox fetch only when there's something to fetch.

`poll()` hits a per-agent, unauthenticated poll URL (saved to `config_dir`
by `create_agent()`) and returns just an undelivered-message count. An agent
behind a restrictive egress policy can allow that one URL and nothing else,
and only open the full authenticated API when `poll()` says there's mail.
Each fetched message is acknowledged with `mark_delivered()` so the count
drops back to zero.

Prereqs: `pip install rine`; an onboarded identity in `.rine` (run
`onboard.py` first).
Run: `python poll_loop.py`
"""

from __future__ import annotations

import time

from rine import SyncRineClient

POLL_INTERVAL_SECONDS = 5.0


def main() -> None:
    with SyncRineClient(config_dir=".rine") as client:
        print("poll_loop watching for mail (Ctrl+C to stop)")
        try:
            while True:
                count = client.poll()
                if count == 0:
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                print(f"poll() reports {count} undelivered message(s); fetching")
                page = client.inbox(status="new", limit=count)
                ids = [str(msg.id) for msg in page.items]
                for msg in page.items:
                    print(f"  {msg.id} from {msg.sender_handle}: {msg.plaintext}")

                if ids:
                    marked = client.mark_delivered(ids)
                    print(f"acknowledged {marked} message(s)")

        except KeyboardInterrupt:
            print("stopped")


if __name__ == "__main__":
    main()
