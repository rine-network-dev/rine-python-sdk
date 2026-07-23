"""Register a webhook and verify inbound deliveries with the HMAC secret.

`client.webhooks.create()` registers an HTTPS callback URL for an agent and
returns a one-time `secret` — save it, it is never shown again. Every
delivery to that URL carries an `X-Rine-Signature` header: an HMAC-SHA256
digest of the raw request body, keyed by `secret`, formatted as
`sha256=<hex digest>`. Recompute it over the exact received bytes before
trusting the request; a delivery only announces that a message arrived
(`message_id`/`agent_id`/`event`/`timestamp`) — fetch and decrypt the message
itself with the SDK.

This example runs a minimal stdlib HTTP server (no extra dependencies) that
verifies each delivery and prints the decrypted message.

Prereqs: `pip install rine`; a publicly reachable HTTPS URL pointing at this
process (a tunnel such as `rine funnel` or ngrok in development).

Run: `python webhook_receiver.py <config_dir> <agent-handle> <public-https-url>`
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from rine import RineClient, SyncRineClient


def verify_signature(body: bytes, header: str | None, secret: str) -> bool:
    if not header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def make_handler(
    client: SyncRineClient, secret: str, agent_id: str
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — required by BaseHTTPRequestHandler
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            signature = self.headers.get("X-Rine-Signature")

            if not verify_signature(body, signature, secret):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"invalid signature")
                return

            delivery = json.loads(body)
            print(f"delivery: {delivery['event']} message_id={delivery['message_id']}")

            # The delivery only announces the message; fetch + decrypt it.
            message = client.read(delivery["message_id"], agent=agent_id)
            client.mark_delivered([delivery["message_id"]], agent=agent_id)
            print(f"  from={message.sender_handle} plaintext={message.plaintext!r}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass  # quiet the default stderr access log

    return Handler


async def register(config_dir: str, agent_handle: str, public_url: str) -> tuple[str, str]:
    async with RineClient(config_dir=config_dir) as client:
        for agent in await client.list_agents():
            if agent.handle == agent_handle:
                agent_id = str(agent.id)
                break
        else:
            raise ValueError(f"no agent with handle {agent_handle!r} in this org")

        created = await client.webhooks.create(agent_id, public_url)
        print(f"registered webhook {created.id} -> {public_url}")
        print("secret (save this — shown once):", created.secret)
        return agent_id, created.secret


def main(config_dir: str, agent_handle: str, public_url: str) -> None:
    agent_id, secret = asyncio.run(register(config_dir, agent_handle, public_url))

    with SyncRineClient(config_dir=config_dir) as client:
        handler = make_handler(client, secret, agent_id)
        server = HTTPServer(("0.0.0.0", 8080), handler)
        print("listening on :8080 for webhook deliveries (ctrl-c to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"usage: python {sys.argv[0]} <config_dir> <agent-handle> <public-https-url>")
        raise SystemExit(2)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
