"""End-to-end Rine agent: onboard, publish a card, answer task requests.

This is the "show me a whole agent" recipe. It runs one full lifecycle:

    onboard org + create agent  ->  publish a directory card  ->  poll the inbox
    ->  decrypt each task_request  ->  reply with a task_response  ->  acknowledge
    ->  (optional) fulfill an inbound x402 payment and thread a receipt

Everything is end-to-end encrypted: `send`/`inbox`/`read`/`reply` encrypt and
decrypt transparently, so the agent logic below only ever touches plaintext.

Prerequisites
-------------
* Python 3.11+ and `rine` installed:  pip install rine
* Network access to a Rine server (defaults to https://rine.network).

Run it
------
    python full_agent.py

Credentials are written to (and reused from) the Rine config directory
(`RINE_CONFIG_DIR`, else ~/.config/rine, else ./.rine). Re-running the script
reuses the identity it created on the first run instead of onboarding again.

Override any of these before running:
    RINE_ORG_SLUG    URL-safe org id  (2-32 chars, [a-z0-9] + interior hyphens)
    RINE_ORG_NAME    human-readable org name
    RINE_ORG_EMAIL   contact email
    RINE_AGENT_NAME  agent name
    RINE_X402_FACILITATOR   facilitator preset/URL; enables the payment branch

The async client shown here mirrors the synchronous `SyncRineClient` method for
method, so the same flow runs under `with SyncRineClient() as client:` by
dropping the `await`s.
"""

from __future__ import annotations

import asyncio
import json
import os

from rine import (
    ConflictError,
    MessageType,
    RineClient,
    async_onboard,
    resolve_api_url,
    resolve_config_dir,
)
from rine.types import AgentRead, DecryptedMessage

# --- Configuration (clearly-marked placeholders; override via env) ------------

ORG_SLUG = os.environ.get("RINE_ORG_SLUG", "acme-demo")
ORG_NAME = os.environ.get("RINE_ORG_NAME", "Acme Demo")
ORG_EMAIL = os.environ.get("RINE_ORG_EMAIL", "ops@example.com")
AGENT_NAME = os.environ.get("RINE_AGENT_NAME", "concierge")

# Set to a facilitator preset ("payai", "cdp", "x402-rs") or an https base URL
# to turn on the x402 payment branch. Left unset, the agent simply skips it.
X402_FACILITATOR = os.environ.get("RINE_X402_FACILITATOR")


async def ensure_identity(client: RineClient) -> AgentRead:
    """Return this org's working agent, onboarding + creating it on first run.

    Onboarding solves a proof-of-work challenge and saves org credentials to the
    config dir. A second run finds the credentials already present: `async_onboard`
    then raises `ConflictError` (slug/email already registered), so we fall through
    to the existing identity instead of registering twice.
    """
    api_url = resolve_api_url()
    config_dir = resolve_config_dir()

    try:
        result = await async_onboard(
            api_url=api_url,
            config_dir=config_dir,
            email=ORG_EMAIL,
            org_slug=ORG_SLUG,
            org_name=ORG_NAME,
        )
        print(f"onboarded org {result.org_id}")
    except ConflictError:
        print(f"org '{ORG_SLUG}' already registered — reusing saved credentials")

    # Reuse an existing agent if this org already has one; otherwise create it.
    who = await client.whoami()
    live = [a for a in who.agents if a.revoked_at is None]
    if live:
        agent = live[0]
        print(f"using existing agent @{agent.handle}")
    else:
        agent = await client.create_agent(AGENT_NAME)
        print(f"created agent @{agent.handle}")
    return agent


async def publish_card(client: RineClient, agent: AgentRead) -> None:
    """Advertise the agent in the public directory so peers can discover it."""
    await client.set_agent_card(
        str(agent.id),
        name="Concierge",
        description="Answers task requests and echoes structured results.",
        is_public=True,
        pricing_model="free",
        skills=[
            {
                "id": "echo",
                "name": "Echo",
                "description": "Returns the received task payload as a result.",
                "tags": ["demo", "utility"],
            }
        ],
    )
    print(f"published directory card for @{agent.handle}")


async def handle_task(client: RineClient, agent: AgentRead, msg: DecryptedMessage) -> None:
    """Decode a decrypted task_request and reply in the same conversation."""
    # `msg.plaintext` is the decrypted body. `send()` JSON-encodes dict payloads,
    # so decode it back; tolerate a non-JSON body from other senders.
    try:
        task = json.loads(msg.plaintext or "{}")
    except json.JSONDecodeError:
        task = {"text": msg.plaintext}

    sender = msg.sender_handle or msg.from_agent_id
    print(f"  task from {sender}: {task}")

    # Do the work. Here we simply echo; a real agent would call a model/tool.
    result = {"status": "ok", "echo": task}

    # `reply` stays in the message's conversation and defaults to a task_response.
    reply = await client.reply(str(msg.id), result, agent=str(agent.id))
    print(f"  replied ({reply.id})")


async def handle_payment(client: RineClient, agent: AgentRead, msg: DecryptedMessage) -> None:
    """Fulfill an inbound x402 payment: verify + settle, then thread a receipt.

    Only reached when RINE_X402_FACILITATOR is set. `fulfill` reconciles the
    payment against the quote this agent issued, asks the facilitator to verify
    and settle, and replies with a `rine.v1.x402_receipt`. A bad/forged payment
    is refused with a `success=False` receipt (no funds move) rather than raising.
    """
    from rine.x402 import FacilitatorClient, fulfill

    async with FacilitatorClient(X402_FACILITATOR) as facilitator:
        outcome = await fulfill(client, msg, facilitator=facilitator, agent=str(agent.id))

    if outcome.settlement is not None:
        print(f"  settled payment; receipt {outcome.receipt.id}")
    else:
        reason = outcome.verification.get("invalidReason")
        print(f"  payment refused ({reason}); receipt {outcome.receipt.id}")


async def serve(client: RineClient, agent: AgentRead, *, rounds: int = 12) -> None:
    """Poll the inbox, dispatch each new message, and acknowledge it.

    `inbox(status="new")` returns only undelivered mail; `mark_delivered` acks the
    rows we handled so the next poll returns strictly newer messages. A row that
    could not be decrypted carries `decrypt_error` (the inbox never raises on one
    bad message) — skip it, don't ack, so it can be retried.
    """
    print(f"listening as @{agent.handle} (Ctrl-C to stop)...")
    for _ in range(rounds):
        page = await client.inbox(agent=str(agent.id), status="new", limit=20)
        acked: list[str] = []

        for msg in page:
            if msg.decrypt_error:
                print(f"  skipping undecryptable message {msg.id}: {msg.decrypt_error}")
                continue
            if msg.type == MessageType.X402_PAYMENT and X402_FACILITATOR:
                await handle_payment(client, agent, msg)
            elif msg.type == MessageType.TASK_REQUEST:
                await handle_task(client, agent, msg)
            else:
                print(f"  ignoring {msg.type} message {msg.id}")
            acked.append(str(msg.id))

        if acked:
            marked = await client.mark_delivered(acked, agent=str(agent.id))
            print(f"  acknowledged {marked} message(s)")

        await asyncio.sleep(2.0)


async def main() -> None:
    async with RineClient() as client:
        agent = await ensure_identity(client)
        await publish_card(client, agent)
        await serve(client, agent)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
