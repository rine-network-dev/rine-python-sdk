"""Pay an x402 quote: prepare_payment() signs and reserves spend in one call.

A payee thread's ``rine.v1.x402_payment_required`` message carries a signed
quote (``PaymentRequired.accepts[]``). Paying it means: pick an ``accepts[]``
entry your spend policy allows, sign an EIP-3009 authorization for it with
your wallet key, and reserve that amount against today's spend cap — all of
which ``prepare_payment()`` does atomically, fail-closed. The signed
``rine.v1.x402_payment`` is then sent as a normal in-thread reply.

The payee is the one that calls a ``FacilitatorClient`` to verify/settle (see
``x402_payee.py``); the payer never talks to a facilitator directly.

Prereqs: `pip install "rine[payments]"` (the `payments` extra provides the
wallet signer); a wallet + spend policy for the paying agent:

    from rine.x402 import create_wallet, save_policy, PaymentPolicy
    create_wallet(config_dir, agent_id)
    save_policy(config_dir, agent_id, PaymentPolicy(
        per_tx_cap="5.00", daily_cap="50.00",
        allowed_assets=["EURC"], allowed_networks=["eip155:8453"],
        auto_pay_threshold="1.00",
    ))

Run: `python x402_payer.py <config_dir> <agent-handle> <quote-message-id>`
"""

from __future__ import annotations

import asyncio
import sys
import time

from rine import MessageType, RineClient
from rine.types import ThreadEntry
from rine.x402 import X402Error, X402ErrorCode, parse_x402_payload, prepare_payment


async def resolve_agent_id(client: RineClient, agent_handle: str) -> str:
    """Look up the agent UUID for a handle.

    ``prepare_payment()`` needs the UUID (wallet keys are stored under it),
    not the handle.
    """
    for agent in await client.list_agents():
        if agent.handle == agent_handle:
            return str(agent.id)
    raise ValueError(f"no agent with handle {agent_handle!r} in this org")


async def pay_quote(client: RineClient, config_dir: str, agent_id: str, quote_message_id: str):
    # read() fetches and decrypts in one call; .plaintext is the raw JSON body.
    quote = await client.read(quote_message_id, agent=agent_id)
    payment_required = parse_x402_payload(quote.plaintext)

    try:
        # Selects the first accepts[] entry the policy allows, signs it, and
        # reserves the spend — the reservation stands even if the send below
        # fails, so a retry of the same quote is an idempotent no-op unless
        # force=True.
        prepared = prepare_payment(
            config_dir,
            agent_id,
            payment_required,
            message_id=quote_message_id,
        )
    except X402Error as exc:
        if exc.code == X402ErrorCode.ALREADY_PAID:
            print(f"quote {quote_message_id} was already paid; pass force=True to repay")
            return None
        # no-acceptable-requirement, per-tx-cap-exceeded, daily-cap-exceeded,
        # wallet-busy, no-policy, ... — exc.code is machine-readable, exc.details
        # carries the amounts/caps involved.
        print(f"payment refused: {exc.code} — {exc.message} ({exc.details})")
        raise

    print(f"selected requirement: {prepared.requirement}")
    print(f"auto-payable under policy threshold: {prepared.auto_payable}")

    sent = await client.reply(
        quote_message_id,
        prepared.message.payload,
        message_type=prepared.message.message_type,
        content_type=prepared.message.content_type,
        metadata=prepared.message.metadata,
        agent=agent_id,
    )
    print(f"sent payment {sent.id} in conversation {sent.conversation_id}")
    return sent


async def await_receipt(
    client: RineClient, conversation_id: str, *, timeout_seconds: float = 30.0
) -> ThreadEntry | None:
    """Poll the thread for the payee's rine.v1.x402_receipt turn."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for turn in await client.thread(conversation_id):
            if turn.type == MessageType.X402_RECEIPT:
                return turn
        await asyncio.sleep(2.0)
    return None


async def main(config_dir: str, agent_handle: str, quote_message_id: str) -> None:
    async with RineClient(config_dir=config_dir) as client:
        agent_id = await resolve_agent_id(client, agent_handle)
        sent = await pay_quote(client, config_dir, agent_id, quote_message_id)
        if sent is None:
            return
        receipt = await await_receipt(client, str(sent.conversation_id))
        if receipt is None:
            print("no receipt yet — the payee may still be settling")
        else:
            print(f"receipt: {receipt.text}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"usage: python {sys.argv[0]} <config_dir> <agent-handle> <quote-message-id>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
