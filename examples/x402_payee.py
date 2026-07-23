"""Charge for your agent: fulfil an incoming x402 payment and issue a receipt.

When a payer's signed ``rine.v1.x402_payment`` arrives, `rine.x402.payee.fulfill()`
runs the whole payee ladder in one call: it binds the payment to the ONE quote
you issued (refusing anything that doesn't reconcile — no settling payer-authored
terms), verifies the signed authorization with your facilitator, settles it
on-chain, and threads a `rine.v1.x402_receipt` back to the payer. rine never
runs the facilitator or custodies funds — you configure and call it directly.

For work that must be delivered before you settle (`settle-after-delivery`),
compose the lower-level primitives instead: `verify()` up front (no broadcast),
do the work, then `settle()` + `send_receipt()`. Both paths are shown below.

Prereqs: `pip install "rine[payments]"`; a `payTo` wallet address for your
quotes (any EVM address you control — no rine wallet key is needed on the
payee side, only on the payer side).

Run: `python x402_payee.py <config_dir> <agent-handle> <payment-message-id>`
"""

from __future__ import annotations

import asyncio
import sys

from rine import RineClient
from rine.x402 import FacilitatorClient, X402Error, fulfill, send_receipt, settle, verify


async def resolve_agent_id(client: RineClient, agent_handle: str) -> str:
    for agent in await client.list_agents():
        if agent.handle == agent_handle:
            return str(agent.id)
    raise ValueError(f"no agent with handle {agent_handle!r} in this org")


async def fulfill_immediately(client: RineClient, agent_id: str, payment_message_id: str) -> None:
    """settle-first: verify, settle, and reply the receipt in one call."""
    payment = await client.read(payment_message_id, agent=agent_id)

    async with FacilitatorClient("payai") as facilitator:
        try:
            result = await fulfill(client, payment, facilitator=facilitator, agent=agent_id)
        except X402Error as exc:
            # Wrong message type, undecryptable payment, or a malformed body —
            # a reconciliation mismatch is a graceful failure receipt instead
            # of raising, so this branch is the narrow structural-error case.
            print(f"could not fulfil: {exc.code} — {exc.message}")
            return

    print(
        f"settlement success: {result.settlement.get('success') if result.settlement else False}"
    )
    print(f"receipt sent: {result.receipt.id}")
    if result.matched_quote:
        print(f"matched quote {result.matched_quote.quote_message_id}")


async def fulfill_after_delivery(
    client: RineClient,
    agent_id: str,
    payment_message_id: str,
    expected_requirement: dict,
) -> None:
    """settle-after-delivery: verify up front, do the work, then settle + receipt.

    ``expected_requirement`` is the ONE `accepts[]` entry from the quote you
    issued for this payment — pass it explicitly here since `verify()`/`settle()`
    otherwise fail closed with no thread context to look the quote up from
    (that lookup is what `fulfill()` above does automatically).
    """
    payment = await client.read(payment_message_id, agent=agent_id)

    async with FacilitatorClient("payai") as facilitator:
        try:
            verification = await verify(
                payment, facilitator=facilitator, expected=expected_requirement
            )
        except X402Error as exc:
            print(f"could not verify: {exc.code} — {exc.message}")
            return
        if not verification.get("isValid", False):
            print("verification failed — refusing to deliver")
            return

        # ... do the paid-for work here ...

        settlement = await settle(payment, facilitator=facilitator, expected=expected_requirement)
        await send_receipt(client, payment, settlement, agent=agent_id)
    print("delivered and settled")


async def main(config_dir: str, agent_handle: str, payment_message_id: str) -> None:
    async with RineClient(config_dir=config_dir) as client:
        agent_id = await resolve_agent_id(client, agent_handle)
        await fulfill_immediately(client, agent_id, payment_message_id)

        # Advertise what you accept: the coarse pricing_model is set through
        # the SDK; the detailed rine.x402.terms array (rail/scheme/network/
        # asset entries) is published with the CLI, which merges it into the
        # same card object:
        #     rine agent set-pricing <agent-id> --x402-terms-file terms.json
        await client.set_agent_card(
            agent_id,
            name="Example Payee Agent",
            description="Summarizes reports for a fee.",
            pricing_model="per_request",
        )


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"usage: python {sys.argv[0]} <config_dir> <agent-handle> <payment-message-id>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))
