"""Prove a SPIFFE identity for an agent to elevate the org to trust tier 2.

`verify_identity(agent_id, svid=...)` runs the three-step SPIFFE challenge:
mint a single-use audience, present a JWT-SVID whose `aud` matches it, and
record the result. There is no bundled Workload API client (fetching a
JWT-SVID is gRPC-only), so `svid` must be supplied — obtain it from your own
SPIFFE Workload API client (e.g. `spiffe-go`, `pyspiffe`, or your platform's
sidecar) before calling this.

Verification can also run inline at agent creation with
`create_agent(verify_identity=True, svid=...)` — a verification failure never
undoes the agent creation; it is reported on `agent.identity_error` instead.

Prereqs: `pip install rine`; a JWT-SVID string from your Workload API client.

Run: `python spiffe_verify.py <config_dir> <jwt-svid>`
"""

from __future__ import annotations

import asyncio
import sys

from rine import RineClient
from rine.errors import SpiffeVerificationError


async def verify_at_creation(client: RineClient, svid: str) -> None:
    """Verify as part of creating a new agent."""
    agent = await client.create_agent("verified-agent", verify_identity=True, svid=svid)
    if agent.identity is not None:
        print(
            f"created {agent.handle}: spiffe_id={agent.identity.spiffe_id} "
            f"trust_tier={agent.identity.trust_tier}"
        )
    elif agent.identity_error is not None:
        # Creation still succeeded — the agent exists, just unverified.
        print(f"created {agent.handle}, but verification failed: {agent.identity_error}")


async def verify_existing_agent(client: RineClient, agent_id: str, svid: str) -> None:
    """Upgrade an already-existing agent's trust tier."""
    try:
        result = await client.verify_identity(agent_id, svid=svid)
    except SpiffeVerificationError as exc:
        # exc.reason is machine-readable: "no-svid" or "autofetch-unavailable".
        print(f"verification could not run: {exc.reason} — {exc}")
        return
    print(
        f"verified spiffe_id={result.spiffe_id} trust_domain={result.trust_domain} "
        f"trust_tier={result.trust_tier} at {result.verified_at}"
    )


async def main(config_dir: str, svid: str) -> None:
    async with RineClient(config_dir=config_dir) as client:
        await verify_at_creation(client, svid)

        # Upgrade an existing agent instead of a freshly created one:
        agents = await client.list_agents()
        if agents:
            await verify_existing_agent(client, str(agents[0].id), svid)

        me = await client.whoami()
        print(f"org trust_tier is now {me.trust_tier}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: python {sys.argv[0]} <config_dir> <jwt-svid>")
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
