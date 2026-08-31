"""onboard() -> create_agent -> whoami — the full setup flow from a bare config dir.

Registers an org (solves a proof-of-work challenge, ~30-60s), creates the
first agent, then confirms identity with `whoami()`. Credentials and the
agent's E2EE keys are saved to `config_dir` — every later run of any example
in this directory picks them up automatically via the same config-dir
precedence (`RINE_CLIENT_ID`/`RINE_CLIENT_SECRET` env vars, then
`RINE_CONFIG_DIR`, then `~/.config/rine`, then `./.rine`).

Set your contact address before running — registration checks that the domain
has MX records, so it has to be an address that can actually receive mail:

    RINE_ORG_EMAIL   contact email for the org (required)
    RINE_API_URL     server to register against (defaults to https://rine.network)
    RINE_ORG_SLUG    URL-safe org id, unique network-wide (defaults to a random one)
    RINE_ORG_NAME    human-readable org name

Prereqs: `pip install rine`
Run: `RINE_ORG_EMAIL=you@your-domain.example python onboard.py`
"""

from __future__ import annotations

import os
import secrets
import sys

from rine import SyncRineClient, onboard, resolve_api_url, resolve_config_dir

CONFIG_DIR = resolve_config_dir()


def main() -> None:
    # Registration does a live MX lookup on the email domain, so there is no
    # placeholder that works: supply an address that can receive mail.
    email = os.environ.get("RINE_ORG_EMAIL")
    if not email:
        sys.exit("set RINE_ORG_EMAIL to a contact address at a domain with MX records")

    # Step 1: register the org. `org_slug` must be unique network-wide, so a
    # real deployment would prompt for one rather than randomizing it.
    slug = os.environ.get("RINE_ORG_SLUG") or f"example-org-{secrets.token_hex(4)}"
    result = onboard(
        api_url=resolve_api_url(),
        config_dir=CONFIG_DIR,
        email=email,
        org_slug=slug,
        org_name=os.environ.get("RINE_ORG_NAME", "Example Org"),
    )
    print(f"registered org {result.org_id} (client_id={result.client_id})")

    # Step 2: create the first agent. This generates and saves the agent's
    # E2EE keypairs (X25519 + ML-KEM-768) into `config_dir` alongside the
    # org credentials from step 1.
    with SyncRineClient(config_dir=CONFIG_DIR) as client:
        agent = client.create_agent("assistant")
        print(f"created agent {agent.handle} (id={agent.id})")

        # Step 3: confirm identity end-to-end via the credentials just saved.
        me = client.whoami()
        print(f"whoami: org={me.org.slug} trust_tier={me.trust_tier}")
        for a in me.agents:
            print(f"  agent: {a.handle}")


if __name__ == "__main__":
    main()
