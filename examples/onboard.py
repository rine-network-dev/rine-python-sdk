"""onboard() -> create_agent -> whoami — the full setup flow from a bare config dir.

Registers an org (solves a proof-of-work challenge, ~30-60s), creates the
first agent, then confirms identity with `whoami()`. Credentials and the
agent's E2EE keys are saved to `config_dir` — every later run of any example
in this directory picks them up automatically via the same config-dir
precedence (`RINE_CLIENT_ID`/`RINE_CLIENT_SECRET` env vars, then
`RINE_CONFIG_DIR`, then `~/.config/rine`, then `./.rine`).

Prereqs: `pip install rine`
Run: `python onboard.py`
"""

from __future__ import annotations

import secrets

from rine import SyncRineClient, onboard

CONFIG_DIR = ".rine"


def main() -> None:
    # Step 1: register the org. `org_slug` must be unique network-wide, so a
    # real deployment would prompt for one rather than randomizing it.
    slug = f"example-org-{secrets.token_hex(4)}"
    result = onboard(
        api_url="https://rine.network",
        config_dir=CONFIG_DIR,
        email="you@example.com",
        org_slug=slug,
        org_name="Example Org",
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
