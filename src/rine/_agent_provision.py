"""Agent create and rotate on the org-root tree.

Both derive the agent's keys from the custody of its branch, sign its certificate
with that branch's key, and send the public halves. Neither stores a new secret:
the leaf files they write are a cache of a pure function of the root, which is
why :mod:`rine._recover` can rebuild them.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from rine._constants import MAIN_BRANCH
from rine._crypto._agent_keys import fetch_verified_keys_sync
from rine._crypto.certs import ChainError
from rine._crypto.keys import held_key_gen, save_agent_keys
from rine._custody import load_custody
from rine._org_certs import agent_create_request, agent_rotate_request
from rine._principal import agent_principal
from rine._profiles import DEFAULT_PROFILE, add_profile_if_absent
from rine._types import Profile
from rine._verify import apply_identity_verification
from rine.errors import AgentIdMismatchError
from rine.types import AgentRead

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._http import SyncHttpClient


def create_agent(
    client: SyncHttpClient,
    config_dir: str,
    owner_dir: str | None,
    name: str,
    human_oversight: bool = True,
    unlisted: bool = False,
    *,
    branch: str = MAIN_BRANCH,
    profile: str = DEFAULT_PROFILE,
    verify_identity: bool = False,
    svid: str | None = None,
    log: Callable[[str], None] | None = None,
) -> AgentRead:
    """Create an agent under ``branch`` with keys derived from the org root.

    The client mints the agent id, so the keys and the certificate are fixed
    before the server sees the request. The leaf keys are saved after the server
    accepts it, and the new agent is named in a runtime profile when ``profile``
    is free.

    Args:
        client: Authenticated HTTP client (as the org or the branch).
        config_dir: Runtime config directory receiving the leaf keys and profile.
        owner_dir: Owner directory holding ``root.key``.
        name: Agent name.
        human_oversight: Whether agent requires human oversight.
        unlisted: Whether agent is unlisted.
        branch: The branch the agent belongs to.
        profile: Name for the runtime profile written for the new agent, if free.
        verify_identity: Run SPIFFE identity verification after creation.
        svid: Caller-supplied JWT-SVID for the verification step. Supplying it
            implies verification even when ``verify_identity`` is False.
        log: Optional sink for verification diagnostics.

    Returns:
        Created AgentRead. When verification runs, ``identity`` (success) or
        ``identity_error`` (failure) is populated — a verify failure never undoes
        creation.

    Raises:
        ConfigError: This process holds no key material for ``branch``.
        AgentIdMismatchError: The server created the agent under another id than the
            one the client minted; no key, pin or profile is written.
    """
    custody = load_custody(config_dir, owner_dir, branch)
    minted_id = str(uuid.uuid4())
    request = agent_create_request(
        custody, minted_id, name, human_oversight=human_oversight, unlisted=unlisted
    )
    agent = AgentRead.model_validate(client.post("/agents", json_body=request.body))
    agent_id = str(agent.id)
    # The keys and the certificate are bound to the minted id: an agent the server
    # created under another id has none of them, so nothing is saved for it.
    if agent_id != minted_id:
        raise AgentIdMismatchError(minted_id, agent_id)
    save_agent_keys(config_dir, agent_id, request.keys)
    client.key_pins.pin_own_agent(agent_id, custody.org_id)

    entry = Profile(
        org_id=custody.org_id,
        principal=str(agent_principal(agent_id)),
        branch=branch,
        agent_id=agent_id,
    )
    if agent.poll_url:
        entry["poll_url"] = agent.poll_url
    add_profile_if_absent(config_dir, profile, entry)

    # Publish an initial batch of MLS KeyPackages so the agent can be added to
    # groups from birth — without them, the first invite fails with "No key
    # packages available". Best-effort: a failure here must never undo agent
    # creation, and the next MLS operation replenishes.
    from rine._mls import replenish_mls_key_packages

    replenish_mls_key_packages(client, config_dir, agent_id)

    apply_identity_verification(client, agent, verify=verify_identity, svid=svid, log=log)
    return agent


def rotate_agent_keys(
    client: SyncHttpClient, config_dir: str, owner_dir: str | None, agent_id: str
) -> AgentRead:
    """Rotate an agent to its next key generation.

    The branch and the current generation come from ``GET /agents/{id}/keys``,
    chain-verified like every other key read, and the next generation is derived
    from the org's custody for that branch. Keys are a pure function of the root,
    so an unchecked answer would make the client re-derive and certify a
    generation that was already superseded, or place the agent in another
    branch: the answer is checked against this device before anything is signed.

    Raises:
        ConfigError: This process holds no key material for the agent's branch.
        ChainError: The key read does not chain to this device's org, or reports an older
            generation than the leaf keys held on this device.
    """
    current = fetch_verified_keys_sync(client, agent_id)
    held = held_key_gen(config_dir, agent_id)
    if held is not None and current.key_gen < held:
        raise ChainError(
            f"the server reports key generation {current.key_gen}, older than the {held} "
            "held on this device"
        )
    custody = load_custody(config_dir, owner_dir, current.branch)
    if current.org_id != custody.org_id:
        raise ChainError(
            f"the key read chains to org {current.org_id}, "
            f"not to this device's org {custody.org_id}"
        )
    request = agent_rotate_request(custody, agent_id, current.key_gen + 1)
    agent = AgentRead.model_validate(
        client.post(f"/agents/{agent_id}/keys", json_body=request.body)
    )
    save_agent_keys(config_dir, agent_id, request.keys)
    return agent
