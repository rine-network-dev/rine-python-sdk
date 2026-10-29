"""Recovery from the 24-word phrase.

Ports rine-core's ``recover.ts``; the closed-group reseat of step 6 is
:mod:`rine._recover_reseat`. The phrase is never echoed: no error or report
string contains any of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rine._config import cache_token
from rine._crypto.derive_nodes import derive_branch, derive_org
from rine._crypto.keys import save_agent_keys
from rine._crypto.org_words import org_words
from rine._crypto.phrase import entropy_from_phrase
from rine._custody import Signer
from rine._http import _USER_AGENT, SyncHttpClient, _check_response, _fetch_oauth_token
from rine._mls.escrow_gap_list import GapMarker, list_gap_markers
from rine._owner import assert_fresh_owner_dir, resolve_owner_dir, save_root
from rine._principal import org_principal
from rine._profiles import DEFAULT_PROFILE, add_profile_if_absent
from rine._recover_agents import AgentRecovery, AgentRecoveryStatus, check_agent
from rine._recover_reseat import GroupReseat, reseat_closed_groups
from rine._types import Profile
from rine.errors import AuthenticationError, ConfigError, names_clock_skew

if TYPE_CHECKING:
    from collections.abc import Callable

NO_ORG_FOR_PHRASE = "no org matches this phrase: check each word, or the org was erased"

RECOVERY_NOTES: tuple[str, ...] = (
    "Closed-group seats are restored from the current epoch on. Your local copy of earlier "
    "closed-group messages is gone; the org reader still shows every escrowed epoch.",
    "Sender-key open groups redistribute keys on the next send.",
    "Wallet keys are random and are not recovered.",
    "1:1 history at every generation is readable again.",
)


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    """What a recovery did, and what the user must be told."""

    org_id: str
    org_words: str
    branches: list[str]
    agents: list[AgentRecovery]
    closed_groups: list[GroupReseat]
    gap_markers: list[GapMarker]
    """Every escrow gap marker on disk for the restored agents, not only this run's."""
    notes: tuple[str, ...] = field(default=RECOVERY_NOTES)


def _reseat_restored(
    api_url: str,
    config_dir: str,
    owner_dir: str,
    profile: str,
    restored: list[str],
) -> list[GroupReseat]:
    """Step 6, acting as the org through the profile and token just written."""
    client = SyncHttpClient(
        config_dir=config_dir, api_url=api_url, owner_dir=owner_dir, profile=profile
    )
    try:
        client.pin_own_agents(restored)
        return reseat_closed_groups(client, config_dir, restored)
    finally:
        client.close()


def recover_org(
    api_url: str,
    config_dir: str,
    phrase: str,
    *,
    owner_dir: str | None = None,
    profile: str = DEFAULT_PROFILE,
    on_org_words: Callable[[str], None] | None = None,
) -> RecoveryReport:
    """Rebuild an org and its agents from the recovery phrase.

    ``on_org_words`` runs before any network call so the user can check the words
    against a record. Nothing is written until the server has confirmed the org
    and every agent was checked.

    Args:
        api_url: API base URL.
        config_dir: Runtime config directory receiving each agent's leaf keys.
        phrase: The 24-word recovery phrase.
        owner_dir: Owner directory to receive ``root.key``; ``RINE_OWNER_DIR`` or
            ``~/.config/rine-owner`` when omitted.
        profile: Name of the org profile written to the owner dir.
        on_org_words: Called with the 8 org verification words before the first request.

    Returns:
        A report with one entry per agent: restored, or mismatched with the reason.

    Raises:
        ConfigError: The owner dir is unsafe or holds an org, or no org matches the phrase.
        PhraseError: The phrase is not 24 valid BIP39 words.
    """
    import httpx

    owner = owner_dir or resolve_owner_dir()
    assert_fresh_owner_dir(owner, config_dir)
    root = entropy_from_phrase(phrase)
    org = derive_org(root)
    words = org_words(org.org_id)
    if on_org_words:
        on_org_words(words)

    signer = Signer(org_principal(org.org_id), org.ed_seed)
    with httpx.Client(base_url=api_url, timeout=60, headers={"User-Agent": _USER_AGENT}) as http:
        try:
            access_token, expires_in = _fetch_oauth_token(http, api_url, signer)
        except AuthenticationError as exc:
            if names_clock_skew(exc.raw):
                raise
            raise ConfigError(NO_ORG_FOR_PHRASE) from None
        http.headers["Authorization"] = f"Bearer {access_token}"

        views = _check_response(http.get("/orgs/me/branches"))["branches"]
        agents = _check_response(http.get("/agents"))["items"]
        branches = {
            view["name"]: derive_branch(org.r_read, org.r_sign, view["name"]) for view in views
        }
        checked = [check_agent(http, config_dir, org.org_id, branches, a) for a in agents]

    recovered = [c.recovery for c in checked]
    for c in checked:
        if c.keys is not None:
            save_agent_keys(config_dir, c.recovery.agent_id, c.keys)
    save_root(owner, root)
    add_profile_if_absent(
        owner, profile, Profile(org_id=org.org_id, principal=str(signer.principal))
    )
    cache_token(owner, str(signer.principal), access_token, expires_in)
    restored = [r.agent_id for r in recovered if r.status is AgentRecoveryStatus.RESTORED]
    closed_groups = _reseat_restored(api_url, config_dir, owner, profile, restored)
    return RecoveryReport(
        org_id=org.org_id,
        org_words=words,
        branches=[view["name"] for view in views],
        agents=recovered,
        closed_groups=closed_groups,
        gap_markers=[m for agent_id in restored for m in list_gap_markers(config_dir, agent_id)],
    )


async def async_recover_org(
    api_url: str,
    config_dir: str,
    phrase: str,
    *,
    owner_dir: str | None = None,
    profile: str = DEFAULT_PROFILE,
    on_org_words: Callable[[str], None] | None = None,
) -> RecoveryReport:
    """Async variant of :func:`recover_org`, run on a worker thread (it is key derivation)."""
    import asyncio

    return await asyncio.to_thread(
        recover_org,
        api_url,
        config_dir,
        phrase,
        owner_dir=owner_dir,
        profile=profile,
        on_org_words=on_org_words,
    )
