"""Which principal a directory acts as, and which key signs for it.

Key material lives in two places. The owner dir holds ``root.key``, from which
the org and every branch beneath it derive. A runtime dir holds an agent's leaf
keys and, for a delegate, a branch's two secrets under ``branch/<name>/``.
:func:`resolve_auth` reads both and says who this process may act as.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rine._branch_custody import BranchSecrets, load_branch_files
from rine._crypto.derive import UUID_RE
from rine._crypto.derive_nodes import OrgNode, derive_branch, derive_org
from rine._crypto.keys import load_agent_keys
from rine._owner import load_root
from rine._principal import Principal, PrincipalKind, parse_principal
from rine._profiles import DEFAULT_PROFILE, get_profile, load_profiles
from rine.errors import ConfigError

if TYPE_CHECKING:
    from rine._types import Profile


@dataclass(frozen=True, slots=True)
class Signer:
    """A principal and the Ed25519 seed that signs its assertions."""

    principal: Principal
    seed: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class Custody:
    """An org's id and the branch it signs under: enough to mint or rotate agents."""

    org_id: str
    branch: BranchSecrets


@dataclass(frozen=True, slots=True)
class ResolvedAuth:
    """Who this directory acts as, and where that principal's token is cached."""

    signer: Signer
    org_id: str
    cache_dir: str


def load_org_from_owner(owner_dir: str | None) -> OrgNode | None:
    """The org derived from ``root.key``, or ``None`` for no dir or a dir without one."""
    root = None if owner_dir is None else load_root(owner_dir)
    return None if root is None else derive_org(root)


def _branch(config_dir: str, org: OrgNode | None, name: str) -> tuple[BranchSecrets, bool] | None:
    """A branch's secrets and whether they were derived from the root, files first."""
    held = load_branch_files(config_dir, name)
    if held is not None:
        return held, False
    if org is None:
        return None
    return BranchSecrets.from_node(derive_branch(org.r_read, org.r_sign, name)), True


def load_custody(config_dir: str, owner_dir: str | None, branch: str) -> Custody:
    """Custody of ``branch``: from ``root.key`` when the owner dir has one, else delegate files.

    Raises:
        ConfigError: This process holds no key material for the branch.
    """
    org = load_org_from_owner(owner_dir)
    if org is not None:
        return Custody(
            org.org_id, BranchSecrets.from_node(derive_branch(org.r_read, org.r_sign, branch))
        )
    held = load_branch_files(config_dir, branch)
    org_id = next(
        (p["org_id"] for p in load_profiles(config_dir).values() if p.get("branch") == branch),
        None,
    )
    if held is None or org_id is None:
        raise ConfigError(
            f"No key material for branch '{branch}': need root.key in the owner dir "
            "or branch key files in the config dir."
        )
    return Custody(org_id, held)


def local_agent_ids(config_dir: str) -> list[str]:
    """The agent ids whose leaf keys this config dir holds."""
    try:
        names = os.listdir(os.path.join(config_dir, "keys"))
    except FileNotFoundError:
        return []
    return [name for name in names if UUID_RE.match(name)]


def _signer_for(
    principal: Principal, config_dir: str, org: OrgNode | None
) -> tuple[Signer, bool] | None:
    """The signer for a principal, and whether its key came from ``root.key``."""
    kind = principal.kind
    if kind is PrincipalKind.AGENT:
        keys = load_agent_keys(config_dir, principal.ident)
        return Signer(principal, keys.signing.private_key), False
    if principal.branch is None:
        if org is None or org.org_id != principal.ident:
            return None
        seed = org.reader_seed if kind is PrincipalKind.READER else org.ed_seed
        return Signer(principal, seed), True
    found = _branch(config_dir, org, principal.branch)
    if found is None:
        return None
    secrets, from_root = found
    seed = secrets.reader_seed if kind is PrincipalKind.READER else secrets.ed_seed
    return Signer(principal, seed), from_root


def _choose_profile(
    config_dir: str, owner_dir: str | None, profile: str | None, owner_org: str | None
) -> Profile | None:
    """The profile to act as: the org's when the owner dir holds its root, by default.

    A named profile is looked up in the runtime dir first. The owner dir's
    profile applies to a runtime dir only when both name the same org, so a
    second org's runtime dir is never signed as the first org.
    """
    name = profile or DEFAULT_PROFILE
    runtime = get_profile(config_dir, name)
    owner = get_profile(owner_dir, name) if owner_dir and owner_org is not None else None
    if owner is not None and runtime is not None and runtime["org_id"] != owner["org_id"]:
        owner = None
    return (owner or runtime) if profile is None else (runtime or owner)


def _check_org_claim(
    entry: Profile, principal: Principal, org: OrgNode | None, from_root: bool
) -> None:
    """Refuse a profile whose org id disagrees with what the key material proves.

    The profile's ``org_id`` becomes the org every own agent is pinned to, so it
    must be the org the principal names and, when the key came from ``root.key``,
    the org that root derives.
    """
    if principal.kind is PrincipalKind.AGENT:
        return
    claimed = entry["org_id"]
    if principal.ident != claimed or (from_root and org is not None and org.org_id != claimed):
        raise ConfigError("The profile names an org that does not match its principal or root.")


def resolve_auth(
    config_dir: str, owner_dir: str | None, profile: str | None = None
) -> ResolvedAuth | None:
    """The signer for ``profile``, or ``None`` when this process holds no identity to act as.

    Raises:
        ConfigError: The profile's org id contradicts its principal or the root.
    """
    org = load_org_from_owner(owner_dir)
    entry = _choose_profile(config_dir, owner_dir, profile, None if org is None else org.org_id)
    if entry is None:
        return None
    principal = parse_principal(entry["principal"])
    found = _signer_for(principal, config_dir, org)
    if found is None:
        return None
    signer, from_root = found
    _check_org_claim(entry, principal, org, from_root)
    return ResolvedAuth(
        signer, entry["org_id"], owner_dir if from_root and owner_dir else config_dir
    )
