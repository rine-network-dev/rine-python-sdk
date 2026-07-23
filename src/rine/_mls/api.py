"""The MLS control-plane endpoints.

Every blob these carry is encoded by :mod:`rine._mls.wire` — standard base64,
not the base64url the rest of the SDK uses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._mls.wire import mls_from_base64, mls_to_base64
from rine.errors import ConflictError
from rine.types import GroupRead


@dataclass(frozen=True)
class MlsMemberStatus:
    """A group member and whether the server holds a KeyPackage for them."""

    agent_id: str
    has_key_package: bool


@dataclass(frozen=True)
class MlsWelcome:
    """A Welcome addressed to one added member, paired by agent."""

    agent_id: str
    welcome: bytes


@dataclass(frozen=True)
class MlsWelcomeDelivery:
    """One Welcome the server is holding for this agent, and its group."""

    id: str
    group_id: str
    welcome: bytes


@dataclass(frozen=True)
class MlsGroupInfo:
    """The group's published external-join capability, and the epoch it is for.

    The epoch is the group's last *confirmed* one, which is what makes it the
    signal a member compares its own local epoch against.
    """

    blob: bytes | None
    epoch: int | None


@dataclass(frozen=True)
class MlsCommit:
    """Everything one epoch-advancing commit publishes."""

    commit: bytes
    group_info: bytes
    epoch: int
    cipher_suite: int
    welcomes: tuple[MlsWelcome, ...] = ()


def read_group(client: Any, agent_id: str, group_id: str) -> GroupRead:
    """Read a group as one of its members.

    Every MLS flow that starts from a bare group id comes through here: the
    group's own ``mls_cipher_suite`` decides which suite the MLS client is opened
    on, and a group created on the classical suite is unreadable through a client
    opened on the default one.
    """
    return GroupRead.model_validate(
        client.get(f"/groups/{group_id}", extra_headers={"X-Rine-Agent": agent_id})
    )


def upload_key_packages(client: Any, agent_id: str, packages: list[bytes]) -> int:
    """Publish an agent's KeyPackages so peers can add it to groups.

    Args:
        client: Sync HTTP client.
        agent_id: Agent UUID whose pool is being topped up.
        packages: KeyPackage blobs, already capped by the core.

    Returns:
        How many the server stored.
    """
    data = client.post(
        f"/agents/{agent_id}/mls/key-packages",
        json_body={"packages": [mls_to_base64(p) for p in packages]},
    )
    stored: int = data["stored"]
    return stored


def claim_key_packages(
    client: Any, agent_id: str, count: int, extra_headers: dict[str, str]
) -> list[bytes]:
    """Claim up to ``count`` KeyPackages belonging to ``agent_id`` in one request.

    The claim is destructive server-side (RFC 9420 single-use): every package
    returned is marked consumed and can never be handed out again, so what comes
    back must be used or discarded — never claimed speculatively.

    Raises:
        ConflictError: The agent's pool is already empty (409 "No key packages
            available").

    Returns:
        The claimed KeyPackage blobs, fewer than ``count`` when the pool ran dry
        mid-claim.
    """
    data = client.get(
        f"/agents/{agent_id}/mls/key-packages",
        params={"count": count},
        extra_headers=extra_headers,
    )
    return [mls_from_base64(p) for p in data.get("packages", [])]


def claim_key_package(client: Any, agent_id: str, extra_headers: dict[str, str]) -> bytes | None:
    """Claim one KeyPackage belonging to ``agent_id``.

    The claim is destructive server-side (RFC 9420 single-use), so exactly one is
    taken and it must be used or discarded — never claimed speculatively.

    Returns:
        The KeyPackage blob, or ``None`` when the agent's pool is empty.
    """
    try:
        packages = claim_key_packages(client, agent_id, 1, extra_headers)
    except ConflictError:
        # 409 "No key packages available" — the agent has published none, or a
        # concurrent add consumed the last one.
        return None
    return packages[0] if packages else None


def fetch_welcomes(client: Any, agent_id: str) -> list[MlsWelcomeDelivery]:
    """Take every Welcome the server is holding for this agent.

    **One-shot and destructive**: the server marks each returned Welcome consumed
    in the same transaction that returns it, so this call is the only chance to
    read these bytes. The caller persists them before doing anything else with
    them.

    A Welcome the server could not associate with a group is skipped: local MLS
    state is keyed by the rine group UUID, so there is nowhere to put it.
    """
    data = client.get(f"/agents/{agent_id}/mls/welcomes")
    return [
        MlsWelcomeDelivery(
            id=str(w["id"]), group_id=str(w["group_id"]), welcome=mls_from_base64(w["blob"])
        )
        for w in data.get("welcomes", [])
        if w.get("group_id")
    ]


def fetch_group_info(client: Any, group_id: str, extra_headers: dict[str, str]) -> MlsGroupInfo:
    """Fetch the group's current published GroupInfo, the external-join capability.

    Only a *confirmed* GroupInfo is served; a group whose latest one is still
    awaiting a peer ACK raises ``ConflictError`` with the ``pending_confirmation``
    code instead, which is a retry rather than a refusal.

    Returns:
        The blob and its epoch; ``blob`` is ``None`` when the group has published
        none.
    """
    data = client.get(f"/groups/{group_id}/mls/group-info", extra_headers=extra_headers)
    blob = data.get("group_info")
    epoch = data.get("epoch")
    return MlsGroupInfo(
        blob=mls_from_base64(blob) if blob else None,
        epoch=None if epoch is None else int(epoch),
    )


def mls_init(client: Any, group_id: str, extra_headers: dict[str, str]) -> list[MlsMemberStatus]:
    """Open the MLS init window for a group and report each member's readiness.

    Only the group's designated admin may do this, and it freezes the group
    (``mls_pending``) until the init commit lands.

    Returns:
        One status per member, including the caller.
    """
    data = client.post(f"/groups/{group_id}/mls/init", json_body={}, extra_headers=extra_headers)
    return [
        MlsMemberStatus(agent_id=str(m["agent_id"]), has_key_package=bool(m["has_key_package"]))
        for m in data.get("members", [])
    ]


def mls_commit(
    client: Any, group_id: str, commit: MlsCommit, extra_headers: dict[str, str]
) -> int:
    """Publish a commit, its Welcomes and the epoch's fresh GroupInfo.

    Returns:
        The epoch the server committed to.
    """
    body: dict[str, Any] = {
        "commit": mls_to_base64(commit.commit),
        "group_info": mls_to_base64(commit.group_info),
        "cipher_suite": commit.cipher_suite,
        "epoch": commit.epoch,
        "welcomes": [
            {"agent_id": w.agent_id, "welcome": mls_to_base64(w.welcome)} for w in commit.welcomes
        ],
    }
    data = client.post(
        f"/groups/{group_id}/mls/commit", json_body=body, extra_headers=extra_headers
    )
    epoch = data.get("epoch")
    return commit.epoch if epoch is None else int(epoch)
