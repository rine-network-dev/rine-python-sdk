"""Handle and agent resolution — WebFinger, UUID, and bare name lookup.

Resolves agent identifiers in multiple formats:
- UUID: passed through directly
- Handle (``name@org`` or ``name@org.rine.network``): resolved via WebFinger
- Bare name: matched case-insensitively against org's agents
"""

from __future__ import annotations

import re
from typing import Any

from rine._logging import logger
from rine.errors import ConfigError, NotFoundError

_DEFAULT_DOMAIN = ".rine.network"


def normalize_handle(handle: str) -> str:
    """Append .rine.network when the domain part has no dots (short-form handle)."""
    at_idx = handle.rfind("@")
    if at_idx == -1:
        return handle
    domain = handle[at_idx + 1 :]
    if "." in domain:
        return handle
    return handle + _DEFAULT_DOMAIN


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_UUID_ALIAS_RE = re.compile(
    r"/agents/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I
)


def is_uuid(value: str) -> bool:
    """Check if a string is a valid UUID."""
    return bool(UUID_RE.match(value))


def is_bare_agent_name(value: str) -> bool:
    """Check if a value is a bare agent name (no @ and not UUID)."""
    return "@" not in value and not is_uuid(value)


def _resolve_handle_from_webfinger(data: dict[str, Any]) -> str | None:
    """Extract agent UUID from WebFinger response aliases."""
    for alias in data.get("aliases", []):
        m = _UUID_ALIAS_RE.search(str(alias))
        if m:
            return m.group(1)
    return None


def resolve_handle_sync(api_url: str, handle: str) -> str:
    """Resolve a handle to agent UUID via WebFinger (sync).

    Args:
        api_url: API base URL.
        handle: Agent handle (e.g. ``name@org`` or ``name@org.rine.network``).

    Returns:
        Agent UUID string, or original handle if WebFinger fails.
    """
    import httpx

    handle = normalize_handle(handle)
    try:
        resp = httpx.get(
            f"{api_url}/.well-known/webfinger",
            params={"resource": f"acct:{handle}"},
            timeout=10,
        )
        if resp.is_success:
            uuid = _resolve_handle_from_webfinger(resp.json())
            if uuid:
                return uuid
    except Exception:
        logger.debug("WebFinger resolution failed for %s", handle, exc_info=True)
    return handle


async def resolve_handle_async(api_url: str, handle: str) -> str:
    """Resolve a handle to agent UUID via WebFinger (async).

    Args:
        api_url: API base URL.
        handle: Agent handle (e.g. ``name@org`` or ``name@org.rine.network``).

    Returns:
        Agent UUID string, or original handle if WebFinger fails.
    """
    import httpx

    handle = normalize_handle(handle)
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.get(
                f"{api_url}/.well-known/webfinger",
                params={"resource": f"acct:{handle}"},
            )
            if resp.is_success:
                uuid = _resolve_handle_from_webfinger(resp.json())
                if uuid:
                    return uuid
    except Exception:
        logger.debug("WebFinger resolution failed for %s", handle, exc_info=True)
    return handle


def resolve_to_uuid_sync(api_url: str, value: str) -> str:
    """Resolve a value (UUID, handle, or bare name) to UUID (sync).

    Args:
        api_url: API base URL.
        value: UUID string, handle, or bare name.

    Returns:
        Agent UUID string.

    Raises:
        NotFoundError: If value format is unrecognizable.
    """
    if is_uuid(value):
        return value
    if "@" in value:
        return resolve_handle_sync(api_url, normalize_handle(value))
    raise NotFoundError(
        f"Invalid agent identifier '{value}': expected a UUID or handle (e.g., 'agent@org')"
    )


async def resolve_to_uuid_async(api_url: str, value: str) -> str:
    """Resolve a value to UUID (async).

    Args:
        api_url: API base URL.
        value: UUID string, handle, or bare name.

    Returns:
        Agent UUID string.

    Raises:
        NotFoundError: If value format is unrecognizable.
    """
    if is_uuid(value):
        return value
    if "@" in value:
        return await resolve_handle_async(api_url, normalize_handle(value))
    raise NotFoundError(
        f"Invalid agent identifier '{value}': expected a UUID or handle (e.g., 'agent@org')"
    )


def resolve_bare_name(agents: list[dict[str, Any]], name: str) -> str:
    """Resolve a bare agent name against a list of agents (case-insensitive).

    Args:
        agents: List of agent dicts with ``id`` and ``name`` fields.
        name: Bare agent name to match.

    Returns:
        Agent UUID.

    Raises:
        NotFoundError: If no agent matches.
    """
    lower = name.lower()
    for agent in agents:
        if agent.get("name", "").lower() == lower:
            return str(agent["id"])
    agent_list = "\n  ".join(
        f"- {a.get('name', '?')} ({a.get('handle', a.get('id', '?'))})" for a in agents
    )
    raise NotFoundError(f"No agent named '{name}'. Available agents:\n  {agent_list}")


def match_group_by_local_name(groups: list[dict[str, Any]], name: str) -> str:
    """Resolve a bare group name against the caller's groups by local part.

    A bare name (no ``@``, not a UUID, optional leading ``#``) is matched against
    each group's handle local part — ``handle.split("@")[0].lstrip("#")`` — because
    the server's ``GET /groups?handle=`` only matches a *full* ``#name@org`` handle,
    so a bare ``#name`` returns nothing. Listing the caller's own groups and
    comparing the local part lets ``invite``/``remove``/etc. accept a bare name,
    matching ``client.groups.list()`` and the crewai inspect tool.

    Args:
        groups: List of group dicts with ``id`` and ``handle`` fields (the
            caller's own groups, fetched with the acting agent's header).
        name: Bare group name to match (leading ``#`` is ignored).

    Returns:
        Group UUID.

    Raises:
        NotFoundError: If no group matches.
        ConfigError: If the name matches more than one group (ambiguous).
    """
    want = name.lstrip("#")
    matches = [g for g in groups if str(g.get("handle", "")).split("@")[0].lstrip("#") == want]
    if len(matches) == 1:
        return str(matches[0]["id"])
    if len(matches) > 1:
        handles = ", ".join(str(g.get("handle", g.get("id", "?"))) for g in matches)
        raise ConfigError(
            f"Group name '{name}' is ambiguous — it matches multiple groups: "
            f"{handles}. Use the full handle (#name@org) or the group UUID."
        )
    raise NotFoundError(f"Group not found: {name}")


def resolve_agent(
    agents: list[dict[str, Any]],
    explicit: str | None = None,
    as_flag: str | None = None,
) -> str:
    """Resolve an agent from context, with priority logic.

    Priority: explicit parameter > as_flag > single-agent auto-select.

    Args:
        agents: List of org's agents.
        explicit: Explicit agent identifier (UUID, handle, or name).
        as_flag: Agent specified via ``--as`` flag or ``agent`` parameter.

    Returns:
        Agent UUID.

    Raises:
        ConfigError: If disambiguation is needed.
    """
    target = explicit or as_flag
    if target:
        if is_uuid(target):
            return target
        return resolve_bare_name(agents, target)

    if len(agents) == 1:
        return str(agents[0]["id"])

    if len(agents) == 0:
        raise ConfigError("No agents found. Create one: client.create_agent('my-agent')")

    agent_list = "\n  ".join(
        f"- {a.get('name', '?')} ({a.get('handle', a.get('id', '?'))})" for a in agents
    )
    raise ConfigError(
        f"Multiple agents found. Specify one:\n  {agent_list}\n\n"
        "Pass agent='name' or agent='uuid' to disambiguate."
    )
