"""Reading a ``GET /whoami`` answer, shared by the async and the sync client."""

from __future__ import annotations

from typing import Any

from rine.errors import ConfigError, OrgMismatchError
from rine.types import WhoAmI, WhoAmIKind


def parse_whoami(data: dict[str, Any], *, local_org_id: str | None = None) -> WhoAmI:
    """Build the :class:`WhoAmI` a ``GET /whoami`` body describes.

    ``local_org_id`` is the org the local profile was created under. A server that
    answers as a different org is refused before anything else is read from it.

    A narrower principal (branch, agent, reader) that sees no agent still has an
    identity, since its org and principal are in the body: it gets an empty list.

    Raises:
        OrgMismatchError: ``local_org_id`` is given and the server names another org.
        ConfigError: The org principal has no agent yet, so there is no identity to report.
    """
    who = WhoAmI.model_validate({**data, "trust_tier": data["org"].get("trust_tier", 0)})
    if local_org_id is not None and str(who.org.id).lower() != local_org_id.lower():
        raise OrgMismatchError(local_org_id, str(who.org.id))
    if who.principal.kind is WhoAmIKind.ORG and not who.agents:
        raise ConfigError("No agents found. Create one: client.create_agent('my-agent')")
    return who
