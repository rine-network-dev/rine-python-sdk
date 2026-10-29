"""Which MLS groups the server lists with an agent seated.

The read recovery's reseat and the rotation's seat sweep are both built on.
The TypeScript twin is ``seatedMlsGroups`` (``rine-core/src/mls-seated-groups.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._actor import AGENT_HEADER
from rine._resources.group_ops import unwrap_items
from rine.format import group_is_mls
from rine.types import GroupRead

if TYPE_CHECKING:
    from rine._http import SyncHttpClient


def seated_mls_groups(client: SyncHttpClient, agent_id: str) -> list[GroupRead]:
    """The MLS groups the server lists with ``agent_id`` seated, in listing order.

    The list is read AS the agent: the acting-agent header is what makes
    ``member_agent_ids`` answer "which of the caller's own agents hold a seat" for
    this one agent rather than for the caller's whole org. A group that is MLS but
    does not list the agent is one it cannot act in, and a group that lists the
    agent without MLS state has no ratchet tree to re-enter.

    A failed listing is not caught: the caller decides what an unreadable list
    means for its own outcome, and swallowing it here would turn a transport
    failure into "the agent is in no groups".
    """
    listed = unwrap_items(client.get("/groups", extra_headers={AGENT_HEADER: agent_id}))
    return [
        group
        for group in map(GroupRead.model_validate, listed)
        if group_is_mls(group) and agent_id in map(str, group.member_agent_ids)
    ]
