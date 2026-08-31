"""``read_group`` refuses a read that is about another group.

This is the read every MLS flow starting from a bare group id comes through, and
:func:`rine._mls.join.install_mls_state` scopes its Welcome pass by the id on
what it returned. Before the check, a server answering ``GET /groups/X`` with a
body naming Y made that scope match no refusal at all: the pass withheld a
Welcome this client had REFUSED instead of raising it, and the join reported
success holding no MLS state.

The honest direction is tested too, and it is the one that matters more — a
check that refuses legitimate reads is worse for every user than the answer it
rejects.

The client is a stub rather than a real ``SyncHttpClient``: ``read_group`` uses
exactly one method on it, and standing up auth and a transport mock would test
those instead of this.

TypeScript twin: ``rine-ts-sdk/src/resources/groups-get-identity.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.api import read_group
from rine.errors import GroupIdentityMismatchError

AGENT_ID = "11111111-2222-3333-4444-555555555555"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_GROUP_ID = "cccccccc-dddd-eeee-ffff-000000000000"


class _Client:
    """Answers ``GET /groups/{id}`` with whichever id it was built with."""

    def __init__(self, answered_id: str) -> None:
        self.answered_id = answered_id
        self.paths: list[str] = []

    def get(self, path: str, **_: Any) -> dict[str, object]:
        self.paths.append(path)
        return {
            "id": self.answered_id,
            "name": "dev",
            "handle": "#dev@acme.rine.network",
            "created_at": "2026-08-03T00:00:00Z",
            "mls_group_id": None,
            "mls_pending": False,
        }


def test_read_group_when_the_response_names_another_group_then_it_is_refused() -> None:
    """The refusal names both ids, so a caller can say what it asked and what it got."""
    client = _Client(OTHER_GROUP_ID)

    with pytest.raises(GroupIdentityMismatchError) as excinfo:
        read_group(client, AGENT_ID, GROUP_ID)

    assert excinfo.value.requested_group_id == GROUP_ID
    assert excinfo.value.answered_group_id == OTHER_GROUP_ID
    # The read did happen — this refuses the answer, not the request.
    assert client.paths == [f"/groups/{GROUP_ID}"]


def test_read_group_when_the_response_names_the_group_asked_for_then_it_is_returned() -> None:
    """The honest direction: an answer about the right group passes through."""
    assert str(read_group(_Client(GROUP_ID), AGENT_ID, GROUP_ID).id) == GROUP_ID


def test_read_group_when_the_response_differs_only_in_case_then_it_is_returned() -> None:
    """A UUID is case-insensitive; refusing on case alone would break honest servers."""
    group = read_group(_Client(GROUP_ID.upper()), AGENT_ID, GROUP_ID)

    assert str(group.id).lower() == GROUP_ID.lower()
