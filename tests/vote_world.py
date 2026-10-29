"""The mocked server, group payloads and seat recorder the vote suites share."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._mls import add_members as add_members_module
from rine._mls.admission import MlsAdmissionOutcome, MlsAdmissionResult

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
APPLICANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
REQUEST_ID = "dddddddd-eeee-ffff-0000-111111111111"

_SENDER_KEY_GROUP = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "majority",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": False,
    "mls_group_id": None,
    "mls_pending": False,
}
_MLS_GROUP = {**_SENDER_KEY_GROUP, "mls_enabled": True, "mls_group_id": "mls-latch"}

_REQUEST = {
    "id": REQUEST_ID,
    "group_id": GROUP_ID,
    "agent_id": APPLICANT_ID,
    "invited_by": None,
    "message": "Please let me in",
    "status": "pending",
    "expires_at": "2024-01-08T00:00:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "resolved_at": None,
    "your_vote": None,
}
_APPROVED = {"request_id": REQUEST_ID, "your_vote": "approve", "status": "approved"}


def _mock_server(agent_id: str, group: dict, vote_response: httpx.Response) -> None:
    """Everything a vote touches: auth, the acting agent, the queue, the group."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": agent_id,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "total": 1,
            },
        )
    )
    respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
        return_value=httpx.Response(200, json={"items": [_REQUEST], "total": 1})
    )
    # The vote names its group by id, and the resolve matches that id
    # against the org's own roster before anything else happens — an id no group
    # of this org carries is refused with the list instead of reaching the wire.
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [group]}))
    respx.get(f"{API}/groups/{GROUP_ID}").mock(return_value=httpx.Response(200, json=group))
    respx.post(f"{API}/groups/{GROUP_ID}/requests/{REQUEST_ID}/vote").mock(
        return_value=vote_response
    )


def _admission(status: str = "added") -> MlsAdmissionResult:
    """What a real add reports back for the one applicant it was asked to seat."""
    return MlsAdmissionResult(
        epoch=3,
        commits=1,
        added=1 if status == "added" else 0,
        outcomes=(
            MlsAdmissionOutcome(
                agent_id=APPLICANT_ID,
                status=status,
                reason=None if status == "added" else "no_key_package",
            ),
        ),
    )


@pytest.fixture
def seat_calls(monkeypatch):
    """Record every MLS add the vote path attempts, without running one."""
    calls: list[tuple] = []

    def _record(client, config_dir, agent_id, group_id, member_agent_ids, extra_headers=None):
        calls.append((agent_id, group_id, tuple(member_agent_ids), extra_headers))
        return _admission()

    monkeypatch.setattr(add_members_module, "add_mls_group_members", _record)
    return calls
