"""An approving vote seats the applicant it just admitted, and says so honestly.

Before this, ``vote()`` posted the vote and stopped. A Python-stack agent casting
the deciding approve therefore seated the applicant in the **rine** group and left
them outside the **MLS** one, with no Welcome — they lost every message until
something else self-healed. The server holds no MLS keys, so the deciding voter is
the only client present that can mint the leaf.

The second half is the admitter's own state: a voter who joined by Welcome and has
never read the group holds nothing locally, which is the ordinary shape of a
``majority`` group. The add path installs that Welcome first, **scoped to the one
group it is establishing** — unscoped, the server picks which refusal is raised
through its own response ordering.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._mls import add_members as add_members_module
from rine._mls.admission import MlsAdmissionOutcome, MlsAdmissionResult
from rine.errors import ConflictError

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


class TestVoteSeatsTheApplicant:
    """The half of an approve that only a member's own client can perform."""

    @respx.mock
    def test_vote_when_an_approve_admits_the_applicant_then_they_are_seated_in_mls(
        self, sync_client, agent_id, seat_calls
    ):
        """The deciding voter mints the leaf, as itself, for the captured applicant."""
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")

        assert result.status == "approved"
        assert seat_calls == [(agent_id, GROUP_ID, (APPLICANT_ID,), {"X-Rine-Agent": agent_id})]
        # The seat outcome reaches the caller, because it is the only thing that
        # knows whether a leaf and a Welcome exist. Four connector surfaces
        # asserted both on the server's `approved` alone.
        assert result.mls_seated is True

    @respx.mock
    async def test_vote_when_an_async_approve_admits_the_applicant_then_they_are_seated(
        self, async_client, agent_id, seat_calls
    ):
        """The async client bridges to the same sync MLS layer, with the same result."""
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))

        result = await async_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")

        assert result.status == "approved"
        assert seat_calls == [(agent_id, GROUP_ID, (APPLICANT_ID,), {"X-Rine-Agent": agent_id})]
        assert result.mls_seated is True
        await async_client.close()

    @respx.mock
    def test_vote_when_the_request_is_still_pending_then_nobody_is_seated(
        self, sync_client, agent_id, seat_calls
    ):
        """An approve below the threshold admits nobody, so it mints no leaf."""
        pending = {**_APPROVED, "status": "pending"}
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=pending))

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")
        assert result.status == "pending"
        assert seat_calls == []
        # No seat was attempted at all, which is a different fact from one that
        # was attempted and did not happen.
        assert result.mls_seated is None

    @respx.mock
    def test_vote_when_the_group_runs_sender_keys_then_no_seat_is_attempted(
        self, sync_client, agent_id, seat_calls
    ):
        """A sender-key group has no ratchet tree, so there is no leaf to mint."""
        _mock_server(agent_id, _SENDER_KEY_GROUP, httpx.Response(200, json=_APPROVED))

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")
        assert result.status == "approved"
        assert seat_calls == []
        # There is no leaf and no Welcome here, and a surface that says there is
        # has to be able to tell.
        assert result.mls_seated is False

    @respx.mock
    def test_vote_when_seating_fails_then_the_vote_still_stands(
        self, sync_client, agent_id, monkeypatch
    ):
        """The membership is already the server's; a failed leaf is retryable.

        Raising here would leave the caller unable to tell a refused vote from an
        admitted member, and ``resume_admission`` is the remedy for the leaf.
        """

        def _boom(*args, **kwargs):
            raise RuntimeError("commit refused")

        monkeypatch.setattr(add_members_module, "add_mls_group_members", _boom)
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")
        assert result.status == "approved"
        assert result.mls_seated is False

    @respx.mock
    def test_vote_when_the_applicant_gets_no_leaf_then_the_vote_does_not_claim_one(
        self, sync_client, agent_id, monkeypatch
    ):
        """A commit that landed is not the same fact as a leaf that was minted.

        An applicant whose KeyPackage pool was empty is skipped by an admission
        that otherwise succeeded, and reads nothing until somebody seats them.
        """
        monkeypatch.setattr(
            add_members_module, "add_mls_group_members", lambda *a, **k: _admission("skipped")
        )
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))

        assert sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve").mls_seated is False

    @respx.mock
    def test_vote_when_the_acting_agent_cannot_be_resolved_then_the_vote_still_returns(
        self, sync_client, agent_id, seat_calls, monkeypatch
    ):
        """Resolving the acting agent is network work, and it sits INSIDE the guard.

        Outside it, a transient WebFinger or ``GET /agents`` failure raises out of
        a vote that has already landed: the caller cannot tell a refused vote from
        an irreversibly admitted member, and the retry answers 409, which reads as
        confirmation that nothing happened.
        """

        def _boom(*args, **kwargs):
            raise RuntimeError("webfinger timeout")

        monkeypatch.setattr(type(sync_client), "_resolve_agent_id", _boom)
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")
        assert result.status == "approved"
        assert result.mls_seated is False
        assert seat_calls == []

    @respx.mock
    def test_vote_when_the_queue_read_fails_then_the_vote_is_still_cast(
        self, sync_client, agent_id, seat_calls
    ):
        """The pre-vote capture belongs to the seat, not to the vote.

        Unguarded, a transient 5xx or a group rate limit on ``GET /requests``
        aborts the whole approve before it is cast, and the caller cannot tell
        that from a refused vote. The vote is the caller's intent; the leaf is
        the retryable half, and ``resume_admission`` is its remedy.
        """
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=_APPROVED))
        respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(503, json={"detail": "unavailable"})
        )

        result = sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")

        assert result.status == "approved"
        assert seat_calls == []
        # Admitted, and this client never learned whom — so it says so.
        assert result.mls_seated is False

    @respx.mock
    def test_vote_when_the_server_refuses_the_vote_then_nobody_is_seated(
        self, sync_client, agent_id, seat_calls
    ):
        """A vote that never landed admits nobody, so it must mint no leaf."""
        _mock_server(agent_id, _MLS_GROUP, httpx.Response(409, json={"detail": "Already voted"}))

        with pytest.raises(ConflictError):
            sync_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")
        assert seat_calls == []


class TestAdmitterState:
    """The add path installs the admitter's own pending Welcome first."""

    @pytest.fixture
    def probe(self, monkeypatch):
        """Record the Welcome install, then stop the add before it opens a store."""
        installs: list[dict] = []

        def _welcomes(client, config_dir, agent_id, *, for_group=None):
            installs.append({"agent_id": agent_id, "for_group": for_group})
            return None

        def _stop(*args, **kwargs):
            raise RuntimeError("stop-after-ensure")

        monkeypatch.setattr(add_members_module, "process_mls_welcomes", _welcomes)
        monkeypatch.setattr(add_members_module, "replenish_mls_key_packages", lambda *a, **k: None)
        monkeypatch.setattr(add_members_module, "read_group", _stop)
        return installs

    def _add(self, monkeypatch, holds: bool):
        monkeypatch.setattr(add_members_module, "holds_mls_state", lambda *a, **k: holds)
        with pytest.raises(RuntimeError, match="stop-after-ensure"):
            add_members_module.add_mls_group_members(
                object(), "/cfg", "agent-1", GROUP_ID, [APPLICANT_ID]
            )

    def test_add_when_the_admitter_holds_no_state_then_its_welcome_is_installed_scoped(
        self, monkeypatch, probe
    ):
        """A voter who joined by Welcome and never read the group can still admit."""
        self._add(monkeypatch, holds=False)

        # Scoped, and to THIS group: unscoped, the server decides which refusal
        # is raised by ordering its own response array.
        assert probe == [{"agent_id": "agent-1", "for_group": GROUP_ID}]

    def test_add_when_the_admitter_already_holds_state_then_no_welcome_is_fetched(
        self, monkeypatch, probe
    ):
        """The fetch is destructive, so it is never made speculatively."""
        self._add(monkeypatch, holds=True)

        assert probe == []
