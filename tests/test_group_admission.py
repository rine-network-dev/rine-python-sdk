"""Founding and adding members in batches — the admission loop.

These drive the real ``rine-mls`` core and mock only the server, so a commit
asserted here is one the server would actually have received: the KeyPackages
are minted by real MLS clients and the Welcomes are real Welcomes.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from rine._constants import (
    MLS_FOUNDING_POST_BUDGET_B64,
    MLS_WELCOME_B64_BASE,
    MLS_WELCOME_B64_PER_MEMBER,
    MLS_WELCOMES_PER_COMMIT_MAX,
)
from rine._crypto.keys import save_agent_keys
from rine._mls import (
    add_mls_group_members,
    claim_founding_key_packages,
    init_mls_group,
    mls_founding_batch_sizes,
    open_mls_client,
)
from rine.errors import CryptoError
from rine.testing import WORLD

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
FOUNDER = "00000000-1111-2222-3333-444444444444"


_GROUP_READ = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": None,
    "mls_pending": False,
    "mls_cipher_suite": None,
}


def _peer(tmp_path, index: int) -> tuple[str, dict, bytes]:
    """A peer agent with real keys and one published KeyPackage.

    The keys are saved into the shared config dir the founder acts from, so the
    founder's MLS client admits the peer's leaf key: its allowed set is every
    agent whose keys live in ``<config_dir>/keys/``.
    """
    agent_id = f"aaaaaaaa-0000-4000-8000-{index:012d}"
    config_dir = str(tmp_path)
    save_agent_keys(config_dir, agent_id, WORLD.keys(agent_id))
    key_package = open_mls_client(config_dir, agent_id).generate_key_package()
    return agent_id, WORLD.keys_response(agent_id), key_package


class _Server:
    """The routes an admission touches, with the calls it made."""

    def __init__(self, peers: list[tuple[str, dict, bytes]]) -> None:
        self.packages = {a: kp for a, _, kp in peers}
        self.keys = {a: body for a, body, _ in peers}
        self.claims: list[list[str]] = []
        self.commits: list[dict] = []
        self.epoch = 0
        self.reject: set[str] = set()

    def install(
        self,
        *,
        members: list[str] | None = None,
        invited: list[str] | None = None,
        pending: list[str] | None = None,
        nominated: list[str] | None = None,
        group: dict | None = None,
    ):
        """Stand up the routes an admission touches.

        ``invited`` are agents an admin vouched for; ``pending`` are strangers
        who applied and are awaiting a vote; ``nominated`` are agents a member
        put forward, which are also awaiting a vote and also carry an
        ``invited_by``. All three are what ``?outstanding=live``
        returns, and the rows carry the ``status`` and ``invited_by`` the
        server's ``JoinRequestRead`` makes required — which is what tells them
        apart. A fixture that emitted ``agent_id`` alone could not express the
        difference, so it could not catch a client that admitted all of them.
        """
        respx.post(f"{API}/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        respx.post(f"{API}/agents/{FOUNDER}/mls/key-packages").mock(
            return_value=httpx.Response(201, json={"stored": 10})
        )
        respx.post(f"{API}/agents/mls/key-packages/claim").mock(side_effect=self._claim)
        respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(side_effect=self._commit)
        respx.get(f"{API}/agents/keys").mock(side_effect=self._agent_keys)
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200, json={"items": [{"agent_id": a} for a in (members or [FOUNDER])]}
            )
        )
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200, json=group or {**_GROUP_READ, "mls_group_id": "latch"}
            )
        )
        # An admission names its group by id, and the resolve matches that
        # id against the org's own roster first — an id no group of this org
        # carries is refused with the list rather than reaching the wire.
        respx.get(f"{API}/groups").mock(
            return_value=httpx.Response(
                200,
                json={"items": [group or {**_GROUP_READ, "mls_group_id": "latch"}]},
            )
        )
        live = (
            [{"agent_id": a, "status": "invited", "invited_by": FOUNDER} for a in (invited or [])]
            + [{"agent_id": a, "status": "pending", "invited_by": None} for a in (pending or [])]
            + [
                {"agent_id": a, "status": "pending", "invited_by": FOUNDER}
                for a in (nominated or [])
            ]
        )
        respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(200, json={"items": live})
        )
        return self

    def _claim(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["agent_ids"]
        self.claims.append(ids)
        return httpx.Response(
            200,
            json={
                "claims": [
                    {
                        "agent_id": a,
                        "packages": (
                            [base64.b64encode(self.packages[a]).decode()]
                            if a in self.packages
                            else []
                        ),
                    }
                    for a in ids
                ]
            },
        )

    def _commit(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.commits.append(body)
        named = {w["agent_id"] for w in body["welcomes"]} & self.reject
        if named:
            return httpx.Response(
                422,
                json={
                    "error": "welcome_recipient_rejected",
                    "detail": "recipients cannot be addressed",
                    "rejected": [{"agent_id": a, "reason": "not_enrolled"} for a in sorted(named)],
                },
            )
        self.epoch = body["epoch"]
        return httpx.Response(200, json={"epoch": self.epoch, "delivered_to": 0})

    def _agent_keys(self, request: httpx.Request) -> httpx.Response:
        ids = request.url.params["ids"].split(",")
        return httpx.Response(200, json={"keys": {a: self.keys[a] for a in ids if a in self.keys}})


def _init_roster(peers: list[tuple[str, str, bytes]]) -> None:
    respx.post(f"{API}/groups/{GROUP_ID}/mls/init").mock(
        return_value=httpx.Response(
            200,
            json={
                "mls_pending": True,
                "members": [
                    {"agent_id": FOUNDER, "has_key_package": True, "membership": "member"},
                    *(
                        {"agent_id": a, "has_key_package": True, "membership": "invited"}
                        for a, _, _ in peers
                    ),
                ],
            },
        )
    )


class TestBatchSizes:
    """b(N): the batch shrinks as the tree grows, because a Welcome carries it."""

    def test_founding_at_the_group_ceiling_takes_39_commits_seating_everyone(self):
        sizes = mls_founding_batch_sizes(499)

        assert sum(sizes) == 499
        assert len(sizes) == 39
        assert sizes[0] == MLS_WELCOMES_PER_COMMIT_MAX

    def test_every_batch_stays_within_the_post_budget(self):
        seated = 400
        for batch in mls_founding_batch_sizes(100, seated):
            seated += batch
            welcome = MLS_WELCOME_B64_PER_MEMBER * seated + MLS_WELCOME_B64_BASE
            assert welcome * (batch + 2) <= MLS_FOUNDING_POST_BUDGET_B64

    def test_a_bigger_tree_admits_a_smaller_batch(self):
        assert mls_founding_batch_sizes(64, 1)[0] > mls_founding_batch_sizes(64, 400)[0]

    def test_nobody_to_seat_is_no_commits(self):
        assert mls_founding_batch_sizes(0) == []


class TestFoundingWithManyMembers:
    @respx.mock
    def test_founding_a_40_member_group_seats_every_one_of_them(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, i) for i in range(40)]
        server = _Server(peers).install()
        _init_roster(peers)

        result = init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        assert result.added == 40
        assert result.commits > 1
        assert [o.status for o in result.outcomes] == ["added"] * 40
        seated = sum(len(c["welcomes"]) for c in server.commits)
        assert seated == 40
        assert all(len(c["welcomes"]) <= MLS_WELCOMES_PER_COMMIT_MAX for c in server.commits)

    @respx.mock
    def test_key_packages_are_claimed_per_batch_not_up_front(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, i) for i in range(40)]
        server = _Server(peers).install()
        _init_roster(peers)

        result = init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        # One claim per commit, each naming only that commit's members: a
        # founding refused at commit five must not have spent the whole roster's
        # one-time KeyPackages.
        assert len(server.claims) == result.commits
        assert [len(c) for c in server.claims] == [len(c["welcomes"]) for c in server.commits]

    @respx.mock
    def test_an_agent_with_no_key_package_is_skipped_not_fatal(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, i) for i in range(3)]
        server = _Server(peers).install()
        del server.packages[peers[1][0]]
        _init_roster(peers)

        result = init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        assert result.added == 2
        # One outcome per requested id, in the order they were named — not in
        # the order the loop happened to decide them.
        assert [o.agent_id for o in result.outcomes] == [a for a, _, _ in peers]
        assert [(o.agent_id, o.reason) for o in result.outcomes if o.status == "skipped"] == [
            (peers[1][0], "no_key_package")
        ]


class TestARejectedRecipient:
    @respx.mock
    def test_the_batch_drops_them_retries_once_and_reports_them(
        self, sync_client, tmp_config_dir, tmp_path, mls_escrow_stub
    ):
        peers = [_peer(tmp_path, i) for i in range(3)]
        server = _Server(peers).install()
        server.reject = {peers[1][0]}
        _init_roster(peers)

        result = init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        assert result.added == 2
        rejected = [o for o in result.outcomes if o.reason == "rejected_by_server"]
        assert [o.agent_id for o in rejected] == [peers[1][0]]
        # The batch, then the retry. Never a loop.
        assert len(server.commits) == 2
        # The accepted retry installed its epoch and escrowed it.
        assert mls_escrow_stub[-1] == (GROUP_ID, server.commits[-1]["epoch"])

    @respx.mock
    def test_a_drain_failure_after_the_server_seated_the_retry_is_raised_not_recorded(
        self, sync_client, tmp_config_dir, tmp_path, monkeypatch
    ):
        peers = [_peer(tmp_path, i) for i in range(3)]
        server = _Server(peers).install()
        server.reject = {peers[1][0]}
        _init_roster(peers)

        def _fail(*_args, **_kwargs):
            raise CryptoError("escrow seal failed")

        monkeypatch.setattr("rine._mls.admission_state.drain_escrow", _fail)

        # The retried commit was accepted, so those joiners are seated: the
        # failure is the caller's, and no one is ledgered as rejected for it.
        with pytest.raises(CryptoError, match="escrow seal failed"):
            init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})


class TestClaimingKeyPackages:
    @respx.mock
    def test_the_claim_is_chunked_at_the_servers_id_cap(self, sync_client):
        respx.post(f"{API}/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        route = respx.post(f"{API}/agents/mls/key-packages/claim").mock(
            return_value=httpx.Response(200, json={"claims": []})
        )

        claim_founding_key_packages(sync_client._http, [f"id-{i}" for i in range(250)])

        assert route.call_count == 2
        assert [len(json.loads(c.request.content)["agent_ids"]) for c in route.calls] == [200, 50]


class TestAddingToAnEstablishedGroup:
    @respx.mock
    def test_adding_members_seats_them_and_running_it_again_seats_nobody(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, i) for i in range(2)]
        later = [_peer(tmp_path, i) for i in range(10, 13)]
        _Server([*peers, *later]).install(
            members=[FOUNDER, *(a for a, _, _ in peers)],
            invited=[a for a, _, _ in later],
        )
        _init_roster(peers)
        init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        added = add_mls_group_members(
            sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, [a for a, _, _ in later]
        )
        assert added.added == 3
        assert added.epoch > 0

        # A resume over the whole population: everyone already holds a leaf.
        again = add_mls_group_members(
            sync_client._http,
            tmp_config_dir,
            FOUNDER,
            GROUP_ID,
            [FOUNDER, *(a for a, _, _ in peers), *(a for a, _, _ in later)],
        )
        assert again.added == 0
        assert {o.reason for o in again.outcomes} == {"already_in_group"}

    @respx.mock
    def test_the_outstanding_invitations_are_read_before_anyone_is_seated(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, 0)]
        joiner = _peer(tmp_path, 20)
        _Server([*peers, joiner]).install(members=[FOUNDER], invited=[joiner[0]])
        _init_roster(peers)
        init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        add_mls_group_members(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, [joiner[0]])

        requests = [c.request for c in respx.calls if "/requests" in str(c.request.url)]
        assert requests, "the tree read must ask for outstanding invitations"
        assert all(r.url.params["outstanding"] == "live" for r in requests)


@pytest.mark.parametrize("count", [1, 33])
@respx.mock
def test_founding_never_exceeds_the_servers_welcome_cap(
    sync_client, tmp_config_dir, tmp_path, count
):
    """33 is the size that used to fail outright: one commit, 33 Welcomes, 422."""
    peers = [_peer(tmp_path, i) for i in range(count)]
    server = _Server(peers).install()
    _init_roster(peers)

    result = init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

    assert result.added == count
    assert all(len(c["welcomes"]) <= MLS_WELCOMES_PER_COMMIT_MAX for c in server.commits)


def _agents_route() -> None:
    """The org's one agent, so the client can name who is acting."""
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": FOUNDER,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


class TestResumingAnAdmissionThatStopped:
    """A latched group whose roster is half-seated has a way forward."""

    @respx.mock
    def test_the_still_unseated_invitees_are_seated_and_a_second_run_seats_nobody(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        stranded = [_peer(tmp_path, i) for i in range(30, 33)]
        _Server(stranded).install(members=[FOUNDER], invited=[a for a, _, _ in stranded])
        _agents_route()
        _init_roster([])
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json={**_GROUP_READ, "mls_group_id": "latch"})
        )
        # The group was founded alone: its three invitees hold vouchers, a seat
        # each in the tree, and no leaf.
        init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        result = sync_client.groups.resume_admission(GROUP_ID)
        assert result.added == 3
        assert [o.status for o in result.outcomes if o.agent_id != FOUNDER] == ["added"] * 3

        again = sync_client.groups.resume_admission(GROUP_ID)
        assert again.added == 0
        assert {o.reason for o in again.outcomes} == {"already_in_group"}

    @respx.mock
    def test_a_pending_applicant_awaiting_a_vote_is_never_seated(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        """A stranger awaiting a vote must not be Welcomed into the tree.

        ``?outstanding=live`` is ``('pending', 'invited')``, so the set a resume
        reads to SIZE the tree is wider than the set it may ADMIT. A ``pending``
        row is a self-application with ``invited_by IS NULL``; Welcoming one
        hands the group's epoch secret to an agent the vote may then deny, and
        no route ever seats a denied applicant, so nothing would reclaim the
        leaf it consumed. The server refuses to offer them to ``/mls/init`` for
        exactly this reason — a client must not re-open it from the other end.
        """
        invitee = _peer(tmp_path, 40)
        stranger = _peer(tmp_path, 41)
        _Server([invitee, stranger]).install(
            members=[FOUNDER],
            invited=[invitee[0]],
            pending=[stranger[0]],
        )
        _agents_route()
        _init_roster([])
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json={**_GROUP_READ, "mls_group_id": "latch"})
        )
        init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        result = sync_client.groups.resume_admission(GROUP_ID)

        seated = {o.agent_id for o in result.outcomes if o.status == "added"}
        assert invitee[0] in seated, "the admin's invitee is entitled to a leaf"
        assert stranger[0] not in seated, (
            "a pending self-applicant was Welcomed into the ratchet tree before "
            "the vote that may deny them"
        )
        assert result.added == 1

    @respx.mock
    def test_a_nominated_agent_awaiting_a_vote_is_never_seated_either(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        """A nomination carries ``invited_by``, and is still not an invitation.

        This is the hole a nomination opens in the row split: before it, a ``pending``
        row always had ``invited_by IS NULL``, so a client keying the admit set
        off the inviter rather than the status happened to be right. It is no
        longer. A nomination is a request the electorate has yet to decide —
        Welcoming one hands the group's epoch secret to an agent that may be
        denied, and the vote is what seats a member.
        """
        invitee = _peer(tmp_path, 42)
        nominee = _peer(tmp_path, 43)
        _Server([invitee, nominee]).install(
            members=[FOUNDER],
            invited=[invitee[0]],
            nominated=[nominee[0]],
        )
        _agents_route()
        _init_roster([])
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json={**_GROUP_READ, "mls_group_id": "latch"})
        )
        init_mls_group(sync_client._http, tmp_config_dir, FOUNDER, GROUP_ID, {})

        result = sync_client.groups.resume_admission(GROUP_ID)

        seated = {o.agent_id for o in result.outcomes if o.status == "added"}
        assert invitee[0] in seated, "the admin's invitee is entitled to a leaf"
        assert nominee[0] not in seated, (
            "a nominee was Welcomed into the ratchet tree before the electorate "
            "voted on the nomination"
        )
        assert result.added == 1

    @respx.mock
    def test_a_group_that_was_never_founded_is_founded(
        self, sync_client, tmp_config_dir, tmp_path
    ):
        peers = [_peer(tmp_path, 40)]
        _Server(peers).install(group=_GROUP_READ)
        _agents_route()
        _init_roster(peers)

        result = sync_client.groups.resume_admission(GROUP_ID)

        assert result.added == 1

    @respx.mock
    def test_a_sender_key_group_says_there_is_no_tree_to_seat_anyone_in(self, sync_client):
        _Server([]).install(group={**_GROUP_READ, "enrollment_policy": "open"})
        _agents_route()

        with pytest.raises(ValueError, match="sender keys"):
            sync_client.groups.resume_admission(GROUP_ID)
