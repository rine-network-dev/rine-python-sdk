"""Tests for group operations — SyncGroups and AsyncGroups."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    save_agent_keys,
)
from rine.errors import AuthorizationError, ConflictError, NotFoundError
from rine.format import group_is_mls
from rine.types import (
    GroupRead,
    InviteResult,
    JoinedResult,
    JoinRequestRead,
    PendingJoinResult,
)

AGENT_ID = "00000000-1111-2222-3333-444444444444"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MEMBER_ID = "11111111-2222-3333-4444-555555555555"
REQUEST_ID = "99999999-8888-7777-6666-555555555555"
CONVERSATION_ID = "77777777-6666-5555-4444-333333333333"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "isolated": False,
    "vote_duration_hours": 72,
    "member_count": 2,
    "created_at": "2024-01-01T00:00:00Z",
}

# Open enrollment is the one policy the server refuses MLS on, so `create` founds
# nothing and has nothing to re-read.
_OPEN_GROUP_PAYLOAD = {**_GROUP_PAYLOAD, "enrollment_policy": "open"}

_AGENT_PAYLOAD = {
    "id": AGENT_ID,
    "name": "test-agent",
    "handle": "test-agent@myorg.rine.network",
    "human_oversight": True,
    "incoming_policy": "accept_all",
    "outgoing_policy": "send_all",
    "created_at": "2024-01-01T00:00:00Z",
}


def _mock_token() -> None:
    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )


def _mock_agents() -> None:
    respx.get("https://rine.network/agents").mock(
        return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD]})
    )


def _mock_group_read() -> None:
    """``GET /groups/{id}`` — the row every verb that names a group by id reads.

    Two callers, one route. ``create`` re-reads it because the MLS init latches
    ``mls_group_id`` server-side after the create response was minted; and it
    is also how a group UUID is RESOLVED, in place of the unpaginated roster
    match this rung used to spend.

    Distinct from :func:`_mock_groups_serverlike`, which answers the ``?handle=``
    filter the handle rungs use and the listing a refusal is composed from.
    """
    respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
    )


MLS_INIT_REFUSAL = "Only the designated admin may initialize MLS"


@pytest.fixture
def landed_mls_init(monkeypatch):
    """The MLS init a create runs succeeds, without running the native MLS core.

    ``init_mls_group`` is the boundary between the create path and the real MLS
    implementation; ``tests/test_mls_wiring.py`` drives that implementation for
    real. Replacing it here is what lets these tests state what ``create`` does
    with each init outcome, and mirrors the TypeScript SDK's
    ``resources/groups-create-mls.test.ts``, which mocks ``initMlsGroup`` at the
    same boundary for the same reason.

    Yields the founding calls, so a test can assert that a create founded
    nothing. The absence of the re-read is not that assertion: a create can skip
    the re-read because the founding FAILED, which is a different fact.
    """
    from rine._mls.admission import MlsAdmissionResult

    foundings: list[tuple[object, ...]] = []

    def _found(*args: object, **_kw: object) -> MlsAdmissionResult:
        foundings.append(args)
        return MlsAdmissionResult(epoch=1, commits=1, added=0, outcomes=())

    monkeypatch.setattr("rine._mls.group_init.init_mls_group", _found)
    return foundings


@pytest.fixture
def refused_mls_init(monkeypatch):
    """The server refuses the MLS init — the group is created regardless."""

    def _refuse(*_a, **_kw):
        raise AuthorizationError(MLS_INIT_REFUSAL)

    monkeypatch.setattr("rine._mls.group_init.init_mls_group", _refuse)


def _mock_groups_serverlike() -> None:
    """Mock ``GET /groups`` the way the real server filters by ``?handle=``.

    The server only matches a *full* ``#name@org`` handle. A bare ``#name`` query
    returns empty (this is the bug the fix works around), while an unfiltered list
    (no ``handle`` param) returns the caller's groups — so a bare name can only be
    resolved by listing and matching the handle's local part.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        handle = request.url.params.get("handle")
        if handle is None:
            return httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        if handle == _GROUP_PAYLOAD["handle"]:
            return httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        return httpx.Response(200, json={"items": []})

    respx.get("https://rine.network/groups").mock(side_effect=_handler)


_INVITE_PAYLOAD = {
    "id": REQUEST_ID,
    "group_id": GROUP_ID,
    "agent_id": AGENT_ID,
    "invited_by": OTHER_AGENT_ID,
    "message": "join us",
    "status": "invited",
    "created_at": "2024-01-01T00:00:00Z",
    "group_handle": "#test-group@myorg.rine.network",
    "group_name": "test-group",
}

# Server response shapes copied field-for-field from src/rine/api/group_schemas.py.

# GroupMemberRead — POST /groups/{id}/join returns this (200) on an immediate join.
_MEMBER_PAYLOAD = {
    "id": MEMBER_ID,
    "group_id": GROUP_ID,
    "agent_id": AGENT_ID,
    "role": "member",
    "joined_at": "2024-01-01T00:00:00Z",
    "agent_handle": "test-agent@myorg.rine.network",
}

# JoinRequestRead (status "pending") — POST /groups/{id}/join returns this (202)
# when a vote is required. The id field is ``id``, never ``request_id``.
_PENDING_REQUEST_PAYLOAD = {
    "id": REQUEST_ID,
    "group_id": GROUP_ID,
    "agent_id": AGENT_ID,
    "invited_by": None,
    "message": "please let me in",
    "status": "pending",
    "expires_at": "2024-01-08T00:00:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "resolved_at": None,
    "your_vote": None,
}

# JoinRequestRead (status "invited") — POST /groups/{id}/invite voucher (201) for
# closed/majority/unanimity groups.
_VOUCHER_PAYLOAD = {
    "id": REQUEST_ID,
    "group_id": GROUP_ID,
    "agent_id": OTHER_AGENT_ID,
    "invited_by": AGENT_ID,
    "message": "join us",
    "status": "invited",
    "expires_at": None,
    "created_at": "2024-01-01T00:00:00Z",
    "resolved_at": None,
    "your_vote": None,
}

# POST /groups/{id}/invite for an OPEN group (201) — no request id.
_OPEN_INVITE_PAYLOAD = {
    "status": "invited",
    "group_id": GROUP_ID,
    "agent_id": OTHER_AGENT_ID,
}


def _mock_invitee_keys(tmp_config_dir: str) -> None:
    """Mock the recipient (invitee) key endpoint so ``send`` can seal a DM."""
    keys = generate_agent_keys()
    save_agent_keys(tmp_config_dir, OTHER_AGENT_ID, keys)
    enc_jwk = encryption_public_key_to_jwk(keys.encryption.public_key)
    respx.get(f"https://rine.network/agents/{OTHER_AGENT_ID}/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "agent_id": OTHER_AGENT_ID,
                "encryption_public_key": enc_jwk,
                "signing_public_key": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
            },
        )
    )


def _mock_no_group_of_that_id(uuid: str) -> None:
    """Answer the group probe a UUID recipient costs, the way the real route answers it.

    ``send()`` offers a UUID to this org's groups before the agent namespace
    By ratified decision: ``GET /groups/{id}`` is org-scoped
    where ``GET /agents/{id}/keys`` is global, so asking the agent side first
    would prefer a stranger's namespace over the caller's own org's. An
    invitee's AGENT id names no group, the route 404s, and the send falls
    through to the 1:1 path — which is the whole of what these tests assert.
    """
    respx.get(f"https://rine.network/groups/{uuid}").mock(
        return_value=httpx.Response(404, json={"detail": "Group not found"})
    )


class TestSyncGroupsCreate:
    @respx.mock
    def test_create_returns_group_read(self, sync_client, landed_mls_init):
        _mock_token()
        _mock_agents()
        _mock_group_read()
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = sync_client.groups.create("test-group", visibility="private")

        assert isinstance(result, GroupRead)
        assert result.name == "test-group"
        assert result.enrollment_policy == "closed"
        assert result.mls_init is None

    @respx.mock
    def test_create_sends_correct_body(self, sync_client):
        _mock_token()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_OPEN_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", enrollment="open", visibility="public")

        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "my-group"
        assert body["enrollment_policy"] == "open"
        assert body["visibility"] == "public"

    @respx.mock
    def test_create_when_a_closed_group_latches_mls_returns_it_as_an_mls_group(
        self, sync_client, landed_mls_init
    ):
        """A freshly created closed group renders as MLS.

        The MLS latch lands after the create response is minted, so a
        create that did not re-read would hand every surface a brand-new MLS
        group that renders as sender-key.
        """
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200, json={**_GROUP_PAYLOAD, "mls_enabled": True, "mls_group_id": "mls-latch-abc"}
            )
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = sync_client.groups.create("test-group", visibility="private")

        assert reread.called
        assert result.mls_group_id == "mls-latch-abc"
        assert group_is_mls(result) is True
        assert result.mls_init is None

    @respx.mock
    def test_create_when_the_group_is_open_enrollment_skips_the_reread(self, sync_client):
        """An open-enrollment create costs no extra round trip.

        Open enrollment runs on sender keys — the server refuses MLS there — so
        nothing was founded and the create response is already the whole truth.
        """
        _mock_token()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_OPEN_GROUP_PAYLOAD)
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_OPEN_GROUP_PAYLOAD)
        )

        result = sync_client.groups.create("my-group", visibility="private", enrollment="open")

        assert result.enrollment_policy == "open"
        assert not reread.called
        # Nothing was attempted, so there is no failure to report either.
        assert result.mls_init is None

    @respx.mock
    def test_create_when_the_mls_init_fails_reports_it_and_skips_the_reread(
        self, sync_client, refused_mls_init, caplog
    ):
        """A failed init is handed back, not swallowed, and costs no round trip.

        The group exists on the sender-key path either way, so the create
        response is already the whole truth — re-reading it could only return
        the same object. The reason travels back on ``mls_init``, which callers
        detect by its presence rather than by matching the text.
        """
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        with caplog.at_level("WARNING"):
            result = sync_client.groups.create("test-group", visibility="private")

        assert str(result.id) == GROUP_ID
        assert not reread.called
        assert result.mls_init is not None
        assert MLS_INIT_REFUSAL in result.mls_init.reason
        assert group_is_mls(result) is False
        assert any("MLS init failed" in r.message for r in caplog.records)

    @respx.mock
    def test_create_when_the_reread_fails_returns_the_created_group(
        self, sync_client, landed_mls_init, caplog
    ):
        """A failed refresh never costs the caller the group they just created.

        The group exists server-side the moment the POST lands, so a transient
        failure on the cosmetic re-read must never take it away.
        """
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            side_effect=httpx.ConnectError("connection reset")
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        with caplog.at_level("WARNING"):
            result = sync_client.groups.create("test-group", visibility="private")

        assert isinstance(result, GroupRead)
        assert str(result.id) == GROUP_ID
        assert result.handle == _GROUP_PAYLOAD["handle"]
        # The init landed; only the cosmetic read failed.
        assert result.mls_init is None
        assert any("was created" in r.message for r in caplog.records)

    @respx.mock
    def test_create_includes_description_when_set(self, sync_client, landed_mls_init):
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", visibility="private", description="a research group")

        body = json.loads(route.calls[0].request.content)
        assert body["description"] == "a research group"

    @respx.mock
    def test_create_omits_description_when_none(self, sync_client, landed_mls_init):
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", visibility="private")

        body = json.loads(route.calls[0].request.content)
        assert "description" not in body

    @respx.mock
    def test_create_when_a_vote_window_is_named_then_it_rides_the_create_request(
        self, sync_client, landed_mls_init
    ):
        """One POST, never a POST followed by a PATCH.

        The route has accepted ``vote_duration_hours`` at create all along; only
        this SDK dropped it and offered it on ``update`` alone. A group founded
        at the server's 72 and edited afterwards is a *different group* for as
        long as the second call has not landed — and a caller that cannot make
        the second call has founded the wrong group.
        """
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )
        patched = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create(
            "my-group", visibility="private", enrollment="majority", vote_duration_hours=6
        )

        assert json.loads(route.calls[0].request.content)["vote_duration_hours"] == 6
        assert route.call_count == 1
        assert not patched.called, "a follow-up edit is not how a window is chosen"

    @respx.mock
    def test_create_when_no_vote_window_is_named_then_the_server_default_stands(
        self, sync_client, landed_mls_init
    ):
        """Omission is the server's 72 hours, not a number this client invents."""
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", visibility="private", enrollment="majority")

        assert "vote_duration_hours" not in json.loads(route.calls[0].request.content)

    @respx.mock
    def test_create_when_mls_is_not_named_then_the_body_says_nothing_about_it(
        self, sync_client, landed_mls_init
    ):
        """The server's default is the default — this SDK states none of its own.

        It used to send ``mls_enabled: true`` on every create, which meant the
        same call from Python and from TypeScript put a different body on the
        wire for the same group. Omission is now the whole request, exactly as
        ``buildCreateBody`` writes it in the TypeScript SDK, and the founding
        still runs.
        """
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", visibility="private")

        assert "mls_enabled" not in json.loads(route.calls[0].request.content)
        assert len(landed_mls_init) == 1

    @respx.mock
    def test_create_when_mls_is_refused_then_the_server_is_told_and_nothing_is_founded(
        self, sync_client, landed_mls_init
    ):
        """A sender-key group is asked for once, on the wire and locally.

        The ``false`` has to travel: a create that only skipped the founding
        would leave a closed row still saying "created to run MLS" with no
        latch, which every surface renders as a broken MLS group for the life
        of the group — no shipped client can PATCH the flag back. And the
        founding has to be skipped, or the group the caller asked not to have
        MLS gets it anyway.
        """
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json={**_GROUP_PAYLOAD, "mls_enabled": False})
        )

        result = sync_client.groups.create("my-group", visibility="private", enable_mls=False)

        assert json.loads(route.calls[0].request.content)["mls_enabled"] is False
        assert landed_mls_init == []
        assert not reread.called
        # A skipped founding is not a failed one: there is no reason to report.
        assert result.mls_init is None
        assert group_is_mls(result) is False

    @respx.mock
    def test_create_when_mls_is_named_true_then_it_is_the_default_said_out_loud(
        self, sync_client, landed_mls_init
    ):
        """``True`` changes neither the request nor what happens after it."""
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", visibility="private", enable_mls=True)

        assert "mls_enabled" not in json.loads(route.calls[0].request.content)
        assert len(landed_mls_init) == 1

    @respx.mock
    @pytest.mark.parametrize("omission", ["absent", "none"])
    def test_create_when_visibility_is_not_named_then_it_refuses_before_the_request(
        self, sync_client, omission
    ):
        """No client picks a visibility for the caller.

        ``None`` is asserted alongside omission because it is the shape the
        hermes, crewai and langchain tool layers actually pass: they hold
        visibility as an optional and forward it so that this refusal is the
        single copy of the sentence. A change that let ``None`` mean "private"
        would list nobody's group and go unnoticed on every surface.
        """
        _mock_token()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )
        kwargs = {} if omission == "absent" else {"visibility": None}

        with pytest.raises(ValueError, match="visibility"):
            sync_client.groups.create("my-group", **kwargs)

        assert not route.called, "the group must not be created before a visibility is named"


class TestSyncGroupsList:
    @respx.mock
    def test_list_returns_group_list(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )

        results = sync_client.groups.list()

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], GroupRead)
        assert results[0].name == "test-group"

    @respx.mock
    def test_list_returns_empty(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        results = sync_client.groups.list()
        assert results == []

    @respx.mock
    def test_list_when_the_group_has_a_conversation_then_the_row_carries_its_id(self, sync_client):
        """The catch-up affordance, from the SDK's side.

        Pydantic drops what the model was not told about, so a field that is not
        declared on ``GroupRead`` never reaches the caller at all — and every
        Python surface renders through this type. This is the test that fails if
        the declaration is dropped.
        """
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200,
                json={"items": [{**_GROUP_PAYLOAD, "conversation_id": CONVERSATION_ID}]},
            )
        )

        results = sync_client.groups.list()

        assert str(results[0].conversation_id) == CONVERSATION_ID

    @respx.mock
    @pytest.mark.parametrize("shape", ["null", "absent"])
    def test_list_when_nothing_was_posted_then_conversation_id_is_none(self, sync_client, shape):
        """A group nobody has spoken in has no conversation, and that is not an error.

        Both shapes land on ``None``: the current server always emits the key
        (``"conversation_id": null``), and an older one omits it entirely. A
        client that required it non-null would refuse to parse a perfectly
        normal group.
        """
        _mock_token()
        payload = (
            {**_GROUP_PAYLOAD, "conversation_id": None} if shape == "null" else _GROUP_PAYLOAD
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [payload]})
        )

        results = sync_client.groups.list()

        assert results[0].conversation_id is None

    @respx.mock
    def test_list_says_which_of_this_orgs_agents_are_seated_in_each_group(self, sync_client):
        """From the SDK's side: ``GET /groups`` is ORG-scoped.

        A group is listed whenever *any* agent of the org is in it, so the row
        alone never said whether the agent about to post was one of them. It says
        so now, and — as with ``conversation_id`` — a field this model does not
        declare is one pydantic silently drops before any surface can render it.
        """
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200,
                json={"items": [{**_GROUP_PAYLOAD, "member_agent_ids": [AGENT_ID, MEMBER_ID]}]},
            )
        )

        results = sync_client.groups.list()

        assert [str(a) for a in results[0].member_agent_ids] == [AGENT_ID, MEMBER_ID]

    @respx.mock
    @pytest.mark.parametrize("shape", ["empty", "absent"])
    def test_list_when_no_agent_of_this_org_is_seated_the_answer_is_empty_not_missing(
        self, sync_client, shape
    ):
        """An org can be in a group through an agent this caller never names.

        Both shapes land on ``[]``: the current server always emits the key, an
        older one omits it. The empty list is the answer "no agent of your org
        holds a seat here" — the surfaces print that sentence rather than a
        blank, and a client that required the key would refuse a perfectly normal
        group.
        """
        _mock_token()
        payload = (
            {**_GROUP_PAYLOAD, "member_agent_ids": []} if shape == "empty" else _GROUP_PAYLOAD
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [payload]})
        )

        results = sync_client.groups.list()

        assert results[0].member_agent_ids == []


class TestSyncGroupsMembers:
    """``groups.members()`` — the roster read, and which rows are the caller's own."""

    @respx.mock
    def test_members_marks_this_orgs_own_seats_and_still_returns_every_other_one(
        self, sync_client
    ):
        """The second field. A marker, never a filter.

        The read is authorised for the org rather than for one agent, so it also
        answers for a group the acting agent is not seated in. ``is_own_org``
        tells the two kinds of row apart; both kinds come back, because the agent
        needs to see who it is talking to as much as who it can talk as.
        """
        _mock_token()
        _mock_group_read()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": MEMBER_ID,
                            "group_id": GROUP_ID,
                            "agent_id": AGENT_ID,
                            "agent_handle": "test-agent@myorg.rine.network",
                            "role": "admin",
                            "joined_at": "2024-01-01T00:00:00Z",
                            "is_own_org": True,
                        },
                        {
                            "id": REQUEST_ID,
                            "group_id": GROUP_ID,
                            "agent_id": OTHER_AGENT_ID,
                            "agent_handle": "outsider@other.rine.network",
                            "role": "member",
                            "joined_at": "2024-01-02T00:00:00Z",
                            "is_own_org": False,
                        },
                    ]
                },
            )
        )

        members = sync_client.groups.members(GROUP_ID)

        assert len(members) == 2
        assert [m.is_own_org for m in members] == [True, False]

    @respx.mock
    def test_members_from_a_server_that_omits_the_field_are_not_claimed_as_ours(self, sync_client):
        """The safe default for an additive field: absent means "not this org's".

        Claiming an unknown row as the caller's own would mark a stranger's seat
        ``(yours)`` on three surfaces, which is worse than marking nothing.
        """
        _mock_token()
        _mock_group_read()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": MEMBER_ID,
                            "group_id": GROUP_ID,
                            "agent_id": AGENT_ID,
                            "role": "member",
                            "joined_at": "2024-01-01T00:00:00Z",
                        }
                    ]
                },
            )
        )

        assert sync_client.groups.members(GROUP_ID)[0].is_own_org is False


class TestSyncGroupsJoin:
    @respx.mock
    def test_open_policy_join_returns_joined(self, sync_client):
        """An open-policy join is a 200 + GroupMemberRead — the caller is a member."""
        _mock_token()
        route = respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        assert str(result.member.agent_id) == AGENT_ID
        assert route.called

    @respx.mock
    def test_voucher_join_returns_joined(self, sync_client):
        """A voucher/invite-matched join is also a 200 + GroupMemberRead."""
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"

    @respx.mock
    def test_vote_required_join_returns_pending(self, sync_client):
        """A vote-gated join is a 202 + JoinRequestRead — a pending request."""
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(202, json=_PENDING_REQUEST_PAYLOAD)
        )

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, PendingJoinResult)
        assert result.status == "pending"
        assert str(result.request.id) == REQUEST_ID

    @respx.mock
    def test_join_by_handle_resolves_first(self, sync_client):
        _mock_token()
        # Mock handle resolution
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )

        result = sync_client.groups.join("#test-group@myorg.rine.network")

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"

    @respx.mock
    def test_join_closed_no_invite_raises_403(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(403, json={"detail": "closed group"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.join(GROUP_ID)

    @respx.mock
    def test_join_duplicate_member_raises_409(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(409, json={"detail": "already a member"})
        )

        with pytest.raises(ConflictError):
            sync_client.groups.join(GROUP_ID)

    @respx.mock
    def test_join_raises_not_found_on_unknown_handle(self, sync_client):
        """A bare name is read against this agent's invitations, and no wider.

        The reference carries no org, so the one rung it gets is the list of
        groups that have already asked for this agent — bounded, and therefore
        safe in front of a verb that cannot be taken back.
        """
        _mock_token()
        seats = respx.get("https://rine.network/groups")
        directory = respx.get("https://rine.network/directory/groups")
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.join("nonexistent-group")

        assert not seats.called
        assert not directory.called

    @respx.mock
    def test_join_mls_group_is_an_ordinary_join(self, sync_client, caplog):
        """An MLS group joins like any other — no caveat, and nothing to warn about.

        The join reads the group to decide whether MLS state must be installed;
        a group whose MLS state has not been founded has none to install. What
        installing it looks like is ``tests/test_mls_join.py``.
        """
        _mock_token()
        _mock_agents()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )
        probe = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200, json={**_GROUP_PAYLOAD, "mls_enabled": True, "mls_group_id": None}
            )
        )

        with caplog.at_level("WARNING"):
            result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        assert "warning" not in JoinedResult.model_fields
        assert probe.call_count == 1
        assert caplog.records == []


class TestAsyncGroupsCreate:
    @respx.mock
    async def test_create_returns_group_read(self, async_client, landed_mls_init):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _mock_agents()
        _mock_group_read()
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = await async_client.groups.create("test-group", visibility="private")

        assert isinstance(result, GroupRead)
        assert result.name == "test-group"
        assert result.mls_init is None
        await async_client.close()

    @respx.mock
    async def test_create_sends_correct_body(self, async_client, landed_mls_init):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group", enrollment="majority", visibility="public")

        body = json.loads(route.calls[0].request.content)
        assert body["enrollment_policy"] == "majority"
        assert body["visibility"] == "public"
        await async_client.close()

    @respx.mock
    async def test_create_when_a_vote_window_is_named_then_it_rides_the_create_request(
        self, async_client, landed_mls_init
    ):
        """Async twin: the same keyword, the same single request."""
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )
        patched = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create(
            "my-group", visibility="private", enrollment="unanimity", vote_duration_hours=1
        )

        assert json.loads(route.calls[0].request.content)["vote_duration_hours"] == 1
        assert route.call_count == 1
        assert not patched.called
        await async_client.close()

    @respx.mock
    async def test_create_when_mls_is_not_named_then_the_body_says_nothing_about_it(
        self, async_client, landed_mls_init
    ):
        """Async mirror: omission is the whole request, and the founding runs."""
        _mock_token()
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group", visibility="private")

        assert "mls_enabled" not in json.loads(route.calls[0].request.content)
        assert len(landed_mls_init) == 1
        await async_client.close()

    @respx.mock
    async def test_create_when_mls_is_refused_then_the_server_is_told_and_nothing_is_founded(
        self, async_client, landed_mls_init
    ):
        """Async mirror: the ``false`` travels and the founding is skipped.

        Asserted on both halves here too, because the two create paths are two
        functions: the async twin has silently dropped a create keyword before.
        """
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json={**_GROUP_PAYLOAD, "mls_enabled": False})
        )

        result = await async_client.groups.create(
            "my-group", visibility="private", enable_mls=False
        )

        assert json.loads(route.calls[0].request.content)["mls_enabled"] is False
        assert landed_mls_init == []
        assert not reread.called
        assert result.mls_init is None
        assert group_is_mls(result) is False
        await async_client.close()

    @respx.mock
    async def test_create_when_a_closed_group_latches_mls_returns_it_as_an_mls_group(
        self, async_client, landed_mls_init
    ):
        """Async mirror: a freshly created closed group renders as MLS."""
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200, json={**_GROUP_PAYLOAD, "mls_enabled": True, "mls_group_id": "mls-latch-abc"}
            )
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = await async_client.groups.create("test-group", visibility="private")

        assert reread.called
        assert result.mls_group_id == "mls-latch-abc"
        assert group_is_mls(result) is True
        assert result.mls_init is None
        await async_client.close()

    @respx.mock
    async def test_create_when_the_group_is_open_enrollment_skips_the_reread(self, async_client):
        """Async mirror: nothing was founded for an open group, so nothing is re-read."""
        _mock_token()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_OPEN_GROUP_PAYLOAD)
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_OPEN_GROUP_PAYLOAD)
        )

        result = await async_client.groups.create(
            "my-group", visibility="private", enrollment="open"
        )

        assert result.enrollment_policy == "open"
        assert not reread.called
        assert result.mls_init is None
        await async_client.close()

    @respx.mock
    async def test_create_when_the_mls_init_fails_reports_it_and_skips_the_reread(
        self, async_client, refused_mls_init, caplog
    ):
        """Async mirror: a failed init is handed back and costs no round trip."""
        _mock_token()
        _mock_agents()
        reread = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        with caplog.at_level("WARNING"):
            result = await async_client.groups.create("test-group", visibility="private")

        assert str(result.id) == GROUP_ID
        assert not reread.called
        assert result.mls_init is not None
        assert MLS_INIT_REFUSAL in result.mls_init.reason
        assert group_is_mls(result) is False
        await async_client.close()

    @respx.mock
    async def test_create_when_the_reread_fails_returns_the_created_group(
        self, async_client, landed_mls_init, caplog
    ):
        """Async mirror: a failed refresh never costs the caller the created group."""
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            side_effect=httpx.ConnectError("connection reset")
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        with caplog.at_level("WARNING"):
            result = await async_client.groups.create("test-group", visibility="private")

        assert isinstance(result, GroupRead)
        assert str(result.id) == GROUP_ID
        assert result.handle == _GROUP_PAYLOAD["handle"]
        assert result.mls_init is None
        assert any("was created" in r.message for r in caplog.records)
        await async_client.close()

    @respx.mock
    async def test_create_includes_description_when_set(self, async_client, landed_mls_init):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create(
            "my-group", visibility="private", description="a research group"
        )

        body = json.loads(route.calls[0].request.content)
        assert body["description"] == "a research group"
        await async_client.close()

    @respx.mock
    async def test_create_omits_description_when_none(self, async_client, landed_mls_init):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _mock_agents()
        _mock_group_read()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group", visibility="private")

        body = json.loads(route.calls[0].request.content)
        assert "description" not in body
        await async_client.close()

    @respx.mock
    @pytest.mark.parametrize("omission", ["absent", "none"])
    async def test_create_when_visibility_is_not_named_then_it_refuses_before_the_request(
        self, async_client, omission
    ):
        """Async twin of the sync refusal — hermes reaches this one."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )
        kwargs = {} if omission == "absent" else {"visibility": None}

        with pytest.raises(ValueError, match="visibility"):
            await async_client.groups.create("my-group", **kwargs)

        assert not route.called, "the group must not be created before a visibility is named"
        await async_client.close()


class TestAsyncGroupsList:
    @respx.mock
    async def test_list_returns_group_list(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )

        results = await async_client.groups.list()

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], GroupRead)
        await async_client.close()


class TestAsyncGroupsJoin:
    @respx.mock
    async def test_open_policy_join_returns_joined(self, async_client):
        _mock_token()
        route = respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )

        result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        assert str(result.member.agent_id) == AGENT_ID
        assert route.called
        await async_client.close()

    @respx.mock
    async def test_voucher_join_returns_joined(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )

        result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        await async_client.close()

    @respx.mock
    async def test_vote_required_join_returns_pending(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(202, json=_PENDING_REQUEST_PAYLOAD)
        )

        result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, PendingJoinResult)
        assert result.status == "pending"
        assert str(result.request.id) == REQUEST_ID
        await async_client.close()

    @respx.mock
    async def test_join_closed_no_invite_raises_403(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(403, json={"detail": "closed group"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.groups.join(GROUP_ID)
        await async_client.close()

    @respx.mock
    async def test_join_duplicate_member_raises_409(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(409, json={"detail": "already a member"})
        )

        with pytest.raises(ConflictError):
            await async_client.groups.join(GROUP_ID)
        await async_client.close()

    @respx.mock
    async def test_join_raises_not_found_on_unknown_handle(self, async_client):
        """The async twin of the sync case: one rung for a bare name, no wider."""
        _mock_token()
        seats = respx.get("https://rine.network/groups")
        directory = respx.get("https://rine.network/directory/groups")
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.join("ghost-group")

        assert not seats.called
        assert not directory.called
        await async_client.close()

    @respx.mock
    async def test_join_mls_group_is_an_ordinary_join(self, async_client, caplog):
        """An MLS group joins like any other — no caveat, and nothing to warn about.

        The join reads the group to decide whether MLS state must be installed;
        a group whose MLS state has not been founded has none to install. What
        installing it looks like is ``tests/test_mls_join.py``.
        """
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        _mock_agents()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json=_MEMBER_PAYLOAD)
        )
        probe = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(
                200, json={**_GROUP_PAYLOAD, "mls_enabled": True, "mls_group_id": None}
            )
        )

        with caplog.at_level("WARNING"):
            result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        assert "warning" not in JoinedResult.model_fields
        assert probe.call_count == 1
        assert caplog.records == []
        await async_client.close()


class TestSyncGroupsBareNameResolve:
    """A bare group name (no @, not a UUID) resolves via the caller's group list.

    The server's ``?handle=`` filter only matches a full ``#name@org`` handle, so
    a bare ``test-group`` is resolved by listing the agent's groups and matching the
    handle's local part. Full handles and UUIDs keep their existing fast paths.
    """

    @respx.mock
    def test_invite_with_bare_name_posts_to_resolved_group(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = sync_client.groups.invite("test-group", OTHER_AGENT_ID)

        assert result.status == "invited"
        assert invite.called

    @respx.mock
    def test_invite_with_full_handle_uses_handle_query(self, sync_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        sync_client.groups.invite("#test-group@myorg.rine.network", OTHER_AGENT_ID)

        # Full handle goes through the ?handle= server filter, not a bare list.
        assert groups.calls[0].request.url.params.get("handle") == (
            "#test-group@myorg.rine.network"
        )
        assert invite.called

    @respx.mock
    def test_invite_with_a_uuid_reads_its_row_and_leaves_the_roster_alone(self, sync_client):
        # A UUID used to short-circuit the lookup entirely, so an id no
        # group of this org carries reached the wire and came back a
        # bare server 404. It is checked now — against its own indexed row
        # rather than against a listing that counts members for every group the
        # org holds. The refusal the roster still buys is asserted below.
        _mock_token()
        row = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert row.called
        assert not groups.called, "the resolved path bought a listing it does not read"
        assert invite.called

    @respx.mock
    def test_invite_to_a_uuid_this_org_has_no_group_for_names_the_ones_it_has(self, sync_client):
        _mock_token()
        # The refusal path, and the one place the roster is still paid for:
        # the row read declines first, and the listing is what the sentence
        # names the org's own groups from.
        respx.get("https://rine.network/groups/cccccccc-0000-4000-8000-00000000ffff").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(
            "https://rine.network/groups/cccccccc-0000-4000-8000-00000000ffff/invite"
        ).mock(return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD))

        with pytest.raises(NotFoundError) as excinfo:
            sync_client.groups.invite("cccccccc-0000-4000-8000-00000000ffff", OTHER_AGENT_ID)

        assert "Group not found: cccccccc-0000-4000-8000-00000000ffff" in excinfo.value.detail
        assert str(_GROUP_PAYLOAD["handle"]) in excinfo.value.detail
        assert not invite.called

    @respx.mock
    def test_remove_member_with_bare_name_deletes_resolved_member(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()
        remove = respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{MEMBER_ID}").mock(
            return_value=httpx.Response(204)
        )

        sync_client.groups.remove_member("test-group", MEMBER_ID)

        assert remove.called

    @respx.mock
    def test_invite_with_unknown_bare_name_raises_not_found(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()

        with pytest.raises(NotFoundError, match="Group not found: ghost"):
            sync_client.groups.invite("ghost", OTHER_AGENT_ID)


class TestAsyncGroupsBareNameResolve:
    """Async parity for bare-name group resolution (see sync counterpart)."""

    @respx.mock
    async def test_invite_with_bare_name_posts_to_resolved_group(self, async_client):
        _mock_token()
        _mock_groups_serverlike()
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = await async_client.groups.invite("test-group", OTHER_AGENT_ID)

        assert result.status == "invited"
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_full_handle_uses_handle_query(self, async_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        await async_client.groups.invite("#test-group@myorg.rine.network", OTHER_AGENT_ID)

        assert groups.calls[0].request.url.params.get("handle") == (
            "#test-group@myorg.rine.network"
        )
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_a_uuid_reads_its_row_and_leaves_the_roster_alone(
        self, async_client
    ):
        # The sync twin carries the reasoning; the two client bodies are
        # hand-mirrored, so covering one proves nothing about the other.
        _mock_token()
        row = respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert row.called
        assert not groups.called, "the resolved path bought a listing it does not read"
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_remove_member_with_bare_name_deletes_resolved_member(self, async_client):
        _mock_token()
        _mock_groups_serverlike()
        remove = respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{MEMBER_ID}").mock(
            return_value=httpx.Response(204)
        )

        await async_client.groups.remove_member("test-group", MEMBER_ID)

        assert remove.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_unknown_bare_name_raises_not_found(self, async_client):
        _mock_token()
        _mock_groups_serverlike()

        with pytest.raises(NotFoundError, match="Group not found: ghost"):
            await async_client.groups.invite("ghost", OTHER_AGENT_ID)
        await async_client.close()


class TestSyncGroupsListInvites:
    """``groups.list_invites()`` lists invites addressed to the calling agent."""

    @respx.mock
    def test_list_invites_returns_join_request_reads(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = sync_client.groups.list_invites()

        assert route.called
        assert len(results) == 1
        assert isinstance(results[0], JoinRequestRead)
        assert str(results[0].group_id) == GROUP_ID
        assert results[0].status == "invited"

    @respx.mock
    def test_list_invites_surfaces_enriched_group_fields(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = sync_client.groups.list_invites()

        assert results[0].group_handle == "#test-group@myorg.rine.network"
        assert results[0].group_name == "test-group"

    @respx.mock
    def test_list_invites_returns_empty(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        assert sync_client.groups.list_invites() == []

    @respx.mock
    def test_list_invites_sends_agent_header(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        sync_client.groups.list_invites(agent=AGENT_ID)

        assert route.calls[0].request.headers["X-Rine-Agent"] == AGENT_ID


class TestAsyncGroupsListInvites:
    """Async parity for ``groups.list_invites()``."""

    @respx.mock
    async def test_list_invites_returns_join_request_reads(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = await async_client.groups.list_invites()

        assert route.called
        assert len(results) == 1
        assert isinstance(results[0], JoinRequestRead)
        assert results[0].group_handle == "#test-group@myorg.rine.network"
        await async_client.close()

    @respx.mock
    async def test_list_invites_returns_empty(self, async_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        assert await async_client.groups.list_invites() == []
        await async_client.close()


class TestSyncGroupsInviteNotification:
    """``invite()`` best-effort emits a ``rine.v1.group_invite`` DM to the invitee."""

    @respx.mock
    def test_invite_emits_group_invite_notification(self, sync_client, tmp_config_dir):
        _mock_token()
        _mock_group_read()
        _mock_agents()
        _mock_invitee_keys(tmp_config_dir)
        _mock_no_group_of_that_id(OTHER_AGENT_ID)
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        send = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(201, json={"id": REQUEST_ID, "status": "queued"})
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID, message="join us")

        assert result.status == "invited"
        assert send.called
        body = json.loads(send.calls[0].request.content)
        assert body["type"] == "rine.v1.group_invite"
        assert body["to_agent_id"] == OTHER_AGENT_ID

    @respx.mock
    def test_invite_succeeds_when_notification_fails(self, sync_client, tmp_config_dir):
        _mock_token()
        _mock_group_read()
        # No invitee key mock and no /messages mock — the notification send blows up.
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        # Best-effort: a failed notification must never fail the invite.
        assert result.status == "invited"


class TestAsyncGroupsInviteNotification:
    """Async parity for the best-effort invite notification."""

    @respx.mock
    async def test_invite_emits_group_invite_notification(self, async_client, tmp_config_dir):
        _mock_token()
        _mock_group_read()
        _mock_agents()
        _mock_invitee_keys(tmp_config_dir)
        _mock_no_group_of_that_id(OTHER_AGENT_ID)
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        send = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(201, json={"id": REQUEST_ID, "status": "queued"})
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID, message="join us")

        assert result.status == "invited"
        assert send.called
        body = json.loads(send.calls[0].request.content)
        assert body["type"] == "rine.v1.group_invite"
        assert body["to_agent_id"] == OTHER_AGENT_ID
        await async_client.close()

    @respx.mock
    async def test_invite_succeeds_when_notification_fails(self, async_client, tmp_config_dir):
        _mock_token()
        _mock_group_read()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert result.status == "invited"
        await async_client.close()


class TestSyncGroupsInviteResult:
    """``invite()`` maps the server body onto ``InviteResult`` for both shapes."""

    @respx.mock
    def test_invite_voucher_populates_request_id(self, sync_client):
        """A closed-group voucher (JoinRequestRead) exposes its id as ``request_id``."""
        _mock_token()
        _mock_group_read()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_VOUCHER_PAYLOAD)
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert str(result.request_id) == REQUEST_ID

    @respx.mock
    def test_invite_open_group_request_id_none(self, sync_client):
        """An open-group invite body has no id, so ``request_id`` is ``None``."""
        _mock_token()
        _mock_group_read()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert result.request_id is None


class TestAsyncGroupsInviteResult:
    """Async parity for ``invite()`` result mapping."""

    @respx.mock
    async def test_invite_voucher_populates_request_id(self, async_client):
        _mock_token()
        _mock_group_read()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_VOUCHER_PAYLOAD)
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert str(result.request_id) == REQUEST_ID
        await async_client.close()

    @respx.mock
    async def test_invite_open_group_request_id_none(self, async_client):
        _mock_token()
        _mock_group_read()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json=_OPEN_INVITE_PAYLOAD)
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert result.request_id is None
        await async_client.close()
