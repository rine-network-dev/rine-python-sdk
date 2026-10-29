"""A group send by an unseated agent refuses BEFORE the key fan-out.

A refused group send used to cost real rows. On the Sender Keys path
``get_or_create_sender_key_sync`` distributes this agent's key to every member
the server lists, as ordinary 1:1 messages, *before* anything is posted — so an
unseated agent wrote message and delivery rows into the inbox of every member,
other orgs included, and only then took the ``403``. Nothing undid them.

The assertion that matters here is therefore **not** that a refusal is raised:
that would pass just as well on a build where the fan-out already happened. It
is that **zero distribution messages reach the wire**, counted on the same
mocked ``POST /messages`` route that the seated control arm makes fire. Only the
HTTP boundary is mocked, so the fan-out either happens for real or does not
happen at all.

The second property this file pins: the refusal names the seated sibling by
**handle**, the spelling its own next clause tells the caller to act as. That
one is a rendering, so it is asserted on the sentence — together with
the two things that make it safe: the agent list is bought **only** when the
refusal is certain, and a list that cannot be read degrades the sentence to
UUIDs rather than replacing the refusal with a transport error.

The third property: the refusal has two arms, and the arm where **no** agent
of the org is seated may not offer the acting-agent remedy, because on that arm
there is no agent to act as. That one is asserted on the sentence too, together
with the cost it must not pay — an arm that spells no handle buys no handle map.

Three neighbouring properties are pinned with it, because each one is a way to
"fix" this that would break something else:

* an **older server** omits ``member_agent_ids`` entirely, and its absence is
  not an answer — that send must still go out (the field is
  ``default_factory=list``, so after validation an omitted key and an empty one
  are the same value, and a guard that read only the model would refuse every
  open-group send made against today's production);
* the **MLS branch** carries no fan-out and is not guarded here;
* a **downgrade** still refuses as a downgrade, because a server that answers
  ``member_agent_ids: []`` must not be able to convert that alarm into a
  benign "you are not seated".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._group_send import encrypt_for_group_sync
from rine._http import SyncHttpClient
from rine._mls.binding import open_mls_client
from rine._mls.group_access import mls_group_id_bytes, note_mls_state_changed
from rine.errors import MlsDowngradeError, NotAGroupMemberError
from rine.group_words import ACTING_AGENT_SPELLING, NO_OWN_AGENTS, NO_SEAT_TO_ACT_AS
from rine.testing import WORLD, write_agent_identity

API = "https://rine.network"
SENDER = "00000000-1111-2222-3333-444444444444"
SIBLING = "11111111-2222-3333-4444-555555555555"
PEER_ORG_MEMBER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#billboard@acme.rine.network"
PAYLOAD = {"announcement": "open enrolment, all welcome"}

#: The org's own roster, as ``GET /agents`` reports it. The sender is on it —
#: an unseated agent is still one of the org's agents — and only the seat the
#: group names is ever spelled out of it.
SENDER_HANDLE = "ops@acme.rine.network"
SIBLING_HANDLE = "billing@acme.rine.network"
OWN_AGENTS = {
    "items": [
        {"id": SENDER, "name": "ops", "handle": SENDER_HANDLE},
        {"id": SIBLING, "name": "billing", "handle": SIBLING_HANDLE},
    ]
}


def _group(**overrides: Any) -> dict[str, Any]:
    """One ``/groups`` row as the server serves it."""
    return {
        "id": GROUP_ID,
        "name": "billboard",
        "handle": GROUP_HANDLE,
        "created_at": "2024-01-01T00:00:00Z",
        "mls_enabled": False,
        "mls_group_id": None,
        "mls_pending": False,
        **overrides,
    }


@dataclass(frozen=True)
class _Wire:
    """The routes a fan-out or a refusal touches, so a test can count them."""

    members: respx.Route
    distributions: respx.Route
    agents: respx.Route


def _serve(
    config_dir: str, group: dict[str, Any], *, agents: httpx.Response | None = None
) -> _Wire:
    """Register a server that can complete a real fan-out, and return its routes.

    The roster names two agents besides the sender — one sibling and one member
    of another org — and both publish real keys, so a distribution that is
    attempted succeeds rather than failing on the harness. That is what makes a
    call count of zero mean "refused", not "the mock could not answer".

    ``agents`` overrides what ``GET /agents`` answers, which is how a test asks
    for the degraded spelling: the refusal buys that list to name the seat, and
    a server that will not serve it must cost the sentence a handle and nothing
    more.
    """
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [group]}))
    own_agents = respx.get(f"{API}/agents").mock(
        return_value=agents if agents is not None else httpx.Response(200, json=OWN_AGENTS)
    )
    members = respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {"agent_id": SIBLING, "role": "member"},
                    {"agent_id": PEER_ORG_MEMBER, "role": "member"},
                ]
            },
        )
    )
    for member in (SIBLING, PEER_ORG_MEMBER):
        save_agent_keys(config_dir, member, WORLD.keys(member))
        respx.get(f"{API}/agents/{member}/keys").mock(
            return_value=httpx.Response(200, json=WORLD.keys_response(member))
        )
    distributions = respx.post(f"{API}/messages").mock(
        return_value=httpx.Response(200, json={"id": "sent", "created_at": "2024-01-01T00:00:00Z"})
    )
    return _Wire(members=members, distributions=distributions, agents=own_agents)


@pytest.fixture
def config_dir(tmp_config_dir):
    """A config dir the sender can authenticate and seal from."""
    write_agent_identity(tmp_config_dir, SENDER)
    return tmp_config_dir


@pytest.fixture
def http(config_dir):
    client = SyncHttpClient(config_dir=config_dir, api_url=API)
    yield client
    client.close()


class TestAnUnseatedSendCostsNothing:
    @respx.mock
    def test_encrypt_for_group_sync_when_no_own_agent_is_seated_distributes_no_key(
        self, config_dir, http
    ):
        """🔴 The assertion this requirement exists for: zero rows on the wire."""
        wire = _serve(config_dir, _group(member_agent_ids=[SIBLING]))

        with pytest.raises(NotAGroupMemberError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.distributions.call_count == 0
        assert not wire.members.called, "the roster is not even read before the refusal"

    @respx.mock
    def test_encrypt_for_group_sync_when_no_own_agent_is_seated_says_what_to_act_as(
        self, config_dir, http
    ):
        _serve(config_dir, _group(member_agent_ids=[SIBLING]))

        with pytest.raises(NotAGroupMemberError) as caught:
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        refusal = str(caught.value)
        assert GROUP_HANDLE in refusal and SENDER in refusal
        assert "is not a member of this group" in refusal
        assert SIBLING_HANDLE in refusal, (
            "the seated sibling is the one fact a caller cannot derive"
        )
        assert "Nothing was sent" in refusal

    @respx.mock
    def test_encrypt_for_group_sync_when_the_server_seats_nobody_of_this_org_refuses(
        self, config_dir, http
    ):
        """An empty list is an answer — unlike an absent key, below."""
        wire = _serve(config_dir, _group(member_agent_ids=[]))

        with pytest.raises(NotAGroupMemberError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.distributions.call_count == 0


class TestTheRefusalSpellsTheSeatTheWayItsOwnRemedyDoes:
    """The sentence asks for a handle, so it must print handles.

    The failure this closes was measured, not argued: a model read
    ``Seated agents of your org: 7c304fe2-…`` beside "choose an acting agent"
    and took its next actor from that list, in the one spelling the sentence
    was not asking for.
    """

    @respx.mock
    def test_encrypt_for_group_sync_when_a_sibling_is_seated_then_names_it_by_handle(
        self, config_dir, http
    ):
        """The whole clause, not a substring: the ids must be gone, not merely joined."""
        wire = _serve(config_dir, _group(member_agent_ids=[SIBLING]))

        with pytest.raises(NotAGroupMemberError) as caught:
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        refusal = str(caught.value)
        assert f"Seated agents of your org: {SIBLING_HANDLE}." in refusal
        assert SIBLING not in refusal, (
            "the seat's UUID is the spelling this clause replaced; printing both would "
            "leave the caller to guess which one the remedy wants"
        )
        assert SENDER_HANDLE not in refusal, (
            "the clause names the SEATS, not the roster the map was built from — the "
            "refused agent is on that roster and is precisely the one that cannot post"
        )
        assert wire.agents.call_count == 1, "the list is bought once, for this sentence"

    @respx.mock
    def test_encrypt_for_group_sync_when_the_agent_list_cannot_be_read_then_falls_back_to_ids(
        self, config_dir, http
    ):
        """🔴 The refusal survives the courtesy lookup, whatever the lookup does.

        A ``GET /agents`` that fails must cost the sentence a handle and
        nothing else: the caller is being told it holds no seat, and replacing
        that with a transport error would take away the one fact it can act on
        and leave the seat unnamed as well. The UUID is still a value
        ``X-Rine-Agent`` accepts, so the degraded sentence is still usable.

        A ``403`` rather than a ``500`` on purpose: ``500`` is in
        ``RETRYABLE_STATUS_CODES``, so it would spend the client's backoff
        ladder here and make this test measure ``time.sleep`` alongside the
        degradation.
        """
        _serve(
            config_dir,
            _group(member_agent_ids=[SIBLING]),
            agents=httpx.Response(403, json={"detail": "nope"}),
        )

        with pytest.raises(NotAGroupMemberError) as caught:
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        refusal = str(caught.value)
        assert f"Seated agents of your org: {SIBLING}." in refusal
        assert "Nothing was sent" in refusal

    @respx.mock
    def test_encrypt_for_group_sync_when_the_seat_has_no_handle_then_that_one_prints_as_its_id(
        self, config_dir, http
    ):
        """Per agent, not per call: one odd row must not blank the whole clause."""
        _serve(
            config_dir,
            _group(member_agent_ids=[SIBLING]),
            agents=httpx.Response(200, json={"items": [{"id": SIBLING, "name": "billing"}]}),
        )

        with pytest.raises(NotAGroupMemberError) as caught:
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert f"Seated agents of your org: {SIBLING}." in str(caught.value)

    @respx.mock
    def test_encrypt_for_group_sync_when_the_acting_agent_is_seated_then_buys_no_agent_list(
        self, config_dir, http
    ):
        """The cost lands on the refusal alone — a send that goes through pays nothing."""
        wire = _serve(config_dir, _group(member_agent_ids=[SENDER, SIBLING]))

        encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.agents.call_count == 0

    @respx.mock
    def test_encrypt_for_group_sync_when_the_server_omits_member_agent_ids_buys_no_agent_list(
        self, config_dir, http
    ):
        """The guard returns before it decides anything, so it spells nothing."""
        wire = _serve(config_dir, _group())

        encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.agents.call_count == 0


class TestTheZeroSeatArmOffersARemedyItCanKeep:
    """When there is nobody to act as, the refusal stops naming one.

    ``resolve_group_for_send`` reads ``GET /groups?handle=``, which lists only
    groups the caller's org holds a seat in, and ``member_agent_ids`` counts
    non-revoked agents while the row is listed if *any* agent holds a seat. An
    empty list on this path therefore means one thing: the org's seat-holders
    have been revoked. The old sentence answered that with
    ``Seated agents of your org: (none — …)`` followed by instructions for
    choosing a different acting agent — the same fact twice, and then advice
    with no exit, since there is no agent left to choose.
    """

    @respx.mock
    def test_encrypt_for_group_sync_when_no_agent_of_the_org_is_seated_names_the_only_remedy(
        self, config_dir, http
    ):
        """The sentence that has an exit, and neither of the two that do not."""
        _serve(config_dir, _group(member_agent_ids=[]))

        with pytest.raises(NotAGroupMemberError) as caught:
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        refusal = str(caught.value)
        assert NO_SEAT_TO_ACT_AS in refusal
        assert ACTING_AGENT_SPELLING not in refusal, (
            "there is no agent of this org to act as, so naming the three ways to "
            "choose one is advice the caller cannot take"
        )
        assert NO_OWN_AGENTS not in refusal, (
            "the empty-seat clause states the fact the new sentence already opens with"
        )
        assert "Nothing was sent" in refusal, "the fan-out guarantee survives the rewording"

    @respx.mock
    def test_encrypt_for_group_sync_when_no_agent_of_the_org_is_seated_buys_no_agent_list(
        self, config_dir, http
    ):
        """No handle is spelled on this arm, so no handle map is bought for it."""
        wire = _serve(config_dir, _group(member_agent_ids=[]))

        with pytest.raises(NotAGroupMemberError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.agents.call_count == 0


class TestAnUnresolvedActorIsNotAccused:
    @respx.mock
    def test_encrypt_for_group_sync_when_the_agent_is_an_unresolved_handle_makes_no_accusation(
        self, config_dir, http
    ):
        """A handle WebFinger could not resolve is not evidence of an empty seat.

        ``resolve_handle_sync`` returns the handle it was given when WebFinger is
        unreachable — a proxy, a DNS blip, an offline dev box — so a *genuinely
        seated* agent can reach the guard spelled as a handle, which matches no
        seat in a list of UUIDs. Accusing it of not being a member would be a
        lie, and a worse one than the honest key error it used to die of one
        frame further down. The guard has no opinion here.
        """
        _serve(config_dir, _group(member_agent_ids=[SENDER]))

        with pytest.raises(Exception) as caught:
            encrypt_for_group_sync(
                http, config_dir, "ops@acme.rine.network", GROUP_HANDLE, PAYLOAD
            )

        assert not isinstance(caught.value, NotAGroupMemberError), str(caught.value)


class TestASeatedSendStillFansOut:
    """The control arm: the same harness, and the fan-out fires."""

    @respx.mock
    def test_encrypt_for_group_sync_when_the_acting_agent_is_seated_distributes_the_key(
        self, config_dir, http
    ):
        wire = _serve(config_dir, _group(member_agent_ids=[SENDER, SIBLING]))

        result, group = encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert str(group.id) == GROUP_ID
        assert result.encryption_version == "sender-key-v1"
        assert wire.distributions.call_count == 2, "one distribution per other member"

    @respx.mock
    def test_encrypt_for_group_sync_when_the_seat_is_spelled_in_upper_case_still_sends(
        self, config_dir, http
    ):
        wire = _serve(config_dir, _group(member_agent_ids=[SENDER.upper()]))

        encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.distributions.call_count == 2


class TestAnOlderServerIsNotContradicted:
    @respx.mock
    def test_encrypt_for_group_sync_when_the_server_omits_member_agent_ids_still_sends(
        self, config_dir, http
    ):
        """The deployed server has no such field; its silence is not a refusal."""
        row = _group()
        assert "member_agent_ids" not in row
        wire = _serve(config_dir, row)

        result, _ = encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert result.encryption_version == "sender-key-v1"
        assert wire.distributions.call_count == 2


class TestTheGuardStaysOffTheOtherPaths:
    @respx.mock
    def test_encrypt_for_group_sync_when_the_group_is_mls_does_not_refuse_on_seats(
        self, config_dir, http, monkeypatch
    ):
        """No fan-out on the MLS path, so no refusal to add — the server rules."""
        monkeypatch.setattr(
            "rine._mls.messages.encrypt_mls_group_message",
            lambda *_args, **_kwargs: _MlsResult(),
        )
        _serve(config_dir, _group(mls_group_id="latched", member_agent_ids=[]))

        result, group = encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert result.encryption_version == "mls-v1"
        assert str(group.id) == GROUP_ID

    @respx.mock
    def test_encrypt_for_group_sync_when_a_downgrade_seats_nobody_still_refuses_the_downgrade(
        self, config_dir, http
    ):
        """The alarm stays audible: an empty roster must not swallow it."""
        open_mls_client(config_dir, SENDER).create_group(mls_group_id_bytes(GROUP_ID)).save()
        note_mls_state_changed(config_dir, SENDER, GROUP_ID)
        wire = _serve(config_dir, _group(member_agent_ids=[]))

        with pytest.raises(MlsDowngradeError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.distributions.call_count == 0


class _MlsResult:
    """The shape ``encrypt_mls_group_message`` returns, stubbed at the boundary."""

    encrypted_payload = "AAAA"
    encryption_version = "mls-v1"
    sender_signing_kid = "kid"
