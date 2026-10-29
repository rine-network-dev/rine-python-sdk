"""The group-reference ladder, and the bare recipient that reaches it.

Every group in this module is invented for the property under test — an exact
name that must beat a normalised one, two candidates that must refuse, a
segment boundary a prefix must land on. None of them is any harness's group, and
none of these tests would notice if one were renamed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
import respx

from rine._group_ref import (
    GROUP_NOT_FOUND_LEAD,
    GROUP_ROSTER_LEAD,
    MAX_LISTED_GROUPS,
    NO_GROUPS_IN_ORG,
    is_bare_reference,
    is_sigil_group_reference,
    match_group_by_local_name,
    normalize_group_ref,
    recipient_group_for_bare_name,
    refuse_if_a_bare_agent_name,
)
from rine.errors import ConfigError, NotFoundError

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
AGENT_ID = "00000000-1111-2222-3333-444444444444"

_TOKEN_RESPONSE = {"access_token": "test-token", "token_type": "Bearer", "expires_in": 900}


def group(gid: str, local: str, name: str = "") -> dict[str, object]:
    """A ``GET /groups`` row, in the two fields the ladder reads."""
    return {"id": gid, "handle": f"#{local}@myorg.rine.network", "name": name}


class TestNormalization:
    def test_normalize_when_spelled_as_prose_then_matches_the_handle_spelling(self):
        assert normalize_group_ref("Quarterly Planning") == "quarterly-planning"

    def test_normalize_when_given_punctuation_and_underscores_then_collapses_each_run(self):
        assert normalize_group_ref("  Quarterly // planning_2 ") == "quarterly-planning-2"

    def test_normalize_when_given_only_punctuation_then_is_empty(self):
        assert normalize_group_ref("--- ") == ""


class TestTheLadder:
    def test_exact_local_part_when_a_normalized_rival_exists_then_the_exact_one_wins(self):
        """Tier 1 decides alone, so widening cannot move a reference that resolved.

        The rival matches on tier 2 by its NAME. If the tiers were merged, or if
        tier 1 fell through when it matched, this would be an ambiguity refusal
        — and a caller who has always named this group by its handle would start
        reading one.
        """
        groups = [group("g-1", "planning"), group("g-2", "planning-archive", "Planning")]

        assert match_group_by_local_name(groups, "planning") == "g-1"

    def test_prose_spelling_when_no_handle_matches_exactly_then_normalizes_onto_it(self):
        groups = [group("g-1", "quarterly-planning", "Quarterly planning")]

        assert match_group_by_local_name(groups, "Quarterly Planning") == "g-1"

    def test_a_group_name_when_it_is_the_only_spelling_that_matches_then_resolves(self):
        """Tier 2 reads the ``name`` as well: a person names the group, not its slug."""
        groups = [group("g-1", "qp-2031", "Quarterly planning")]

        assert match_group_by_local_name(groups, "quarterly planning") == "g-1"

    def test_one_group_when_it_matches_by_both_handle_and_name_then_is_one_candidate(self):
        """Two spellings of one group are not an ambiguity."""
        groups = [group("g-1", "quarterly-planning", "Quarterly planning")]

        assert match_group_by_local_name(groups, "quarterly-planning") == "g-1"

    def test_a_tier_when_two_groups_match_it_then_refuses_and_names_both(self):
        groups = [group("g-1", "planning-a", "Planning"), group("g-2", "planning-b", "Planning")]

        with pytest.raises(ConfigError) as excinfo:
            match_group_by_local_name(groups, "Planning")

        refusal = str(excinfo.value)
        assert "#planning-a@myorg.rine.network" in refusal
        assert "#planning-b@myorg.rine.network" in refusal

    def test_an_ambiguous_tier_when_a_looser_tier_would_decide_then_still_refuses(self):
        """A looser tier must never overrule a real ambiguity.

        Both groups answer to ``planning`` on tier 2. Exactly one of them would
        also answer to it on tier 3 — so a ladder that fell through on ambiguity
        would resolve this reference, silently, to a group the caller never
        singled out.
        """
        groups = [group("g-1", "planning", "Planning board"), group("g-2", "planning")]

        with pytest.raises(ConfigError):
            match_group_by_local_name(groups, "Planning")

    def test_a_prefix_when_it_ends_mid_segment_then_resolves_nothing(self):
        groups = [group("g-1", "shipping-manifest-4417", "Shipping manifest")]

        with pytest.raises(NotFoundError):
            match_group_by_local_name(groups, "ship")

    def test_a_prefix_when_it_ends_on_a_segment_boundary_then_resolves(self):
        groups = [group("g-1", "shipping-manifest-4417", "Shipping manifest")]

        assert match_group_by_local_name(groups, "shipping manifest") == "g-1"

    def test_a_prefix_when_two_groups_extend_it_then_refuses(self):
        groups = [group("g-1", "shipping-manifest-1"), group("g-2", "shipping-manifest-2")]

        with pytest.raises(ConfigError):
            match_group_by_local_name(groups, "shipping-manifest")

    def test_a_leading_hash_and_surrounding_space_when_written_then_are_ignored(self):
        groups = [group("g-1", "planning")]

        assert match_group_by_local_name(groups, "  #planning ") == "g-1"

    def test_a_reference_of_only_punctuation_when_given_then_matches_nothing(self):
        """An empty normalisation must not prefix-match the whole org."""
        groups = [group("g-1", "planning")]

        with pytest.raises(NotFoundError):
            match_group_by_local_name(groups, "#")


class TestTierFour:
    """The rung that peels a word naming the KIND of thing a group is.

    It fires only when tiers 1–3 matched nothing at all, so every test here has
    to say two things at once: that the peel happens, and that it never gets to
    overrule a group that answered on a stricter rung.
    """

    _OPS = group("g-ops", "ops", "Ops")

    @pytest.mark.parametrize("reference", ["ops group", "ops channel", "the ops room"])
    def test_a_trailing_classifier_when_it_is_the_only_mismatch_then_is_peeled(self, reference):
        """The whole rung, in one line: the word names the kind, not the thing."""
        assert match_group_by_local_name([self._OPS], reference) == "g-ops"

    def test_a_group_that_ends_in_a_classifier_when_named_in_full_then_wins_on_tier_two(self):
        """A stricter rung decides alone, so the peel never gets to run.

        ``#ops-group`` answers to ``ops group`` outright. If tier 4 could be
        reached while tier 2 had a match, the peel would hand the reference to
        ``#ops`` instead — a different group, in the same org, for a reference
        that was never ambiguous.
        """
        groups = [self._OPS, group("g-og", "ops-group", "Ops group")]

        assert match_group_by_local_name(groups, "ops group") == "g-og"

    def test_a_longer_group_when_it_extends_the_reference_then_wins_on_tier_three(self):
        """Tier 3 is stricter than tier 4, and a prefix match keeps its answer."""
        groups = [self._OPS, group("g-ogb", "ops-group-b", "Ops group b")]

        assert match_group_by_local_name(groups, "ops group") == "g-ogb"

    def test_the_peel_when_a_longer_reference_still_answers_then_stops_there(self):
        """🔴 One segment per step: ``ops-chat-room`` → ``ops-chat`` → ``ops``.

        A single whole-run strip would yield ``ops`` immediately and steal the
        answer from the group that answers to more of what the caller wrote.
        """
        groups = [self._OPS, group("g-oc", "ops-chat", "Ops chat")]

        assert match_group_by_local_name(groups, "ops chat room") == "g-oc"

    def test_the_peel_when_the_first_remainder_answers_to_nothing_then_goes_on(self):
        """``ops-chat`` answers to nothing here, so the walk carries on to ``ops``."""
        groups = [self._OPS, group("g-ot", "ops-team", "Ops team")]

        assert match_group_by_local_name(groups, "ops chat room") == "g-ops"

    def test_a_leading_article_when_present_then_is_dropped_before_any_trailing_noun(self):
        """``the-ops-group-chat`` → ``ops-group-chat`` → ``ops-group``, which answers."""
        groups = [self._OPS, group("g-og", "ops-group", "Ops group")]

        assert match_group_by_local_name(groups, "the ops group chat") == "g-og"

    @pytest.mark.parametrize("reference", ["the group", "groups", "the", "chat room"])
    def test_a_reference_of_only_classifiers_when_given_then_still_refuses(self, reference):
        """The peel stops while one segment is left, so none of these empties out.

        A reference that peeled to nothing would prefix-match every group in the
        org on tier 3 — the exact failure the empty-normalisation guard exists
        to prevent, arriving by another door.
        """
        with pytest.raises(NotFoundError):
            match_group_by_local_name([self._OPS, group("g-2", "planning")], reference)

    @pytest.mark.parametrize("reference", ["#", "---"])
    def test_a_reference_that_normalizes_to_nothing_when_given_then_peels_nothing(self, reference):
        """The empty-normalisation guard sits in front of tier 4, and stays there."""
        with pytest.raises(NotFoundError):
            match_group_by_local_name([self._OPS], reference)

    def test_a_word_outside_the_set_when_trailing_then_is_not_peeled(self):
        """``team`` is a content word here, and the set is deliberately narrow.

        It is the likeliest segment of a real handle of the ones considered, so
        peeling it would resolve ``ops team`` onto ``#ops`` in an org that has
        both. Excluding it costs one reference shape.
        """
        with pytest.raises(NotFoundError):
            match_group_by_local_name([self._OPS], "ops team")

    def test_a_peel_when_two_groups_answer_it_then_refuses_and_names_both(self):
        """Refuse-on-ambiguity is unchanged by the widening that reached it."""
        groups = [group("g-1a", "ops-one"), group("g-1b", "ops-two")]

        with pytest.raises(ConfigError) as excinfo:
            match_group_by_local_name(groups, "ops group")

        refusal = str(excinfo.value)
        assert "#ops-one@myorg.rine.network" in refusal
        assert "#ops-two@myorg.rine.network" in refusal
        # 🔴 The caller's OWN spelling, never the peeled remainder: both entry
        # points pass the original reference beside the prepared one, so a
        # tier-4 refusal still quotes what was actually written.
        assert "Group name 'ops group' is ambiguous" in refusal

    def test_a_peel_that_answers_to_nothing_when_refused_then_quotes_the_original(self):
        """The refusal quotes what the caller wrote, never what the ladder tried."""
        with pytest.raises(NotFoundError) as excinfo:
            match_group_by_local_name([self._OPS], "invoices group")

        assert excinfo.value.detail.startswith(f"{GROUP_NOT_FOUND_LEAD}: invoices group.")

    def test_the_bare_recipient_entry_point_when_used_then_reaches_the_same_rung(self):
        """One ladder, both doors — the reason tier 4 lives inside it, not at one."""
        assert recipient_group_for_bare_name([self._OPS], "the ops channel")["id"] == "g-ops"


class TestTheRefusal:
    def test_the_lead_when_nothing_matches_then_is_the_pinned_literal(self):
        """Five published surfaces branch on this prefix to pick a directory."""
        with pytest.raises(NotFoundError) as excinfo:
            match_group_by_local_name([group("g-1", "planning")], "ghost")

        assert excinfo.value.detail.startswith(GROUP_NOT_FOUND_LEAD)

    def test_a_zero_match_when_the_org_has_groups_then_lists_them(self):
        groups = [group("g-1", "planning", "Planning"), group("g-2", "shipping-manifest")]

        with pytest.raises(NotFoundError) as excinfo:
            match_group_by_local_name(groups, "ghost")

        refusal = str(excinfo.value)
        assert GROUP_ROSTER_LEAD in refusal
        assert "  - #planning@myorg.rine.network (Planning)" in refusal
        assert "  - #shipping-manifest@myorg.rine.network" in refusal
        assert "(None)" not in refusal

    def test_a_zero_match_when_the_org_is_in_no_groups_then_says_so(self):
        """The arm a hand-rolled copy of this tail always drops."""
        with pytest.raises(NotFoundError) as excinfo:
            match_group_by_local_name([], "ghost")

        refusal = excinfo.value.detail
        assert refusal == f"{GROUP_NOT_FOUND_LEAD}: ghost. {NO_GROUPS_IN_ORG}"
        assert GROUP_ROSTER_LEAD not in refusal

    def test_a_zero_match_when_the_org_has_many_groups_then_caps_the_list(self):
        groups = [group(f"g-{i}", f"team-{i}") for i in range(MAX_LISTED_GROUPS + 5)]

        with pytest.raises(NotFoundError) as excinfo:
            match_group_by_local_name(groups, "ghost")

        refusal = str(excinfo.value)
        assert refusal.count("  - ") == MAX_LISTED_GROUPS
        assert "and 5 more" in refusal


class TestTheBareRecipientGuard:
    _AGENTS = [{"id": AGENT_ID, "name": "ops", "handle": "ops@myorg.rine.network"}]

    def test_a_bare_name_when_an_agent_carries_it_then_refuses_naming_the_handle(self):
        """The whole safety argument: never a silent group post for a dropped @org."""
        with pytest.raises(ConfigError) as excinfo:
            refuse_if_a_bare_agent_name(self._AGENTS, "ops")

        assert "ops@myorg.rine.network" in str(excinfo.value)

    def test_a_bare_name_when_an_agent_carries_it_in_another_case_then_still_refuses(self):
        with pytest.raises(ConfigError):
            refuse_if_a_bare_agent_name(self._AGENTS, "OPS")

    def test_the_group_spelling_it_offers_is_derived_from_the_callers_own_org(self):
        # 🔴 The sentence names the handle the caller would actually write,
        # not ``#name@org`` — a slot in exactly the shape a model fills
        # by keeping the placeholder half. The org comes from a handle this
        # refusal already prints, so it costs no lookup and cannot be wrong.
        with pytest.raises(ConfigError) as excinfo:
            refuse_if_a_bare_agent_name(self._AGENTS, "ops")

        assert "write it as #ops@myorg.rine.network." in str(excinfo.value)

    def test_the_group_spelling_folds_the_callers_own_case(self):
        # 🔴 The paste is the point, and only the folded spelling can ever
        # resolve: a group name is a lowercase DNS slug server-side
        # (``validate_slug``) and the handle lookup is an exact match, so
        # ``#OPS@…`` names no group that can exist. Pinned on both stacks — the
        # cross-stack binder stops before this tail.
        with pytest.raises(ConfigError) as excinfo:
            refuse_if_a_bare_agent_name(self._AGENTS, "OPS")

        assert "write it as #ops@myorg.rine.network." in str(excinfo.value)

    def test_an_org_that_mints_no_handles_answers_the_sigil_form_of_that_word(self):
        # There is nothing to derive from, and the arm used to answer with
        # `#logistics@acme.rine.network` labelled as an example — a placeholder
        # domain inside a refusal, offered to the one caller who provably cannot
        # construct a handle. `#ops` is a spelling this stack accepts, needs no
        # org half, and is the one the collision guard is skipped for, so it is
        # the step that turns this very refusal off.
        handleless = [{"id": AGENT_ID, "name": "ops"}]

        with pytest.raises(ConfigError) as excinfo:
            refuse_if_a_bare_agent_name(handleless, "ops")

        refusal = str(excinfo.value)
        assert refusal.endswith("To post to a group of that name, write it as #ops.")
        assert "acme.rine.network" not in refusal
        # The local echo of `check-model-facing-examples.mjs`'s `template-org`
        # rule, which does not read this package: no slot, and now no domain.
        assert "@org." not in refusal

    def test_a_bare_name_when_no_agent_carries_it_then_reaches_the_group_tier(self):
        refuse_if_a_bare_agent_name(self._AGENTS, "planning")

    def test_a_recipient_when_nothing_answers_then_describes_both_spellings_and_shows_neither(
        self,
    ):
        groups = [group("g-1", "planning", "Planning")]

        with pytest.raises(NotFoundError) as excinfo:
            recipient_group_for_bare_name(groups, "ghost")

        refusal = str(excinfo.value)
        # 🔴 It says what a bare name IS read as. The sentence this
        # replaced ended "a bare name is neither", which stopped being true the
        # day bare names resolved — a refusal that contradicts the instruction
        # the caller has just followed reads as a broken product.
        assert "A bare name is read as a group you hold a seat in" in refusal
        assert "its name, an at sign, and its org's domain" in refusal
        assert "a leading hash and the same three parts" in refusal
        # 🔴 The worked example this used to carry is banned. A complete address
        # does beat a fillable ``agent@org`` slot — but both lose to naming
        # nobody: a model reads whichever address is in front of it as the
        # answer and sends there. Asserting the ABSENCE is the point; the new
        # sentence being present does not stop an old one being appended beside
        # it.
        lead = refusal.split(GROUP_ROSTER_LEAD)[0]
        assert "@" not in lead, "the lead invented an address the caller did not give"
        # The roster after the lead legitimately carries ``@`` — those are the
        # caller's OWN handles, which is rung 1 of the ladder and what a
        # refusal is asked to name.
        assert "  - #planning@myorg.rine.network (Planning)" in refusal

    def test_a_recipient_when_one_group_answers_then_returns_that_group(self):
        groups = [group("g-1", "quarterly-planning", "Quarterly planning")]

        assert recipient_group_for_bare_name(groups, "Quarterly Planning")["id"] == "g-1"


# --- The send path -----------------------------------------------------------

_GROUP_JSON = group("bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "quarterly-planning-31", "Q planning")
_AGENT_JSON = {
    "id": AGENT_ID,
    "name": "ops",
    "handle": "ops@myorg.rine.network",
    "human_oversight": True,
    "incoming_policy": "accept_all",
    "outgoing_policy": "send_all",
    "created_at": "2024-01-01T00:00:00Z",
}
_MESSAGE_JSON = {
    "id": "cccccccc-dddd-eeee-ffff-000000000001",
    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
    "from_agent_id": AGENT_ID,
    "type": "rine.v1.task_request",
    "encrypted_payload": "x",
    "encryption_version": "sender-key-v1",
    "sender_signing_kid": f"rine:{AGENT_ID}",
    "created_at": "2024-01-01T00:00:00Z",
}


def _mock_send_endpoints(groups: list[dict[str, object]]) -> respx.Route:
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=_TOKEN_RESPONSE))
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(200, json={"items": [_AGENT_JSON]})
    )
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": groups}))
    return respx.post(f"{API}/messages").mock(return_value=httpx.Response(200, json=_MESSAGE_JSON))


def _record_the_branch(client, seen: list[str]) -> None:
    """Watch which of ``send()``'s two branches a recipient takes, and with what.

    The encryption itself is not re-tested here — ``test_mls_messages`` already
    drives the real group branch end to end. What this pins is the routing
    itself: that a bare name arrives at the SAME branch, carrying the same handle a
    ``#handle`` send carries, rather than at a second send path that would then
    have its own encryption to keep in step.
    """

    def _group(agent_id, to, payload, msg_type):
        seen.append(to)
        body = {"to_handle": to, "type": msg_type, "encrypted_payload": "x"}
        return SimpleNamespace(escrow_fp=None), body, None

    def _dm(agent_id, to, payload, msg_type):
        raise AssertionError(f"a group reference reached the 1:1 path: {to!r}")

    async def _group_async(agent_id, to, payload, msg_type):
        return _group(agent_id, to, payload, msg_type)

    async def _dm_async(agent_id, to, payload, msg_type):
        return _dm(agent_id, to, payload, msg_type)

    is_async = client.__class__.__name__ == "RineClient"
    client._encrypt_group = _group_async if is_async else _group
    client._encrypt_dm = _dm_async if is_async else _dm


class TestSendRoutesABareRecipient:
    @respx.mock
    def test_a_bare_name_when_one_group_answers_then_takes_the_group_handle_path(
        self, sync_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send("Q planning", {"task": "handover"})

        assert seen == [_GROUP_JSON["handle"]]
        assert json.loads(posted.calls[0].request.content)["to_handle"] == _GROUP_JSON["handle"]

    @respx.mock
    def test_a_bare_name_when_compared_with_the_handle_spelling_then_sends_identically(
        self, sync_client
    ):
        """One send path, reached by two spellings of the same group."""
        _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send(str(_GROUP_JSON["handle"]), {"task": "handover"})
        sync_client.send("q planning", {"task": "handover"})

        assert seen[0] == seen[1]

    @respx.mock
    def test_a_bare_name_when_an_agent_carries_it_then_refuses_before_any_send(self, sync_client):
        posted = _mock_send_endpoints([_GROUP_JSON])

        with pytest.raises(ConfigError) as excinfo:
            sync_client.send("ops", {"task": "handover"})

        assert "ops@myorg.rine.network" in str(excinfo.value)
        assert not posted.called

    @respx.mock
    def test_a_bare_name_when_nothing_answers_then_describes_both_spellings_and_shows_neither(
        self, sync_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])

        with pytest.raises(NotFoundError) as excinfo:
            sync_client.send("ghost team", {"task": "handover"})

        refusal = str(excinfo.value)
        assert "its name, an at sign, and its org's domain" in refusal
        assert "a leading hash and the same three parts" in refusal
        # The same ban, through the send path this time: the composer is
        # shared, and a site pair is only as banned as its least-covered half.
        assert "@" not in refusal.split(GROUP_ROSTER_LEAD)[0]
        assert str(_GROUP_JSON["handle"]) in refusal
        assert not posted.called

    @respx.mock
    def test_a_blank_recipient_when_sent_to_then_keeps_the_agent_refusal(self, sync_client):
        """A blank names nothing in either namespace; the older sentence says so best."""
        _mock_send_endpoints([_GROUP_JSON])

        with pytest.raises(NotFoundError) as excinfo:
            sync_client.send("   ", {"task": "handover"})

        assert "expected a UUID or handle" in excinfo.value.detail

    @respx.mock
    async def test_the_async_client_when_given_a_bare_name_then_routes_it_the_same_way(
        self, async_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(async_client, seen)

        await async_client.send("Q planning", {"task": "handover"})
        await async_client.close()

        assert seen == [_GROUP_JSON["handle"]]
        assert json.loads(posted.calls[0].request.content)["to_handle"] == _GROUP_JSON["handle"]

    @respx.mock
    async def test_the_async_client_when_an_agent_carries_the_name_then_refuses(
        self, async_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])

        with pytest.raises(ConfigError):
            await async_client.send("ops", {"task": "handover"})
        await async_client.close()

        assert not posted.called


_OPS_GROUP_JSON = group("dddddddd-eeee-ffff-0000-111111111111", "ops", "ops")
_SECOND_GROUP_JSON = group("eeeeeeee-ffff-0000-1111-222222222222", "quarterly-planning-32", "Q2")


class TestSendRoutesASigiledRecipient:
    """``#name`` with no org — the spelling every other group verb already took.

    ``send()`` decided group-vs-1:1 on the leading ``#`` and then handed the
    whole string to the server's ``?handle=`` filter, which answers
    ``#name@org`` and nothing shorter. So the one recipient spelling that had
    already *stated* it meant a group was the only one the ladder never saw.
    These pin that it now lands on the same ladder, and that neither of the
    spellings around it moved.
    """

    @respx.mock
    def test_a_sigiled_name_when_one_group_answers_then_takes_the_group_handle_path(
        self, sync_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send("#quarterly-planning-31", {"task": "handover"})

        assert seen == [_GROUP_JSON["handle"]]
        assert json.loads(posted.calls[0].request.content)["to_handle"] == _GROUP_JSON["handle"]

    @respx.mock
    def test_a_sigiled_name_when_compared_with_the_full_handle_then_sends_identically(
        self, sync_client
    ):
        """One send path, reached by the sigiled reference and the whole handle."""
        _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send(str(_GROUP_JSON["handle"]), {"task": "handover"})
        sync_client.send("#Q planning", {"task": "handover"})

        assert seen[0] == seen[1]

    @respx.mock
    def test_a_sigiled_name_when_an_agent_carries_it_then_still_reaches_the_group(
        self, sync_client
    ):
        """The bare path's agent guard is deliberately not run for a sigiled name.

        ``_AGENT_JSON`` is named ``ops``, which is exactly what makes the bare
        ``send("ops")`` refuse. A caller who wrote ``#ops`` has already said
        which namespace they meant, so the same org sends.
        """
        posted = _mock_send_endpoints([_OPS_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send("#ops", {"task": "handover"})

        assert seen == [_OPS_GROUP_JSON["handle"]]
        assert posted.called

    @respx.mock
    def test_a_sigiled_name_when_nothing_answers_to_it_then_names_the_roster(self, sync_client):
        posted = _mock_send_endpoints([_GROUP_JSON])

        with pytest.raises(NotFoundError) as excinfo:
            sync_client.send("#ghost-team", {"task": "handover"})

        refusal = str(excinfo.value)
        assert GROUP_ROSTER_LEAD in refusal
        assert str(_GROUP_JSON["handle"]) in refusal
        assert not posted.called

    @respx.mock
    def test_a_sigiled_name_when_two_groups_answer_then_refuses_and_names_both(self, sync_client):
        posted = _mock_send_endpoints([_GROUP_JSON, _SECOND_GROUP_JSON])

        with pytest.raises(ConfigError) as excinfo:
            sync_client.send("#quarterly-planning", {"task": "handover"})

        refusal = str(excinfo.value)
        assert str(_GROUP_JSON["handle"]) in refusal
        assert str(_SECOND_GROUP_JSON["handle"]) in refusal
        assert not posted.called

    @respx.mock
    def test_a_group_handle_that_carries_its_org_when_sent_to_then_lists_no_groups(
        self, sync_client
    ):
        """Both org spellings go straight out, and neither consults the ladder.

        The short-form ``@myorg`` is completed by ``normalize_handle`` exactly as
        it was before, which is the point: a handle that carries its org is
        addressed as written, not looked up among the caller's OWN groups —
        where a same-named group of this org would answer for another org's.
        """
        _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(sync_client, seen)

        sync_client.send("#quarterly-planning-31@myorg", {"task": "handover"})
        sync_client.send("#quarterly-planning-31@myorg.rine.network", {"task": "handover"})

        assert seen == [_GROUP_JSON["handle"], _GROUP_JSON["handle"]]
        assert [c for c in respx.calls if c.request.url.path == "/groups"] == []

    @respx.mock
    async def test_the_async_client_when_given_a_sigiled_name_then_routes_it_the_same_way(
        self, async_client
    ):
        posted = _mock_send_endpoints([_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(async_client, seen)

        await async_client.send("#quarterly-planning-31", {"task": "handover"})
        await async_client.close()

        assert seen == [_GROUP_JSON["handle"]]
        assert json.loads(posted.calls[0].request.content)["to_handle"] == _GROUP_JSON["handle"]

    @respx.mock
    async def test_the_async_client_when_an_agent_carries_the_sigiled_name_then_still_sends(
        self, async_client
    ):
        posted = _mock_send_endpoints([_OPS_GROUP_JSON])
        seen: list[str] = []
        _record_the_branch(async_client, seen)

        await async_client.send("#ops", {"task": "handover"})
        await async_client.close()

        assert seen == [_OPS_GROUP_JSON["handle"]]
        assert posted.called


class TestTheSigilReferencePredicate:
    """Which sigiled spellings reach the ladder, and which the server still answers.

    The complement matters as much as the set: ``#name@org`` is a whole handle
    the server's ``?handle=`` filter resolves, and routing it through the ladder
    would look it up among the caller's OWN groups — turning a send to another
    org's group into a refusal, or worse, into a match on a same-named group of
    this one.
    """

    @pytest.mark.parametrize(
        "spelling", ["#ops", "#quarterly-planning-31", "#Q planning", "#ops_team", "##ops"]
    )
    def test_a_spelling_when_it_names_a_group_and_no_org_then_is_sigiled(self, spelling):
        assert is_sigil_group_reference(spelling) is True

    @pytest.mark.parametrize("spelling", ["#", "#   ", "##"])
    def test_a_spelling_when_it_is_sigil_and_nothing_else_then_is_still_claimed(self, spelling):
        """A sigil naming no group is the ladder's to refuse, not the wire's.

        It cannot match: :func:`group_reference_matches` refuses an empty
        normalisation before tier 2 could prefix-match every group in the org.
        Claiming it anyway is what turns a bare server 404 into
        :func:`unknown_group_refusal`, which names the groups the org has — and
        it is what keeps this predicate byte-equivalent to its TypeScript twin
        ``isSigilGroupReference``, which claims the same three.
        """
        assert is_sigil_group_reference(spelling) is True

    @pytest.mark.parametrize(
        "spelling",
        [
            "#ops@myorg",
            "#ops@myorg.rine.network",
            " #ops",
            "ops",
            "ops@myorg.rine.network",
            AGENT_ID,
            "",
        ],
    )
    def test_a_spelling_when_it_is_not_a_lone_group_sigil_then_is_not_claimed(self, spelling):
        assert is_sigil_group_reference(spelling) is False


class TestTheBareReferencePredicate:
    """The gate in front of the ladder — the only reason bare-name routing takes nothing away.

    ``send()`` routes a recipient through the agent guard and on to the group
    ladder exactly when :func:`is_bare_reference` claims it, so this predicate's
    complement is the set of spellings the agent namespace still answers for.
    Widening it is how a routing change becomes a misdelivery on an E2EE
    product: a handle or a UUID that reached the ladder would be looked up among
    GROUPS and posted to whichever one happened to normalise onto it.

    ``#quarterly-planning`` stays outside it even though ``send()`` now reaches
    the ladder with that spelling too — it gets there through
    :func:`is_sigil_group_reference` and WITHOUT the agent guard, which is the
    whole difference between the two. This predicate means "neither namespace
    answers this as written", and a sigiled reference is in the group namespace
    as written.

    The TypeScript twin asserts the same property from the other end, by the
    ABSENCE of a ``GET /agents`` fetch for those spellings
    (``rine-ts-sdk/src/resources/messages-bare-recipient.test.ts``). Neither
    stack had it stated on this side until now.
    """

    @pytest.mark.parametrize(
        "spelling",
        [
            "ops@myorg.rine.network",
            "ops@myorg",
            "#quarterly-planning@myorg.rine.network",
            "#quarterly-planning",
            AGENT_ID,
            "   ",
            "",
        ],
    )
    def test_a_spelling_when_a_namespace_already_answers_it_then_is_not_bare(self, spelling):
        assert is_bare_reference(spelling) is False

    @pytest.mark.parametrize("spelling", ["quarterly planning", "Q planning", "ops-team", "x"])
    def test_a_spelling_when_neither_namespace_answers_it_then_is_bare(self, spelling):
        assert is_bare_reference(spelling) is True
