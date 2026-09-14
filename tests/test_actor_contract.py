"""The acting-agent contract, tested where a caller can see it.

Only the rine HTTP boundary is mocked (respx); the SDK is real, so a header
asserted here is the header that would go on the wire, and a refusal asserted
here is the sentence an operator reads.

Four things are pinned:

* the **ladder** — an explicit ``agent=`` beats ``RINE_AGENT`` silently, and the
  env var beats nothing but the server's auto-select;
* the **normalisation** — trim once, blank is *absent*, a non-string refuses;
* the **refusal** — one text, naming the org's agents, on both stacks;
* the **header name** — one constant, and the server's own copy still agrees.
"""

from __future__ import annotations

import pathlib
import re

import httpx
import pytest
import respx

from rine import AGENT_HEADER, RineClient, SyncRineClient, normalize_actor, single_actor_value
from rine._actor import ACTING_AGENT_ENV
from rine._constants import PEEK_HEADER
from rine._resolve import resolve_agent
from rine.errors import ConfigError

API_URL = "https://rine.network"
FIRST_ID = "00000000-1111-2222-3333-444444444444"
SECOND_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

_TOKEN = {"access_token": "test-token", "token_type": "Bearer", "expires_in": 900}


def _agent(agent_id: str, name: str) -> dict:
    return {
        "id": agent_id,
        "name": name,
        "handle": f"{name}@myorg.rine.network",
        "human_oversight": True,
        "incoming_policy": "accept_all",
        "outgoing_policy": "send_all",
        "created_at": "2024-01-01T00:00:00Z",
    }


TWO_AGENTS = [_agent(FIRST_ID, "kofi"), _agent(SECOND_ID, "bob")]
#: The one-agent roster: one agent, so the actor slot decides nothing.
ONE_AGENT = [_agent(FIRST_ID, "kofi")]


def _mock_org(agents: list[dict]) -> None:
    respx.post(f"{API_URL}/oauth/token").mock(return_value=httpx.Response(200, json=_TOKEN))
    respx.get(f"{API_URL}/agents").mock(return_value=httpx.Response(200, json={"items": agents}))


def _mock_inbox(agent_id: str):
    return respx.get(f"{API_URL}/agents/{agent_id}/messages").mock(
        return_value=httpx.Response(200, json={"items": [], "total": 0, "next_cursor": None})
    )


def _client(config_dir: str, **kwargs) -> RineClient:
    return RineClient(config_dir=config_dir, api_url=API_URL, **kwargs)


@pytest.fixture
def config_dir(tmp_config_dir):
    """A config dir the client can authenticate from."""
    from rine._config import save_credentials

    save_credentials(
        tmp_config_dir, {"default": {"client_id": "test-cid", "client_secret": "test-csecret"}}
    )
    return tmp_config_dir


class TestTheEnvironmentRung:
    @respx.mock
    async def test_a_client_that_names_nobody_acts_as_the_environments_agent(
        self, config_dir, monkeypatch
    ):
        # Rung 3. Before this, a two-agent org's client built with no ``agent=``
        # refused here — RINE_AGENT was documented on other surfaces and read by
        # none of the Python ones.
        monkeypatch.setenv(ACTING_AGENT_ENV, "bob")
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        async with _client(config_dir) as client:
            await client.inbox()

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    async def test_a_named_agent_beats_the_environment_without_a_word(
        self, config_dir, monkeypatch
    ):
        # Cross-rung precedence is silent (only a same-rung disagreement refuses):
        # the constructor's agent wins and nothing is printed about it.
        monkeypatch.setenv(ACTING_AGENT_ENV, "bob")
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(FIRST_ID)

        async with _client(config_dir, agent="kofi") as client:
            await client.inbox()

        assert route.calls[0].request.headers[AGENT_HEADER] == FIRST_ID

    @respx.mock
    async def test_a_blank_environment_agent_names_nobody(self, config_dir, monkeypatch):
        # ``rine-eve``'s scaffolder writes a bare ``RINE_AGENT=`` line into every
        # project it generates, so blank is the shipped shape of "not set" — it
        # must fall through to the next rung, never be hunted for as a name.
        monkeypatch.setenv(ACTING_AGENT_ENV, "   ")
        _mock_org(TWO_AGENTS)

        async with _client(config_dir) as client:
            with pytest.raises(ConfigError) as excinfo:
                await client.inbox()

        assert "more than one agent" in str(excinfo.value)
        assert "No agent named" not in str(excinfo.value)

    @respx.mock
    async def test_the_environment_is_read_by_the_sync_client_too(self, config_dir, monkeypatch):
        # The two clients are twins by hand; a rung added to one and not the
        # other is exactly the drift this contract exists to stop.
        monkeypatch.setenv(ACTING_AGENT_ENV, "bob")
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        client = SyncRineClient(config_dir=config_dir, api_url=API_URL)
        try:
            client.inbox()
        finally:
            client.close()

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID


class TestNormalisation:
    def test_an_actor_is_trimmed_once(self):
        assert normalize_actor("  bob  ") == "bob"

    def test_blank_and_missing_are_both_absent(self):
        assert normalize_actor("") is None
        assert normalize_actor("   ") is None
        assert normalize_actor(None) is None

    def test_case_is_not_folded(self):
        # Bare names already match case-insensitively and handles normalise in
        # ``normalize_handle``; a third rule here could only disagree with them.
        assert normalize_actor("Bob") == "Bob"

    def test_a_non_string_actor_refuses_rather_than_stringifying(self, config_dir):
        # ``str({})`` is ``"{}"``, and hunting for an agent by that name either
        # finds nobody or, worse, finds somebody.
        with pytest.raises(ConfigError, match="must be a name, handle or UUID"):
            _client(config_dir, agent=42)

    @respx.mock
    async def test_a_blank_constructor_agent_falls_through_to_the_environment(
        self, config_dir, monkeypatch
    ):
        monkeypatch.setenv(ACTING_AGENT_ENV, "bob")
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        async with _client(config_dir, agent="  ") as client:
            await client.inbox()

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID


class TestTwoSpellingsOnOneRung:
    def test_naming_the_actor_twice_with_one_value_is_fine(self):
        assert single_actor_value("bob", "BOB") == "bob"
        assert single_actor_value("bob", None) == "bob"
        assert single_actor_value(None, "bob") == "bob"
        assert single_actor_value(None, None) is None

    def test_naming_two_different_actors_refuses_and_names_both(self):
        with pytest.raises(ConfigError) as excinfo:
            single_actor_value("bob", "kofi")

        message = str(excinfo.value)
        assert "bob" in message and "kofi" in message
        assert "Name it once" in message

    def test_the_resolver_refuses_two_disagreeing_spellings(self):
        # The alias slot is the *same rung*, so no precedence rule may pick a
        # winner — the loser is an identity the caller believed they were using.
        with pytest.raises(ConfigError, match="named the acting agent twice"):
            resolve_agent(TWO_AGENTS, explicit="kofi", as_flag="bob")


class TestTheRefusal:
    def test_it_names_the_orgs_agents_and_how_to_choose_one(self):
        with pytest.raises(ConfigError) as excinfo:
            resolve_agent(TWO_AGENTS)

        message = str(excinfo.value)
        assert "This org has more than one agent" in message
        assert "  - kofi (kofi@myorg.rine.network)" in message
        assert "  - bob (bob@myorg.rine.network)" in message
        assert f"set {ACTING_AGENT_ENV}" in message

    def test_it_invites_the_retry_without_a_fillable_slot(self):
        # 🔴 The placeholder trap in the actor slot itself. The shipped line was ``Pass
        # agent=<name>`` — a bracketed template in model-facing text, in the
        # exact parameter a model filled with the literal word ``null``. The
        # replacement names no specific agent on purpose: ``GET /agents`` has no
        # ``ORDER BY``, so "retry with agent=kofi" would print a different name
        # run to run and make the refusal irreproducible.
        with pytest.raises(ConfigError) as excinfo:
            resolve_agent(TWO_AGENTS)

        message = str(excinfo.value)
        assert f"Name one of them with agent=, or set {ACTING_AGENT_ENV}." in message
        assert "<" not in message and "{" not in message

    def test_it_names_an_agent_by_its_uuid_when_it_has_claimed_no_handle(self):
        # ``handle`` is present-and-null until the org has a slug, and a ``.get``
        # default does not fire on an explicit ``None`` — the refusal read
        # ``bob (None)``, naming the agent by nothing the header accepts.
        nameless = dict(TWO_AGENTS[1], handle=None)

        with pytest.raises(ConfigError) as excinfo:
            resolve_agent([TWO_AGENTS[0], nameless])

        assert f"  - bob ({SECOND_ID})" in str(excinfo.value)

    def test_an_unknown_actor_is_told_which_agents_exist(self):
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent(TWO_AGENTS, explicit="ghost")

        message = str(excinfo.value)
        assert "No agent named 'ghost'" in message
        assert "  - kofi (kofi@myorg.rine.network)" in message

    @pytest.mark.parametrize("actor", ["ghost", "ghost@myorg.rine.network"])
    def test_an_org_with_no_agents_is_told_so_rather_than_shown_an_empty_list(self, actor):
        # The sentence that trails off: an empty org renders as the empty string,
        # so a refusal that appends the roster unconditionally ends "Available
        # agents:" and then stops — worst exactly where the caller most needs to
        # hear there is nothing to choose from. The handle spelling read that way
        # until both spellings were given one tail.
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent([], explicit=actor)

        message = str(excinfo.value)
        assert message.endswith("No active agents in this org.")
        assert "Available agents:" not in message


class TestThePerCallRung:
    """A bare name named on the call itself — the spelling the refusals ask for.

    Every refusal above tells a caller to say which agent is acting, and the
    list it prints leads with the agent's *name*. The per-call rung took that
    spelling and refused it (``Invalid agent identifier 'ops'``): only the
    constructor rung looked names up, so ``agent="ops"`` worked once, at
    construction, and not on the call. Both rungs now go through the same
    lookup, and the name reaches the wire as the UUID the header accepts —
    resolving the rung without resolving the header would only have moved the
    refusal from the client to the server's ``422``.
    """

    @respx.mock
    async def test_a_bare_name_named_on_the_call_acts_as_that_agent(self, config_dir):
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        async with _client(config_dir) as client:
            await client.inbox(agent="bob")

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    def test_the_sync_twin_resolves_a_per_call_bare_name_too(self, config_dir):
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        client = SyncRineClient(config_dir=config_dir, api_url=API_URL)
        try:
            client.inbox(agent="bob")
        finally:
            client.close()

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    async def test_a_per_call_name_beats_the_clients_own_agent(self, config_dir):
        # Precedence, and silent: the narrower rung wins with nothing printed.
        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        async with _client(config_dir, agent="kofi") as client:
            await client.inbox(agent="bob")

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    async def test_a_handle_named_on_the_call_acts_as_that_agent(self, config_dir):
        # 🔴 An acting agent must be an agent the caller OWNS, so a handle is
        # looked up in this org's own agents exactly as a name is — and the id
        # that lookup returns is what goes on the wire. The header would have
        # taken the handle as written and resolved it server-side, which is why
        # this used to be sent verbatim to save a lookup; the lookup is what
        # makes an actor this org does not own refuse by name here
        # instead of as a ``422`` about a header, and it is memoised.
        _mock_org(TWO_AGENTS)
        route = respx.get(f"{API_URL}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        async with _client(config_dir) as client:
            await client.groups.list(agent="bob@myorg.rine.network")

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    async def test_a_short_form_handle_names_the_same_agent(self, config_dir):
        # ``bob@myorg`` and ``bob@myorg.rine.network`` are one identifier — both
        # sides of the comparison normalise — so widening the rung must not make
        # the short form the one spelling that refuses.
        _mock_org(TWO_AGENTS)
        route = respx.get(f"{API_URL}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        async with _client(config_dir) as client:
            await client.groups.list(agent="bob@myorg")

        assert route.calls[0].request.headers[AGENT_HEADER] == SECOND_ID

    @respx.mock
    async def test_a_uuid_the_wire_parses_is_never_looked_up_as_a_name(self, config_dir):
        """🔴 Widening the rung must not narrow which UUIDs are still UUIDs.

        ``X-Rine-Agent`` is parsed server-side with ``uuid.UUID()``
        (``src/rine/api/agent_identity.py``), which takes the dashless,
        ``urn:uuid:`` and braced spellings as readily as the canonical one — so
        all four have always worked on every **header-only** call. The rung
        decides "resolve this first" from the *wire's* rule for that reason:
        deciding it from ``is_uuid``, which is deliberately strict because
        recipient and group resolution also ask it, would send the other three
        to the bare-name matcher and refuse them with ``No agent named
        'aaaaaaaabbbb…'`` — an agent nobody was looking for, on a value the
        server would have accepted.

        Header-only is the whole scope, and ``groups.list`` is one: a call that
        needs the id for something else (``inbox`` builds
        ``/agents/{id}/messages`` from it) goes through ``_resolve_agent_id``'s
        own strict path and has refused these spellings since before this rung
        moved. That is a separate, older gap and not what this pins.
        """
        _mock_org(TWO_AGENTS)
        route = respx.get(f"{API_URL}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        dashless = SECOND_ID.replace("-", "")

        async with _client(config_dir) as client:
            await client.groups.list(agent=dashless)

        assert route.calls[0].request.headers[AGENT_HEADER] == dashless, (
            "the caller's spelling reaches the wire, which accepts it"
        )

    @pytest.mark.parametrize(
        ("actor", "lead"),
        [
            ("ghost", "No agent named 'ghost'"),
            (
                "ghost@myorg.rine.network",
                "No agent with handle 'ghost@myorg.rine.network'",
            ),
        ],
    )
    @respx.mock
    async def test_an_unknown_actor_is_told_which_agents_exist(self, config_dir, actor, lead):
        # 🔴 One mistake, one answer, whichever spelling made it. A bare
        # name was refused for the *shape* of the identifier once — "expected a
        # UUID or handle", a true sentence about the wire and a useless one to a
        # caller whose org has exactly the agent they named — and the handle
        # kept that defect a release longer in a worse form: it went to the
        # **recipient** resolver, asked WebFinger who owns it, and came back
        # unresolved, so the caller was eventually told ``Invalid agent_id:
        # 'ghost@…'. Expected a UUID.`` by a filesystem path-safety guard.
        from rine.errors import NotFoundError

        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        async with _client(config_dir) as client:
            with pytest.raises(NotFoundError) as excinfo:
                await client.inbox(agent=actor)

        message = str(excinfo.value)
        assert lead in message
        assert "  - kofi (kofi@myorg.rine.network)" in message
        assert "  - bob (bob@myorg.rine.network)" in message
        assert not route.called, "an unresolvable actor reads nobody's inbox"

    @pytest.mark.parametrize(
        ("actor", "lead"),
        [
            ("ghost", "No agent named 'ghost'"),
            (
                "ghost@myorg.rine.network",
                "No agent with handle 'ghost@myorg.rine.network'",
            ),
        ],
    )
    @respx.mock
    def test_the_sync_twin_refuses_an_unknown_actor_the_same_way(self, config_dir, actor, lead):
        # The twins resolve the actor through two copies of one method; the
        # spelling branch is present in both.
        from rine.errors import NotFoundError

        _mock_org(TWO_AGENTS)
        route = _mock_inbox(SECOND_ID)

        client = SyncRineClient(config_dir=config_dir, api_url=API_URL)
        try:
            with pytest.raises(NotFoundError) as excinfo:
                client.inbox(agent=actor)
        finally:
            client.close()

        message = str(excinfo.value)
        assert lead in message
        assert "  - bob (bob@myorg.rine.network)" in message
        assert not route.called, "an unresolvable actor reads nobody's inbox"

    @respx.mock
    async def test_an_unknown_handle_is_refused_before_it_reaches_the_wire(self, config_dir):
        # The other half of the same fix: a call that needs no agent id still
        # builds the header from the actor, and a handle used to travel there
        # verbatim for the server to answer — a ``422`` naming a header and no
        # agent (``src/rine/api/agent_identity.py``). The header path and the id
        # path ask the same question now, so this refuses in the same words as
        # ``inbox`` above and sends nothing.
        from rine.errors import NotFoundError

        _mock_org(TWO_AGENTS)
        route = respx.get(f"{API_URL}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        async with _client(config_dir) as client:
            with pytest.raises(NotFoundError) as excinfo:
                await client.groups.list(agent="ghost@myorg.rine.network")

        message = str(excinfo.value)
        assert "No agent with handle 'ghost@myorg.rine.network'" in message
        assert "  - bob (bob@myorg.rine.network)" in message
        assert not route.called, "an actor this org does not own lists nobody's groups"

    @respx.mock
    async def test_a_name_two_agents_share_refuses_and_names_both(self, config_dir):
        # 🔴 A bare name is not unique in an org and nothing on the server makes
        # it so. Both stacks used to take the first match of an unordered list,
        # which acts as an identity the caller never chose.
        _mock_org(
            [
                dict(_agent(FIRST_ID, "ops"), handle="ops@myorg.rine.network"),
                dict(_agent(SECOND_ID, "ops"), handle="ops-standby@myorg.rine.network"),
            ]
        )
        route = respx.get(f"{API_URL}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        async with _client(config_dir) as client:
            with pytest.raises(ConfigError) as excinfo:
                await client.groups.list(agent="ops")

        message = str(excinfo.value)
        assert "More than one agent is named 'ops'" in message
        assert "  - ops (ops@myorg.rine.network)" in message
        assert "  - ops (ops-standby@myorg.rine.network)" in message
        assert "name it by handle or UUID" in message
        assert not route.called, "an ambiguous actor acts as neither candidate"

    def test_two_agents_of_one_name_are_told_apart_by_uuid_in_a_slugless_org(self):
        # A slugless org mints no handles, so the two candidates would print as
        # one repeated line — the refusal falls back to the id, the only other
        # spelling ``X-Rine-Agent`` takes.
        agents = [
            dict(_agent(FIRST_ID, "ops"), handle=None),
            dict(_agent(SECOND_ID, "ops"), handle=None),
        ]

        with pytest.raises(ConfigError) as excinfo:
            resolve_agent(agents, explicit="ops")

        message = str(excinfo.value)
        assert f"  - ops ({FIRST_ID})" in message
        assert f"  - ops ({SECOND_ID})" in message


class TestAOneAgentOrgNeverRefusesOverTheActorSlot:
    """Resolve where there is one answer, teach where there is a choice.

    The measured defect was a model calling a send tool with ``agent: "null"``
    — the schema's own placeholder text, in a slot whose org had one agent. A
    refusal there is a refusal over a parameter that cannot carry information:
    there is exactly one agent it could have meant. So the sole agent acts, and
    the caller is told what was passed, who acted, and that the slot can be
    omitted.

    🔴 The predecessor of this class matched the value against a hardcoded list
    of bogus words. That mechanism is deleted: after this, the one-agent org
    resolves before such a list could be consulted, and the multi-agent org says
    the same sentence whether the value was ``null`` or a misspelled colleague.
    """

    def test_a_name_that_names_nobody_acts_as_the_sole_agent(self):
        resolved = resolve_agent(ONE_AGENT, explicit="null")

        assert resolved.agent_id == FIRST_ID

    def test_the_warning_says_what_was_passed_who_acted_and_how_to_omit_it(self):
        resolved = resolve_agent(ONE_AGENT, explicit="null")

        assert resolved.warning == (
            "Ignored agent='null': this org has one agent, "
            "so kofi (kofi@myorg.rine.network) acted. "
            "Omit agent for a one-agent org."
        )

    def test_the_warning_names_rine_agent_when_the_value_came_from_there(self):
        # The lever the reader can actually move. A value the client constructor
        # took off the environment was never in the call, so "omit agent" names
        # something the caller did not do — and on a one-agent org this warning
        # is the only channel a stale export has left, because the refusal that
        # used to carry it is gone.
        resolved = resolve_agent(ONE_AGENT, explicit="zed", origin="environment")

        assert resolved.warning == (
            "Ignored RINE_AGENT='zed': this org has one agent, "
            "so kofi (kofi@myorg.rine.network) acted. "
            "RINE_AGENT names no agent this org has — unset it, "
            "or point it at one that exists."
        )

    def test_a_handle_that_names_nobody_falls_back_the_same_way(self):
        # Rung 2 and rung 3a both fall back. A handle spelled at a foreign org
        # is the other way a model produces a value this org does not have.
        resolved = resolve_agent(ONE_AGENT, explicit="ghost@other.rine.network")

        assert resolved.agent_id == FIRST_ID
        assert "ghost@other.rine.network" in str(resolved.warning)

    @pytest.mark.parametrize("actor", ["kofi", "KOFI", "kofi@myorg.rine.network", FIRST_ID])
    def test_a_value_that_did_name_that_agent_warns_about_nothing(self, actor):
        # 🔴 The judgment call, pinned: the warning fires only when the value
        # did NOT name the agent that acted. Warning on a correct call would
        # teach a model that correct behaviour produces complaints. This is
        # automatic rather than checked — the fallback lives on the failure
        # path — and this test is what keeps it that way.
        resolved = resolve_agent(ONE_AGENT, explicit=actor)

        assert resolved.warning is None

    def test_naming_nobody_at_all_is_still_silent(self):
        # Rung 4 is unchanged and was never noisy: a caller who named nothing
        # made no mistake to be told about.
        resolved = resolve_agent(ONE_AGENT)

        assert resolved.agent_id == FIRST_ID
        assert resolved.warning is None

    def test_a_uuid_naming_no_agent_of_this_org_never_falls_back(self):
        # 🔴 The deliberate limit of that fallback. Ignoring a caller-supplied id and
        # acting as somebody else is a silent identity substitution, and a model
        # that does not know the value emits a *word*, not a UUID — so the rung
        # the defect uses is the bare name, and this one keeps its meaning. The
        # id travels as written and the server refuses it.
        resolved = resolve_agent(ONE_AGENT, explicit=SECOND_ID)

        assert resolved.agent_id == SECOND_ID
        assert resolved.warning is None

    def test_an_agent_genuinely_named_none_still_resolves(self):
        # 🔴 The ordering test, and the reason the word list had to go rather
        # than merely stop being consulted: ``none`` is a legal agent name — the
        # server reserves no words — so a pre-flight reject on vocabulary would
        # have deleted a capability to improve a sentence.
        agents = [_agent(FIRST_ID, "none"), _agent(SECOND_ID, "bob")]

        assert resolve_agent(agents, explicit="none").agent_id == FIRST_ID

    @respx.mock
    async def test_an_agent_named_none_can_still_act_on_a_call(self, config_dir):
        # The same ordering, through the public interface rather than the
        # resolver: the header goes out and the read happens.
        _mock_org([_agent(FIRST_ID, "none"), _agent(SECOND_ID, "bob")])
        route = _mock_inbox(FIRST_ID)

        async with _client(config_dir) as client:
            await client.inbox(agent="none")

        assert route.called
        assert route.calls[0].request.headers[AGENT_HEADER] == FIRST_ID


class TestAMultiAgentOrgStillRequiresTheSlot:
    """A real choice, so a real requirement — and one sentence for every value."""

    @pytest.mark.parametrize("actor", ["null", "kofy", "<agent>", "your_agent"])
    def test_a_value_this_org_does_not_have_refuses_whatever_it_was(self, actor):
        # 🔴 No placeholder vocabulary decides anything. ``null`` and a
        # misspelled colleague are the same mistake — the caller named something
        # this org does not have — so they get the same answer. The value is
        # still echoed: a caller who cannot see their own typo cannot fix it.
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent(TWO_AGENTS, explicit=actor)

        # ``detail``, not ``str(exc)``: the three Python wrapper packages branch
        # on ``detail.startswith(_UNKNOWN_ACTOR_LEADS)``, so the opening
        # substring is load-bearing exactly where they read it.
        message = excinfo.value.detail
        assert message.startswith(f"No agent named '{actor}'.")
        assert "This org has more than one agent, so a call has to name one." in message

    def test_the_refusal_lists_the_agents_and_invites_the_retry(self):
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent(TWO_AGENTS, explicit="null")

        message = str(excinfo.value)
        assert "Available agents:" in message
        assert "  - kofi (kofi@myorg.rine.network)" in message
        assert "  - bob (bob@myorg.rine.network)" in message
        assert message.endswith(f"Name one of them with agent=, or set {ACTING_AGENT_ENV}.")

    def test_an_unknown_handle_reads_the_same_tail_under_its_own_lead(self):
        # 🔴 Both leads keep their exact opening substrings: ``rine-hermes``,
        # ``rine-crewai`` and ``rine-langchain`` branch on ``"No agent named '"``
        # and ``"No agent with handle '"`` to decide whether a 404 gets the
        # *"try discovery"* tail. Reword a lead and all three surfaces send every
        # actor refusal to the agent directory, with every suite green.
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent(TWO_AGENTS, explicit="ghost@myorg.rine.network")

        message = excinfo.value.detail
        assert message.startswith("No agent with handle 'ghost@myorg.rine.network'.")
        assert "This org has more than one agent, so a call has to name one." in message

    def test_an_org_with_no_agents_is_told_that_instead(self):
        # The zero-agent arm keeps its own tail: there is no roster to print and
        # no retry to invite, and the sentence must not trail off saying so.
        from rine.errors import NotFoundError

        with pytest.raises(NotFoundError) as excinfo:
            resolve_agent([], explicit="null")

        message = excinfo.value.detail
        assert message == "No agent named 'null'. No active agents in this org."
        assert "Available agents:" not in message


class TestTheWarningReachesTheCaller:
    """The channel: a per-call value object, never a mutable client attribute.

    ``RineClient`` is built to be shared and already caches across calls, and
    ``asyncio.gather(client.send(a), client.send(b))`` interleaves at every
    ``await`` — a ``last_actor_warning`` written while resolving one call would
    be read by the wrapper that just finished the other. So the warning is
    returned, per call, and a surface that wants it resolves once, explicitly,
    before the operation.
    """

    @respx.mock
    async def test_a_one_agent_org_that_named_nobody_still_reads_its_inbox(self, config_dir):
        _mock_org(ONE_AGENT)
        route = _mock_inbox(FIRST_ID)

        async with _client(config_dir) as client:
            await client.inbox(agent="null")

        assert route.called, "a one-agent org has nothing to choose and nothing to refuse"
        assert route.calls[0].request.headers[AGENT_HEADER] == FIRST_ID

    @respx.mock
    async def test_the_public_resolve_step_hands_back_the_warning(self, config_dir):
        _mock_org(ONE_AGENT)

        async with _client(config_dir) as client:
            resolved = await client.resolve_actor("null")

        assert resolved.agent_id == FIRST_ID
        assert "Omit agent for a one-agent org." in str(resolved.warning)

    @respx.mock
    def test_the_sync_twin_hands_back_the_same_warning(self, config_dir):
        # The two clients are twins by hand; a channel added to one and not the
        # other is exactly the drift this contract exists to stop.
        _mock_org(ONE_AGENT)

        client = SyncRineClient(config_dir=config_dir, api_url=API_URL)
        try:
            resolved = client.resolve_actor("null")
        finally:
            client.close()

        assert resolved.agent_id == FIRST_ID
        assert "Omit agent for a one-agent org." in str(resolved.warning)

    @respx.mock
    async def test_the_memo_keeps_the_warning_for_every_later_call(self, config_dir):
        # 🔴 The client memoises its constructor actor. Memoising the id alone
        # would drop the warning after the first call, so the second send would
        # do the same substitution and report nothing about it.
        _mock_org(ONE_AGENT)
        _mock_inbox(FIRST_ID)

        async with _client(config_dir, agent="null") as client:
            await client.inbox()
            resolved = await client.resolve_actor()

        assert resolved.agent_id == FIRST_ID
        assert "Ignored agent='null'" in str(resolved.warning)

    @respx.mock
    async def test_a_correct_actor_carries_no_note_to_render(self, config_dir):
        # ``note_fields`` is what a model-facing surface spreads into its tool
        # result; on a call that needed no warning it must add no key at all,
        # rather than shipping ``"warning": null`` for every model to read.
        _mock_org(ONE_AGENT)

        async with _client(config_dir) as client:
            resolved = await client.resolve_actor("kofi")

        assert resolved.note_fields() == {}
        assert resolved.annotate("Sent.") == "Sent."

    @respx.mock
    async def test_a_fallback_renders_on_both_of_the_two_channels(self, config_dir):
        _mock_org(ONE_AGENT)

        async with _client(config_dir) as client:
            resolved = await client.resolve_actor("null")

        assert resolved.note_fields() == {"warning": resolved.warning}
        assert resolved.annotate("Sent.") == f"Sent.\n{resolved.warning}"

    @respx.mock
    async def test_the_operator_log_carries_it_for_a_host_with_no_model_channel(
        self, config_dir, caplog
    ):
        # 🔴 On ``rine-crewai``, ``rine-langchain``, ``rine-mastra`` and
        # ``rine-eve`` the actor is fixed at construction and is not a
        # model-visible parameter, so the audience for the fallback is the
        # operator. That costs those packages zero code: the SDK logs it where
        # the fallback happens, once, for every host.
        import logging

        _mock_org(ONE_AGENT)
        _mock_inbox(FIRST_ID)

        with caplog.at_level(logging.WARNING, logger="rine"):
            async with _client(config_dir) as client:
                await client.inbox(agent="null")

        assert any("Ignored agent='null'" in record.getMessage() for record in caplog.records)


class TestTheHeaderConstant:
    def test_the_sdk_names_the_header_once(self):
        assert AGENT_HEADER == "X-Rine-Agent"

    def test_the_server_still_spells_it_the_same_way(self):
        # 🔴 Two constants, bound by this test rather than by an import: the
        # backend must not import the SDK — they are separate deployables and
        # both own the top-level ``rine`` import package, so one process cannot
        # hold both. Read the server's source instead, and skip cleanly when the
        # SDK is being tested outside the monorepo (a published sdist, a rig).
        #
        # The declaration is looked up across ``src/rine/api`` rather than in one
        # named module: the server moved it once already (out of
        # ``agent_identity.py`` into ``agent_listing.py``) and the file it
        # sits in is the server's business, not this contract's. What this pins
        # is the spelling, and that there is exactly one of it — the same
        # single-declaration rule the SDK holds itself to below.
        api = pathlib.Path(__file__).resolve().parents[2] / "src/rine/api"
        if not api.is_dir():
            pytest.skip("server source not present — SDK tested outside the monorepo")

        spellings = {
            match.group(1): path.name
            for path in sorted(api.glob("*.py"))
            for match in re.finditer(r'^HEADER = "([^"]+)"', path.read_text(), re.MULTILINE)
        }
        assert spellings, f"no HEADER constant anywhere in {api}"
        assert len(spellings) == 1, f"the server spells the header more than one way: {spellings}"
        assert next(iter(spellings)) == AGENT_HEADER

    def test_the_sdk_source_holds_no_second_copy_of_the_header(self):
        # The same rule on this stack: the literal lives in ``_actor.py`` and nowhere
        # else, so renaming it is one edit rather than seventeen.
        src = pathlib.Path(__file__).resolve().parents[1] / "src/rine"
        offenders = [
            str(path.relative_to(src))
            for path in src.rglob("*.py")
            if path.name != "_actor.py" and f'"{AGENT_HEADER}"' in path.read_text()
        ]
        assert offenders == []


class TestThePeekHeaderConstant:
    """``X-Rine-Peek``, held to the same single-declaration rule as the actor header.

    The same two-deployables reason :class:`TestTheHeaderConstant` gives applies
    unchanged: the backend cannot import this SDK, so the two constants are bound
    by this test instead. The peek header is the load-bearing half of
    ``read(peek=True)`` — a client that spells it differently from the server
    consumes every row it believes it is deferring, silently and in the direction
    that loses work.
    """

    def test_the_sdk_names_the_peek_header_once(self):
        assert PEEK_HEADER == "X-Rine-Peek"

    def test_the_server_still_spells_it_the_same_way(self):
        api = pathlib.Path(__file__).resolve().parents[2] / "src/rine/api"
        if not api.is_dir():
            pytest.skip("server source not present — SDK tested outside the monorepo")

        spellings = {
            match.group(1): path.name
            for path in sorted(api.glob("*.py"))
            for match in re.finditer(r'^PEEK_HEADER = "([^"]+)"', path.read_text(), re.MULTILINE)
        }
        assert spellings, f"no PEEK_HEADER constant anywhere in {api}"
        assert len(spellings) == 1, (
            f"the server spells the peek header more than one way: {spellings}"
        )
        assert next(iter(spellings)) == PEEK_HEADER

    def test_the_sdk_source_holds_no_second_copy_of_the_peek_header(self):
        src = pathlib.Path(__file__).resolve().parents[1] / "src/rine"
        offenders = [
            str(path.relative_to(src))
            for path in src.rglob("*.py")
            if path.name != "_constants.py" and f'"{PEEK_HEADER}"' in path.read_text()
        ]
        assert offenders == []


class TestNoPersistedDefault:
    @respx.mock
    async def test_choosing_an_actor_writes_no_selector_to_the_config_dir(
        self, config_dir, monkeypatch
    ):
        # ``RINE_AGENT`` is the pin, and there is no selector file. An env
        # var is scoped to the process that set it; a file in the config dir is
        # shared by every process that reads it, which is what a host running
        # several agents must not have.
        #
        # Phrased as "nothing on disk names the actor", not "no file appears":
        # authenticating legitimately writes ``token_cache.json``, which is
        # keyed by profile and holds a token and an expiry (``_config.py``'s
        # ``cache_token``). A file-count assertion fails on that write while
        # saying nothing about selection; a selector, by contrast, cannot exist
        # without recording WHICH agent it selected.
        monkeypatch.setenv(ACTING_AGENT_ENV, "bob")
        _mock_org(TWO_AGENTS)
        _mock_inbox(SECOND_ID)
        before = sorted(p.name for p in pathlib.Path(config_dir).iterdir())

        async with _client(config_dir) as client:
            await client.inbox()

        after = sorted(p.name for p in pathlib.Path(config_dir).iterdir())
        assert [name for name in after if name not in {*before, "token_cache.json"}] == []

        for path in sorted(pathlib.Path(config_dir).rglob("*")):
            if not path.is_file():
                continue
            written = path.read_text()
            assert "bob" not in written, f"{path.name} records the acting agent"
            assert SECOND_ID not in written, f"{path.name} records the resolved actor"
            assert ACTING_AGENT_ENV not in written, f"{path.name} records the actor pin"
