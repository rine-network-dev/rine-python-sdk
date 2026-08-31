"""Tests for agent and handle resolution."""

from __future__ import annotations

import pytest

from rine._resolve import (
    is_uuid,
    is_wire_agent_id,
    normalize_handle,
    resolve_agent,
)
from rine.errors import ConfigError, NotFoundError


class TestIsUuid:
    def test_valid_uuid(self):
        assert is_uuid("12345678-1234-1234-1234-123456789abc")

    def test_uppercase_uuid(self):
        assert is_uuid("12345678-1234-1234-1234-123456789ABC")

    def test_not_uuid(self):
        assert not is_uuid("not-a-uuid")
        assert not is_uuid("agent@org.rine.network")
        assert not is_uuid("")

    def test_a_uuid_with_a_trailing_newline_is_not_a_uuid(self):
        """🔴 Python's ``$`` matches before a trailing newline; JavaScript's does not.

        A line read off a file or piped in carries the ``\\n``, and an id is
        interpolated into ``GET /groups/{id}`` — httpx refuses the
        newline with ``InvalidURL``, which is not a ``RineError`` and so leaves
        the SDK's error hierarchy entirely, while ``rine-core``'s ``UUID_RE``
        classifies the same string as a handle and composes the roster refusal.
        The two classifiers have to agree; this is the input that told them
        apart.
        """
        assert not is_uuid("12345678-1234-1234-1234-123456789abc\n")
        assert not is_uuid("\n12345678-1234-1234-1234-123456789abc")
        assert not is_uuid("12345678-1234-1234-1234-123456789abc\r\n")


class TestIsWireAgentId:
    """The wire's own question: is this spelling already an agent **id**?

    Deliberately looser than :func:`is_uuid` and deliberately false for a
    handle — the header parses all four UUID spellings itself, while a handle
    names an agent the caller must own and is looked up like a name.
    """

    def test_the_canonical_spelling_is_an_id(self):
        assert is_wire_agent_id("12345678-1234-1234-1234-123456789abc")

    def test_the_spellings_uuid_parses_but_is_uuid_refuses_are_ids_too(self):
        assert is_wire_agent_id("123456781234123412341234567890ab")
        assert is_wire_agent_id("urn:uuid:12345678-1234-1234-1234-123456789abc")
        assert is_wire_agent_id("{12345678-1234-1234-1234-123456789abc}")

    def test_a_handle_is_not_an_id(self):
        assert not is_wire_agent_id("agent@org.rine.network")

    def test_a_bare_name_is_not_an_id(self):
        assert not is_wire_agent_id("my-agent")


class TestBareNameMatching:
    """The bare-name rung, through the resolver that ships it.

    Was ``TestResolveBareName``, against a wrapper no call path executed. The
    matching is the same code either way (``_match_bare_name``); what changes is
    that a rewrite of the shipped path can no longer leave this green.
    """

    def test_case_insensitive_match(self):
        agents = [
            {"id": "uuid-1", "name": "My-Agent", "handle": "my-agent@org.rine.network"},
            {"id": "uuid-2", "name": "other", "handle": "other@org.rine.network"},
        ]
        assert resolve_agent(agents, explicit="my-agent").agent_id == "uuid-1"
        assert resolve_agent(agents, explicit="MY-AGENT").agent_id == "uuid-1"

    def test_no_match_raises(self):
        agents = [
            {"id": "uuid-1", "name": "other", "handle": "other@org.rine.network"},
            {"id": "uuid-2", "name": "third", "handle": "third@org.rine.network"},
        ]
        with pytest.raises(NotFoundError, match="No agent named"):
            resolve_agent(agents, explicit="missing")


class TestResolveAgent:
    def test_single_agent_auto_selected(self):
        agents = [{"id": "uuid-1", "name": "bot", "handle": "bot@org.rine.network"}]
        assert resolve_agent(agents).agent_id == "uuid-1"

    def test_explicit_uuid(self):
        agents = [{"id": "uuid-1", "name": "bot"}]
        result = resolve_agent(agents, explicit="12345678-1234-1234-1234-123456789abc")
        assert result.agent_id == "12345678-1234-1234-1234-123456789abc"

    def test_explicit_name(self):
        agents = [
            {"id": "uuid-1", "name": "bot1"},
            {"id": "uuid-2", "name": "bot2"},
        ]
        assert resolve_agent(agents, explicit="bot2").agent_id == "uuid-2"

    def test_multiple_agents_no_explicit_raises(self):
        agents = [{"id": "uuid-1", "name": "a"}, {"id": "uuid-2", "name": "b"}]
        with pytest.raises(ConfigError, match="more than one agent"):
            resolve_agent(agents)

    def test_no_agents_raises(self):
        with pytest.raises(ConfigError, match="No active agents in this org"):
            resolve_agent([])

    def test_no_agents_still_says_how_to_make_one(self):
        # The converged refusal is one sentence for every stack; the
        # actionable half of the old text is kept rather than lost to it.
        with pytest.raises(ConfigError, match="client.create_agent"):
            resolve_agent([])

    def test_explicit_handle(self):
        agents = [
            {"id": "uuid-1", "name": "bot1", "handle": "bot1@acme.rine.network"},
            {"id": "uuid-2", "name": "bot2", "handle": "bot2@acme.rine.network"},
        ]
        assert resolve_agent(agents, explicit="bot2@acme.rine.network").agent_id == "uuid-2"

    def test_explicit_short_form_handle(self):
        agents = [{"id": "uuid-1", "name": "bot", "handle": "bot@acme.rine.network"}]
        assert resolve_agent(agents, explicit="bot@acme").agent_id == "uuid-1"

    def test_explicit_handle_case_insensitive(self):
        agents = [{"id": "uuid-1", "name": "bot", "handle": "bot@acme.rine.network"}]
        assert resolve_agent(agents, explicit="BOT@ACME.RINE.NETWORK").agent_id == "uuid-1"

    def test_explicit_unknown_handle_raises(self):
        # Two agents, deliberately: with one there is nothing to choose between,
        # so an unresolvable handle falls back to the sole agent instead of
        # refusing — the fallback pinned in ``test_actor_contract.py``.
        agents = [
            {"id": "uuid-1", "name": "bot", "handle": "bot@acme.rine.network"},
            {"id": "uuid-2", "name": "bot2", "handle": "bot2@acme.rine.network"},
        ]
        with pytest.raises(NotFoundError, match="No agent with handle"):
            resolve_agent(agents, explicit="ghost@acme.rine.network")

    def test_as_flag_used_when_no_explicit(self):
        agents = [
            {"id": "uuid-1", "name": "bot1"},
            {"id": "uuid-2", "name": "bot2"},
        ]
        assert resolve_agent(agents, as_flag="bot1").agent_id == "uuid-1"


class TestNormalizeHandle:
    def test_short_agent_handle(self):
        assert normalize_handle("agent@org") == "agent@org.rine.network"

    def test_short_group_handle(self):
        assert normalize_handle("#group@org") == "#group@org.rine.network"

    def test_full_agent_handle_unchanged(self):
        assert normalize_handle("agent@org.rine.network") == "agent@org.rine.network"

    def test_full_group_handle_unchanged(self):
        assert normalize_handle("#group@org.rine.network") == "#group@org.rine.network"

    def test_federated_handle_unchanged(self):
        assert normalize_handle("agent@org.other-provider.com") == "agent@org.other-provider.com"

    def test_bare_name_unchanged(self):
        assert normalize_handle("not-a-handle") == "not-a-handle"

    def test_uuid_unchanged(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert normalize_handle(uuid) == uuid

    def test_empty_string(self):
        assert normalize_handle("") == ""

    def test_multiple_at_uses_last(self):
        assert normalize_handle("a@b@org") == "a@b@org.rine.network"


class TestPublicSurface:
    """Resolver + config helpers are importable from the top-level ``rine`` package.

    These were promoted from private modules (``rine._resolve``/``rine._config``)
    so consumers (e.g. crewai-rine) import stable public names, not privates.
    """

    def test_resolver_helpers_importable_from_rine(self):
        from rine import is_uuid as public_is_uuid
        from rine import normalize_handle as public_normalize_handle

        assert public_is_uuid("550e8400-e29b-41d4-a716-446655440000")
        assert public_normalize_handle("agent@org") == "agent@org.rine.network"

    def test_config_helpers_importable_from_rine(self):
        from rine import resolve_api_url, resolve_config_dir

        assert callable(resolve_api_url)
        assert callable(resolve_config_dir)

    def test_promoted_names_in_dunder_all(self):
        import rine

        for name in ("is_uuid", "normalize_handle", "resolve_api_url", "resolve_config_dir"):
            assert name in rine.__all__
            assert hasattr(rine, name)
