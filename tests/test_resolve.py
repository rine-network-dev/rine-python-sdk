"""Tests for agent and handle resolution."""

from __future__ import annotations

import pytest

from rine._resolve import (
    is_bare_agent_name,
    is_uuid,
    normalize_handle,
    resolve_agent,
    resolve_bare_name,
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


class TestIsBareAgentName:
    def test_bare_name(self):
        assert is_bare_agent_name("my-agent")

    def test_handle_is_not_bare(self):
        assert not is_bare_agent_name("agent@org.rine.network")

    def test_uuid_is_not_bare(self):
        assert not is_bare_agent_name("12345678-1234-1234-1234-123456789abc")


class TestResolveBareName:
    def test_case_insensitive_match(self):
        agents = [{"id": "uuid-1", "name": "My-Agent", "handle": "my-agent@org.rine.network"}]
        assert resolve_bare_name(agents, "my-agent") == "uuid-1"
        assert resolve_bare_name(agents, "MY-AGENT") == "uuid-1"

    def test_no_match_raises(self):
        agents = [{"id": "uuid-1", "name": "other", "handle": "other@org.rine.network"}]
        with pytest.raises(NotFoundError, match="No agent named"):
            resolve_bare_name(agents, "missing")


class TestResolveAgent:
    def test_single_agent_auto_selected(self):
        agents = [{"id": "uuid-1", "name": "bot", "handle": "bot@org.rine.network"}]
        assert resolve_agent(agents) == "uuid-1"

    def test_explicit_uuid(self):
        agents = [{"id": "uuid-1", "name": "bot"}]
        result = resolve_agent(agents, explicit="12345678-1234-1234-1234-123456789abc")
        assert result == "12345678-1234-1234-1234-123456789abc"

    def test_explicit_name(self):
        agents = [
            {"id": "uuid-1", "name": "bot1"},
            {"id": "uuid-2", "name": "bot2"},
        ]
        assert resolve_agent(agents, explicit="bot2") == "uuid-2"

    def test_multiple_agents_no_explicit_raises(self):
        agents = [{"id": "uuid-1", "name": "a"}, {"id": "uuid-2", "name": "b"}]
        with pytest.raises(ConfigError, match="Multiple agents"):
            resolve_agent(agents)

    def test_no_agents_raises(self):
        with pytest.raises(ConfigError, match="No agents"):
            resolve_agent([])

    def test_as_flag_used_when_no_explicit(self):
        agents = [
            {"id": "uuid-1", "name": "bot1"},
            {"id": "uuid-2", "name": "bot2"},
        ]
        assert resolve_agent(agents, as_flag="bot1") == "uuid-1"


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
