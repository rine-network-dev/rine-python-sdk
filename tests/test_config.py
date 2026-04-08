"""Tests for config directory resolution and credential management."""

from __future__ import annotations

import json
import os
import time

import pytest

from rine._config import (
    cache_token,
    get_cached_token,
    get_credential_entry,
    load_credentials,
    load_token_cache,
    resolve_api_url,
    resolve_config_dir,
    save_credentials,
)
from rine.errors import ConfigError


class TestResolveConfigDir:
    def test_env_var_takes_priority(self, tmp_path, monkeypatch):
        custom_dir = str(tmp_path / "custom")
        monkeypatch.setenv("RINE_CONFIG_DIR", custom_dir)
        assert resolve_config_dir() == custom_dir

    def test_xdg_with_credentials(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RINE_CONFIG_DIR", raising=False)
        xdg_dir = tmp_path / ".config" / "rine"
        xdg_dir.mkdir(parents=True)
        (xdg_dir / "credentials.json").write_text("{}")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / p.lstrip("~/")))
        result = resolve_config_dir()
        assert "rine" in result


class TestResolveApiUrl:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("RINE_API_URL", raising=False)
        assert resolve_api_url() == "https://rine.network"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("RINE_API_URL", "https://custom.example.com/")
        assert resolve_api_url() == "https://custom.example.com"


class TestCredentials:
    def test_save_and_load_round_trip(self, tmp_config_dir):
        creds = {
            "default": {"client_id": "test-id", "client_secret": "test-secret"}
        }
        save_credentials(tmp_config_dir, creds)
        loaded = load_credentials(tmp_config_dir)
        assert loaded["default"]["client_id"] == "test-id"

    def test_file_permissions(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {"default": {"client_id": "a", "client_secret": "b"}})
        path = os.path.join(tmp_config_dir, "credentials.json")
        stat = os.stat(path)
        assert stat.st_mode & 0o777 == 0o600

    def test_load_missing_returns_empty(self, tmp_config_dir):
        assert load_credentials(tmp_config_dir) == {}

    def test_load_malformed_returns_empty(self, tmp_config_dir):
        path = os.path.join(tmp_config_dir, "credentials.json")
        os.makedirs(tmp_config_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write("not json{{{")
        assert load_credentials(tmp_config_dir) == {}

    def test_env_vars_take_priority(self, tmp_config_dir, monkeypatch):
        monkeypatch.setenv("RINE_CLIENT_ID", "env-id")
        monkeypatch.setenv("RINE_CLIENT_SECRET", "env-secret")
        save_credentials(tmp_config_dir, {"default": {"client_id": "file-id", "client_secret": "x"}})
        entry = get_credential_entry(tmp_config_dir)
        assert entry is not None
        assert entry["client_id"] == "env-id"

    def test_get_entry_from_file(self, tmp_config_dir, monkeypatch):
        monkeypatch.delenv("RINE_CLIENT_ID", raising=False)
        monkeypatch.delenv("RINE_CLIENT_SECRET", raising=False)
        save_credentials(tmp_config_dir, {"default": {"client_id": "file-id", "client_secret": "s"}})
        entry = get_credential_entry(tmp_config_dir)
        assert entry is not None
        assert entry["client_id"] == "file-id"

    def test_get_entry_missing_returns_none(self, tmp_config_dir, monkeypatch):
        monkeypatch.delenv("RINE_CLIENT_ID", raising=False)
        monkeypatch.delenv("RINE_CLIENT_SECRET", raising=False)
        assert get_credential_entry(tmp_config_dir) is None


class TestTokenCache:
    def test_cache_and_retrieve(self, tmp_config_dir):
        cache_token(tmp_config_dir, "default", "my-token", 3600)
        cached = get_cached_token(tmp_config_dir)
        assert cached == "my-token"

    def test_expired_token_returns_none(self, tmp_config_dir):
        cache_token(tmp_config_dir, "default", "old-token", 0)
        assert get_cached_token(tmp_config_dir) is None

    def test_nearly_expired_returns_none(self, tmp_config_dir):
        # Token expires in 30 seconds, but margin is 60
        cache_token(tmp_config_dir, "default", "almost-expired", 30)
        assert get_cached_token(tmp_config_dir) is None
