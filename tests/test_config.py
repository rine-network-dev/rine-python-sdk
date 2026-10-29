"""Tests for config dir resolution, profiles, the token cache and the owner dir."""

from __future__ import annotations

import os
import time

import pytest

from rine._config import (
    PROFILES_FILE,
    RETIRED_SIGN_IN_FILE,
    cache_token,
    get_cached_token_entry,
    resolve_api_url,
    resolve_config_dir,
)
from rine._crypto.phrase import entropy_from_phrase
from rine._crypto.pq_keys import UPGRADE_DETAIL
from rine._owner import (
    OWNER_DIR_ENV,
    PHRASE_FILE,
    ROOT_KEY_FILE,
    assert_owner_dir_allowed,
    load_root,
    remove_root,
    resolve_owner_dir,
    save_root,
)
from rine._principal import (
    agent_principal,
    branch_principal,
    org_principal,
    parse_principal,
    reader_principal,
)
from rine._profiles import (
    add_profile_if_absent,
    get_profile,
    load_profiles,
    save_profiles,
)
from rine._types import Profile
from rine._utils import from_base64url, to_base64url
from rine.errors import ConfigError
from rine.testing import WORLD

AGENT_ID = "00000000-1111-2222-3333-444444444444"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ORG_ID = WORLD.org_id


def _entry(principal: str) -> Profile:
    """A minimal runtime profile naming one principal."""
    return Profile(org_id=ORG_ID, principal=principal)


class TestResolveConfigDir:
    def test_env_var_takes_priority(self, tmp_path, monkeypatch):
        custom_dir = str(tmp_path / "custom")
        monkeypatch.setenv("RINE_CONFIG_DIR", custom_dir)
        assert resolve_config_dir() == custom_dir

    def test_xdg_with_profiles(self, tmp_path, monkeypatch):
        monkeypatch.delenv("RINE_CONFIG_DIR", raising=False)
        xdg_dir = tmp_path / ".config" / "rine"
        xdg_dir.mkdir(parents=True)
        (xdg_dir / PROFILES_FILE).write_text("{}")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / p.lstrip("~/")))
        assert resolve_config_dir() == str(xdg_dir)

    def test_resolve_config_dir_when_candidate_holds_both_files_then_accepts_it(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("RINE_CONFIG_DIR", raising=False)
        xdg_dir = tmp_path / ".config" / "rine"
        xdg_dir.mkdir(parents=True)
        (xdg_dir / RETIRED_SIGN_IN_FILE).write_text("{}")
        (xdg_dir / PROFILES_FILE).write_text("{}")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / p.lstrip("~/")))
        assert resolve_config_dir() == str(xdg_dir)

    def test_resolve_config_dir_when_candidate_holds_only_the_retired_file_then_raises_upgrade(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("RINE_CONFIG_DIR", raising=False)
        xdg_dir = tmp_path / ".config" / "rine"
        xdg_dir.mkdir(parents=True)
        (xdg_dir / RETIRED_SIGN_IN_FILE).write_text("{}")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / p.lstrip("~/")))
        with pytest.raises(ConfigError) as excinfo:
            resolve_config_dir()
        assert str(excinfo.value) == UPGRADE_DETAIL

        env_dir = tmp_path / "env"
        env_dir.mkdir()
        (env_dir / RETIRED_SIGN_IN_FILE).write_text("{}")
        monkeypatch.setenv("RINE_CONFIG_DIR", str(env_dir))
        with pytest.raises(ConfigError) as excinfo:
            resolve_config_dir()
        assert str(excinfo.value) == UPGRADE_DETAIL


class TestResolveApiUrl:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("RINE_API_URL", raising=False)
        assert resolve_api_url() == "https://rine.network"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("RINE_API_URL", "https://custom.example.com/")
        assert resolve_api_url() == "https://custom.example.com"


class TestProfiles:
    def test_save_and_load_round_trip(self, tmp_config_dir):
        entry = _entry(str(agent_principal(AGENT_ID)))
        save_profiles(tmp_config_dir, {"default": entry})
        loaded = load_profiles(tmp_config_dir)
        assert loaded["default"]["principal"] == entry["principal"]
        assert loaded["default"]["org_id"] == ORG_ID

    def test_file_permissions(self, tmp_config_dir):
        save_profiles(tmp_config_dir, {"default": _entry(str(agent_principal(AGENT_ID)))})
        stat = os.stat(os.path.join(tmp_config_dir, PROFILES_FILE))
        assert stat.st_mode & 0o777 == 0o600

    def test_save_profiles_when_the_rename_fails_then_no_temp_file_is_left(
        self, tmp_config_dir, monkeypatch
    ):
        """A failed rename keeps the old profiles and removes the temp file."""
        first = {"default": _entry(str(agent_principal(AGENT_ID)))}
        save_profiles(tmp_config_dir, first)

        def refuse_rename(src: str, dst: str) -> None:
            raise OSError("rename refused")

        monkeypatch.setattr(os, "replace", refuse_rename)
        with pytest.raises(OSError, match="rename refused"):
            save_profiles(
                tmp_config_dir, {"default": _entry(str(agent_principal(OTHER_AGENT_ID)))}
            )
        monkeypatch.undo()
        assert os.listdir(tmp_config_dir) == [PROFILES_FILE]
        assert load_profiles(tmp_config_dir) == first

    def test_load_missing_returns_empty(self, tmp_config_dir):
        assert load_profiles(tmp_config_dir) == {}

    def test_load_malformed_returns_empty(self, tmp_config_dir):
        path = os.path.join(tmp_config_dir, PROFILES_FILE)
        os.makedirs(tmp_config_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write("not json{{{")
        assert load_profiles(tmp_config_dir) == {}

    def test_get_profile_returns_named_entry_and_none_for_unknown(self, tmp_config_dir):
        entry = _entry(str(agent_principal(AGENT_ID)))
        save_profiles(tmp_config_dir, {"default": entry})
        assert get_profile(tmp_config_dir) == entry
        assert get_profile(tmp_config_dir, "missing") is None

    def test_add_profile_if_absent_writes_once_and_keeps_the_first(self, tmp_config_dir):
        first = _entry(str(agent_principal(AGENT_ID)))
        second = _entry(str(agent_principal(OTHER_AGENT_ID)))
        assert add_profile_if_absent(tmp_config_dir, "default", first) is True
        assert add_profile_if_absent(tmp_config_dir, "default", second) is False
        assert get_profile(tmp_config_dir) == first

    def test_load_profiles_when_dir_holds_only_the_retired_file_then_raises_upgrade_error(
        self, tmp_config_dir
    ):
        with open(os.path.join(tmp_config_dir, RETIRED_SIGN_IN_FILE), "w") as f:
            f.write("{}")
        with pytest.raises(ConfigError) as excinfo:
            load_profiles(tmp_config_dir)
        assert str(excinfo.value) == UPGRADE_DETAIL


class TestTokenCache:
    def test_cache_and_retrieve(self, tmp_config_dir):
        principal = str(agent_principal(AGENT_ID))
        cache_token(tmp_config_dir, principal, "my-token", 3600)
        cached = get_cached_token_entry(tmp_config_dir, principal)
        assert cached is not None
        assert cached["access_token"] == "my-token"

    def test_entry_carries_the_expiry_it_checked(self, tmp_config_dir):
        # The caller needs the deadline, not just the string: a client that
        # warm-starts from this cache has to seed its own expiry from it.
        #
        # 🔴 The deadline is asserted against the clock the entry was written by,
        # not against the ``now`` it was queried with. ``> 1000.0`` was true of
        # any wall-clock timestamp whatsoever — including one seeded from the
        # wrong field, or a lifetime of zero — because ``now=1000.0`` is a
        # 1970 clock and every real ``time.time()`` beats it. The value is the
        # thing under test, so pin the value.
        principal = str(agent_principal(AGENT_ID))
        t0 = time.time()
        cache_token(tmp_config_dir, principal, "my-token", 3600)
        cached = get_cached_token_entry(tmp_config_dir, principal, now=1000.0)
        assert cached is not None
        assert cached["expires_at"] == pytest.approx(t0 + 3600, abs=5)

    def test_expired_token_returns_none(self, tmp_config_dir):
        principal = str(agent_principal(AGENT_ID))
        cache_token(tmp_config_dir, principal, "old-token", 0)
        assert get_cached_token_entry(tmp_config_dir, principal) is None

    def test_nearly_expired_returns_none(self, tmp_config_dir):
        # Token expires in 30 seconds, but margin is 60
        principal = str(agent_principal(AGENT_ID))
        cache_token(tmp_config_dir, principal, "almost-expired", 30)
        assert get_cached_token_entry(tmp_config_dir, principal) is None

    def test_injected_clock_decides_freshness(self, tmp_config_dir):
        principal = str(agent_principal(AGENT_ID))
        cache_token(tmp_config_dir, principal, "tok", 3600)
        entry = get_cached_token_entry(tmp_config_dir, principal)
        assert entry is not None
        # Same entry, a clock past its expiry: stale.
        assert (
            get_cached_token_entry(tmp_config_dir, principal, now=entry["expires_at"] + 1) is None
        )

    def test_two_principals_in_one_dir_do_not_overwrite_each_other(self, tmp_config_dir):
        first = str(agent_principal(AGENT_ID))
        second = str(agent_principal(OTHER_AGENT_ID))
        cache_token(tmp_config_dir, first, "first-token", 3600)
        cache_token(tmp_config_dir, second, "second-token", 3600)
        first_entry = get_cached_token_entry(tmp_config_dir, first)
        second_entry = get_cached_token_entry(tmp_config_dir, second)
        assert first_entry is not None and first_entry["access_token"] == "first-token"
        assert second_entry is not None and second_entry["access_token"] == "second-token"


class TestOwnerDir:
    def test_resolve_owner_dir_honours_env(self, tmp_path, monkeypatch):
        owner = str(tmp_path / "owner")
        monkeypatch.setenv(OWNER_DIR_ENV, owner)
        assert resolve_owner_dir() == os.path.abspath(owner)

    def test_resolve_owner_dir_defaults_under_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv(OWNER_DIR_ENV, raising=False)
        monkeypatch.setattr("os.path.expanduser", lambda p: str(tmp_path / p.lstrip("~/")))
        assert resolve_owner_dir().endswith(os.path.join(".config", "rine-owner"))

    def test_save_root_writes_key_and_phrase(self, tmp_path):
        owner_dir = str(tmp_path / "owner")
        save_root(owner_dir, WORLD.root)
        with open(os.path.join(owner_dir, ROOT_KEY_FILE)) as f:
            key_text = f.read().strip()
        assert from_base64url(key_text) == WORLD.root
        with open(os.path.join(owner_dir, PHRASE_FILE)) as f:
            phrase_text = f.read().strip()
        assert len(phrase_text.split()) == 24
        assert entropy_from_phrase(phrase_text) == WORLD.root
        assert os.stat(os.path.join(owner_dir, ROOT_KEY_FILE)).st_mode & 0o777 == 0o600
        assert os.stat(os.path.join(owner_dir, PHRASE_FILE)).st_mode & 0o777 == 0o600
        assert os.stat(owner_dir).st_mode & 0o777 == 0o700

    def test_save_root_twice_raises(self, tmp_path):
        owner_dir = str(tmp_path / "owner")
        save_root(owner_dir, WORLD.root)
        with pytest.raises(ConfigError):
            save_root(owner_dir, WORLD.root)

    def test_save_root_when_a_root_lands_after_the_check_then_it_is_kept_and_raises(
        self, tmp_path, monkeypatch
    ):
        owner_dir = tmp_path / "owner"
        owner_dir.mkdir()
        other = to_base64url(bytes(range(32))) + "\n"
        (owner_dir / ROOT_KEY_FILE).write_text(other)
        # Another process writes its root between the freshness check and this write.
        monkeypatch.setattr("rine._owner.has_root", lambda _dir: False)

        with pytest.raises(ConfigError, match="already exists"):
            save_root(str(owner_dir), WORLD.root)

        assert (owner_dir / ROOT_KEY_FILE).read_text() == other
        assert not (owner_dir / PHRASE_FILE).exists()

    def test_assert_owner_dir_allowed_rejects_a_git_worktree(self, tmp_path):
        (tmp_path / ".git").mkdir()
        with pytest.raises(ConfigError):
            assert_owner_dir_allowed(str(tmp_path / "owner"))

    def test_assert_owner_dir_allowed_rejects_project_rine(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ConfigError):
            assert_owner_dir_allowed(str(tmp_path / ".rine"))

    def test_assert_owner_dir_allowed_rejects_a_symlink_into_a_git_worktree(self, tmp_path):
        repo = tmp_path / "dotfiles"
        (repo / ".git").mkdir(parents=True)
        link = tmp_path / "link"
        link.symlink_to(repo)
        with pytest.raises(ConfigError, match="git worktree"):
            assert_owner_dir_allowed(str(link / "owner"))

    def test_assert_owner_dir_allowed_rejects_a_dotdot_alias_of_project_rine(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "sub").mkdir()
        with pytest.raises(ConfigError, match="project .rine"):
            assert_owner_dir_allowed(str(tmp_path / "sub" / ".." / ".rine"))

    @pytest.mark.parametrize("nested", ["", "owner"])
    def test_assert_owner_dir_allowed_rejects_the_runtime_config_dir_and_its_children(
        self, tmp_path, nested
    ):
        config_dir = tmp_path / "cfg"
        with pytest.raises(ConfigError, match="runtime config directory"):
            assert_owner_dir_allowed(str(config_dir / nested), str(config_dir))

    def test_assert_owner_dir_allowed_rejects_an_owner_dir_that_holds_the_config_dir(
        self, tmp_path
    ):
        owner_dir = tmp_path / "owner"
        with pytest.raises(ConfigError, match="runtime config directory"):
            assert_owner_dir_allowed(str(owner_dir), str(owner_dir / "cfg"))

    def test_load_root_when_empty_then_none(self, tmp_path):
        assert load_root(str(tmp_path / "empty")) is None

    def test_load_root_when_corrupt_then_raises(self, tmp_path):
        owner_dir = tmp_path / "owner"
        owner_dir.mkdir()
        (owner_dir / ROOT_KEY_FILE).write_text(to_base64url(b"too short") + "\n")
        with pytest.raises(ConfigError):
            load_root(str(owner_dir))

    def test_remove_root_removes_both_files_and_tolerates_absence(self, tmp_path):
        owner_dir = str(tmp_path / "owner")
        save_root(owner_dir, WORLD.root)
        remove_root(owner_dir)
        assert not os.path.exists(os.path.join(owner_dir, ROOT_KEY_FILE))
        assert not os.path.exists(os.path.join(owner_dir, PHRASE_FILE))
        remove_root(owner_dir)


class TestPrincipal:
    @pytest.mark.parametrize(
        "principal",
        [
            org_principal(ORG_ID),
            branch_principal(ORG_ID, "main"),
            agent_principal(AGENT_ID),
            reader_principal(ORG_ID),
            reader_principal(ORG_ID, "main"),
        ],
    )
    def test_str_parse_round_trip(self, principal):
        assert parse_principal(str(principal)) == principal

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "org",
            "agent:not-a-uuid",
            f"branch:{ORG_ID}",
            f"org:{ORG_ID}:extra",
            f"robot:{ORG_ID}",
        ],
    )
    def test_parse_principal_when_invalid_then_raises(self, text):
        with pytest.raises(ConfigError):
            parse_principal(text)
