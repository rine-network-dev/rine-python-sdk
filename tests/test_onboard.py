"""Tests for onboarding — slug validation and the org register flow."""

from __future__ import annotations

import json
import os

import httpx
import pytest
import respx

from rine._config import get_cached_token_entry
from rine._crypto.derive_nodes import derive_branch, derive_org
from rine._crypto.jws import JwsTyp, verify_jws
from rine._crypto.org_words import org_words
from rine._onboard import _Mint, async_register, register, validate_slug
from rine._org_certs import branch_key_body
from rine._owner import PHRASE_FILE, ROOT_KEY_FILE, load_root
from rine._profiles import load_profiles
from rine._utils import to_base64url
from rine.errors import ConfigError, ConflictError, CryptoError, RineError, ServiceUnavailableError
from rine.testing import WORLD, write_owner
from rine.types import RegistrationResult

API = "https://rine.network"
EMAIL = "ops@acme.test"
SLUG = "acme"
NAME = "Acme"
CHALLENGE = {
    "challenge_id": "c1",
    "algorithm": "rsa-timelock-v1",
    "prefix": "p",
    "modulus": "7",
    "difficulty": 1,
}
_SECRET_WORDS = ("root", "seed", "secret", "private")


class TestValidateSlug:
    def test_valid_slugs(self):
        assert validate_slug("acme")
        assert validate_slug("my-org")
        assert validate_slug("ab")
        assert validate_slug("a0")
        assert validate_slug("a" * 32)

    def test_invalid_slugs(self):
        assert not validate_slug("")
        assert not validate_slug("a")  # too short
        assert not validate_slug("-start")  # leading hyphen
        assert not validate_slug("end-")  # trailing hyphen
        assert not validate_slug("UPPER")  # uppercase
        assert not validate_slug("has space")
        assert not validate_slug("a" * 33)  # too long
        assert not validate_slug("has_underscore")


class TestTheRegisterSpelling:
    """The word the rest of the product uses is bound here too.

    ``rine.onboard`` is this SDK's name for the call; the TypeScript SDK, the
    CLI and every piece of prose about day one say *register*. A reader who
    reached for that word found nothing bound to it, and an SDK cannot be
    discovered by the name its own documentation uses everywhere else.
    """

    def test_register_when_imported_from_the_root_then_is_the_same_object_as_onboard(self):
        import rine

        # Identity, not equality: two functions would be two implementations
        # that can drift, and a caller passing one to a mock would not see the
        # other patched.
        assert rine.register is rine.onboard
        assert rine.async_register is rine.async_onboard

    def test_register_when_reading_the_public_surface_then_both_spellings_are_exported(self):
        import rine

        assert {"register", "async_register", "onboard", "async_onboard"} <= set(rine.__all__)


def _mock_routes(
    owner_dir: str,
    *,
    challenge: dict = CHALLENGE,
    solve_status: int = 200,
    token_status: int = 200,
    served_org_id: str | None = None,
):
    """Register the three routes registration touches, with no real PoW.

    The solve route answers with the org id the client committed to, read back
    from the ``root.key`` the client wrote before the request — exactly what a
    server that accepted the registration would echo.
    """
    begin = respx.post(f"{API}/auth/register").mock(
        return_value=httpx.Response(200, json=challenge)
    )

    def _solve(request: httpx.Request) -> httpx.Response:
        if solve_status != 200:
            return httpx.Response(solve_status, json={"detail": "refused"})
        root = load_root(owner_dir)
        assert root is not None
        return httpx.Response(200, json={"org_id": served_org_id or derive_org(root).org_id})

    solve = respx.post(f"{API}/auth/register/solve").mock(side_effect=_solve)
    token = respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(token_status, json={"access_token": "tok", "expires_in": 900})
    )
    return begin, solve, token


def _no_pow(monkeypatch) -> None:
    """Replace the time-lock solver so no proof of work ever runs."""
    monkeypatch.setattr("rine._onboard.solve_timelock", lambda *args, **kwargs: "nonce")


def _minted_org(owner_dir: str):
    """The org node derived from the root the client wrote to ``owner_dir``."""
    root = load_root(owner_dir)
    assert root is not None
    return derive_org(root)


class TestMintFromRoot:
    """The fleet enrols from a root it already holds, not one it mints."""

    def test_from_root_when_called_twice_then_the_derivation_is_the_same(self):
        root = bytes(range(32))
        first, second = _Mint.from_root(root), _Mint.from_root(root)
        assert first.org.org_id == second.org.org_id
        assert first.main.b_read == second.main.b_read
        assert first.main.b_sign == second.main.b_sign
        assert first.main.ed_pk == second.main.ed_pk

    def test_from_root_when_the_root_is_short_then_it_is_refused(self):
        with pytest.raises(CryptoError):
            _Mint.from_root(bytes(31))


def _assert_registration_written(owner: str, result: RegistrationResult) -> None:
    """Every artifact a successful registration leaves behind, checked once."""
    org = _minted_org(owner)
    assert isinstance(result, RegistrationResult)
    assert result.org_id == org.org_id
    assert result.org_words == org_words(org.org_id)
    assert result.phrase_path.endswith("recovery-phrase.txt")
    assert os.path.isfile(result.phrase_path)

    assert os.stat(os.path.join(owner, ROOT_KEY_FILE)).st_mode & 0o777 == 0o600
    assert os.stat(result.phrase_path).st_mode & 0o777 == 0o600

    assert load_profiles(owner)["default"]["principal"] == f"org:{org.org_id}"

    with open(result.phrase_path) as f:
        phrase = f.read().strip()
    assert all(phrase not in str(value) for value in result.model_dump().values())

    assert get_cached_token_entry(owner, f"org:{org.org_id}") is not None


class TestRegisterBegin:
    @respx.mock
    def test_register_when_begin_then_posts_only_public_org_keys(self, tmp_path, monkeypatch):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        begin, _, _ = _mock_routes(owner)

        register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        body = json.loads(begin.calls[0].request.content)
        org = _minted_org(owner)
        assert body["org_id"] == org.org_id
        assert body["org_signing_public_key"] == to_base64url(org.ed_pk)
        assert body["org_pq_signing_public_key"] == to_base64url(org.dsa_pk)
        assert not any(word in key for key in body for word in _SECRET_WORDS)


FORWARDED = {"X-Forwarded-For": "10.7.0.9"}


def _forwarded(*routes) -> list[str | None]:
    """The ``X-Forwarded-For`` every request on ``routes`` carried."""
    return [call.request.headers.get("x-forwarded-for") for r in routes for call in r.calls]


class TestRegisterExtraHeaders:
    @respx.mock
    def test_register_when_extra_headers_given_then_every_request_carries_them(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        routes = _mock_routes(owner)

        register(
            API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner, extra_headers=FORWARDED
        )

        assert _forwarded(*routes) == ["10.7.0.9"] * 3

    @respx.mock
    def test_register_when_no_extra_headers_then_none_is_sent(self, tmp_path, monkeypatch):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        routes = _mock_routes(owner)

        register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert _forwarded(*routes) == [None] * 3

    @respx.mock
    async def test_async_register_when_extra_headers_given_then_every_request_carries_them(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        routes = _mock_routes(owner)

        await async_register(
            API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner, extra_headers=FORWARDED
        )

        assert _forwarded(*routes) == ["10.7.0.9"] * 3


class TestRegisterSolve:
    @respx.mock
    def test_register_when_solve_then_carries_branch_cert_and_proof(self, tmp_path, monkeypatch):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _, solve, _ = _mock_routes(owner)

        register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        body = json.loads(solve.calls[0].request.content)
        org = _minted_org(owner)
        main = derive_branch(org.r_read, org.r_sign, "main")

        branch = body["main_branch"]
        assert set(branch) == set(branch_key_body(main, "cert"))
        claims = verify_jws(branch["certificate"], org.ed_pk, JwsTyp.BRANCH_CERT)
        assert claims["org"] == org.org_id

        proof = verify_jws(body["proof"], org.ed_pk, JwsTyp.REGISTER_POP)
        assert proof["aud"] == f"{API}/auth/register/solve"
        assert proof["challenge_id"] == "c1"

        assert body["reader_public_key"]
        assert body["consent"] is True


class TestRegisterSuccess:
    @respx.mock
    def test_register_when_solve_succeeds_then_writes_root_phrase_profile_and_token(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner)

        result = register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        _assert_registration_written(owner, result)


class TestRegisterFailures:
    @respx.mock
    def test_register_when_solve_conflicts_then_removes_root_and_phrase(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, solve_status=409)

        with pytest.raises(ConflictError):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert not os.path.exists(os.path.join(owner, ROOT_KEY_FILE))
        assert not os.path.exists(os.path.join(owner, PHRASE_FILE))

    @respx.mock
    def test_register_when_solve_unavailable_then_keeps_root(self, tmp_path, monkeypatch):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, solve_status=503)

        with pytest.raises(ServiceUnavailableError):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert os.path.isfile(os.path.join(owner, ROOT_KEY_FILE))

    @respx.mock
    def test_register_when_server_names_another_org_then_refuses_and_writes_no_profile(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, served_org_id=WORLD.org_id)

        with pytest.raises(RineError, match="does not match your root"):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert load_profiles(owner) == {}
        assert os.path.isfile(os.path.join(owner, ROOT_KEY_FILE))

    @respx.mock
    def test_register_when_algorithm_unsupported_then_refuses_before_writing_root(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, challenge={**CHALLENGE, "algorithm": "sha256-v1"})

        with pytest.raises(RineError, match="Unsupported PoW algorithm"):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert not os.path.exists(os.path.join(owner, ROOT_KEY_FILE))

    @respx.mock
    def test_register_when_token_fetch_fails_then_registration_still_succeeds(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, token_status=500)

        result = register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert result.org_id == _minted_org(owner).org_id
        assert os.path.isfile(os.path.join(owner, ROOT_KEY_FILE))


class TestRegisterGuards:
    @respx.mock
    def test_register_when_owner_dir_has_root_then_refuses_and_posts_nothing(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        write_owner(owner)
        begin, _, _ = _mock_routes(owner)

        with pytest.raises(ConfigError):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert not begin.called

    @respx.mock
    def test_register_when_owner_dir_in_git_worktree_then_refuses(self, tmp_path, monkeypatch):
        _no_pow(monkeypatch)
        (tmp_path / ".git").mkdir()
        owner = str(tmp_path / "o")
        _mock_routes(owner)

        with pytest.raises(ConfigError):
            register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

    @respx.mock
    def test_register_when_slug_invalid_then_refuses_before_any_request(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        begin, _, _ = _mock_routes(owner)

        with pytest.raises(RineError):
            register(API, str(tmp_path / "cfg"), EMAIL, "Bad Slug", NAME, owner_dir=owner)

        assert not begin.called


class TestAsyncRegister:
    @respx.mock
    async def test_async_register_when_server_names_another_org_then_refuses(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner, served_org_id=WORLD.org_id)

        with pytest.raises(RineError, match="does not match your root"):
            await async_register(API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner)

        assert load_profiles(owner) == {}

    @respx.mock
    async def test_async_register_when_solve_succeeds_then_writes_root_phrase_profile_and_token(
        self, tmp_path, monkeypatch
    ):
        _no_pow(monkeypatch)
        owner = str(tmp_path / "owner")
        _mock_routes(owner)

        result = await async_register(
            API, str(tmp_path / "cfg"), EMAIL, SLUG, NAME, owner_dir=owner
        )

        _assert_registration_written(owner, result)
