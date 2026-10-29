"""Recovery from the 24-word phrase: what is rebuilt, refused and never echoed.

Every key response comes from :data:`rine.testing.WORLD`, so a
restored agent is checked against the same certificate chain production runs.
"""

from __future__ import annotations

import os
from dataclasses import replace

import httpx
import pytest
import respx

from rine._config import get_cached_token_entry, keys_dir
from rine._crypto.keys import load_agent_keys, save_agent_keys
from rine._crypto.org_words import org_words
from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_gap import DrainGap, EscrowLoss, write_gap
from rine._crypto.phrase import PhraseError, phrase_from_entropy
from rine._owner import has_root, load_root
from rine._principal import org_principal
from rine._profiles import get_profile
from rine._recover import (
    NO_ORG_FOR_PHRASE,
    RECOVERY_NOTES,
    AgentRecoveryStatus,
    async_recover_org,
    recover_org,
)
from rine.errors import AuthenticationError, ConfigError, CryptoError, InternalServerError
from rine.testing import WORLD, World, write_owner

API = "https://rine.network"
PHRASE = phrase_from_entropy(WORLD.root)
ALPHA = "00000000-1111-2222-3333-444444444444"
BETA = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _mock_token(status: int = 200, refusal: dict[str, str] | None = None) -> None:
    """Answer ``POST /oauth/token``, with a refusal (``{"detail": "no"}`` by default) when asked."""
    ok = {"access_token": "test-token", "expires_in": 900}
    body = ok if status == 200 else (refusal or {"detail": "no"})
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(status, json=body))


def _mock_branches() -> None:
    """Answer ``GET /orgs/me/branches`` with the one branch the world derives."""
    respx.get(f"{API}/orgs/me/branches").mock(
        return_value=httpx.Response(200, json={"branches": [{"name": "main"}]})
    )


def _mock_agents() -> None:
    """Answer ``GET /agents`` with the two agents every case restores."""
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={"items": [{"id": ALPHA, "name": "alpha"}, {"id": BETA, "name": "beta"}]},
        )
    )


def _mock_keys(agent_id: str, body: dict | None = None, *, newer: bool = False) -> None:
    """Answer ``GET /agents/{id}/keys`` with the world's chain, or a tampered copy.

    The next generation (``?gen=``) is a 404 unless ``newer``: a rolled-back server still serves it.
    """
    served = body if body is not None else WORLD.keys_response(agent_id)

    def answer(request: httpx.Request) -> httpx.Response:
        if "gen" in request.url.params and not newer:
            return httpx.Response(404, json={"detail": "Key generation not found"})
        return httpx.Response(200, json=served)

    respx.get(f"{API}/agents/{agent_id}/keys").mock(side_effect=answer)


def _mock_happy_routes() -> None:
    """Register every route a clean recovery reads."""
    _mock_token()
    _mock_branches()
    _mock_agents()
    _mock_keys(ALPHA)
    _mock_keys(BETA)
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": []}))


def _owner_dir(tmp_path) -> str:
    """A fresh owner dir under the test's tmp path."""
    return str(tmp_path / "owner")


def _config_dir(tmp_path) -> str:
    """A fresh runtime config dir under the test's tmp path."""
    return str(tmp_path / "config")


@respx.mock
def test_recover_when_the_phrase_matches_then_both_agents_are_restored(tmp_path):
    """A clean recovery rebuilds the root, both agents' leaves and the org profile."""
    _mock_happy_routes()
    config_dir, owner_dir = _config_dir(tmp_path), _owner_dir(tmp_path)

    report = recover_org(API, config_dir, PHRASE, owner_dir=owner_dir)

    assert report.org_id == WORLD.org_id
    assert report.branches == ["main"]
    assert [a.status for a in report.agents] == [
        AgentRecoveryStatus.RESTORED,
        AgentRecoveryStatus.RESTORED,
    ]
    assert report.closed_groups == []
    assert report.notes == RECOVERY_NOTES
    assert load_root(owner_dir) == WORLD.root
    for agent_id in (ALPHA, BETA):
        assert load_agent_keys(config_dir, agent_id) == WORLD.keys(agent_id)
    assert get_profile(owner_dir)["principal"] == str(org_principal(WORLD.org_id))
    entry = get_cached_token_entry(owner_dir, str(org_principal(WORLD.org_id)))
    assert entry is not None and entry["access_token"] == "test-token"


@respx.mock
def test_recover_when_org_words_are_offered_then_the_callback_runs_before_any_request(tmp_path):
    """The words reach the user before the first byte leaves the process."""
    _mock_happy_routes()
    seen: list[tuple[str, int]] = []

    recover_org(
        API,
        _config_dir(tmp_path),
        PHRASE,
        owner_dir=_owner_dir(tmp_path),
        on_org_words=lambda words: seen.append((words, respx.calls.call_count)),
    )

    assert seen == [(org_words(WORLD.org_id), 0)]


@respx.mock
def test_recover_when_a_restored_agent_has_gap_markers_then_the_report_lists_them(tmp_path):
    """Every marker on disk for a restored agent is in the report, with its reason."""
    _mock_happy_routes()
    config_dir, owner_dir = _config_dir(tmp_path), _owner_dir(tmp_path)
    group = "c3d4e5f6-a7b8-9012-cdef-123456789012"
    write_gap(config_dir, ALPHA, group, DrainGap(6, EscrowGapReason.CONTEXT_TOO_LARGE))
    write_gap(config_dir, ALPHA, group, DrainGap(9, EscrowLoss.REFUSED), bytes.fromhex("07" * 16))

    report = recover_org(API, config_dir, PHRASE, owner_dir=owner_dir)

    assert [(m.agent_id, m.group_id, m.epoch, m.fork, m.reason) for m in report.gap_markers] == [
        (ALPHA, group, 6, None, EscrowGapReason.CONTEXT_TOO_LARGE),
        (ALPHA, group, 9, "07" * 16, EscrowLoss.REFUSED),
    ]


@respx.mock
def test_recover_when_the_token_is_refused_then_no_org_matches_and_nothing_is_written(tmp_path):
    """A 401 is the phrase naming no org, and it leaves both dirs untouched."""
    _mock_token(401)
    config_dir, owner_dir = _config_dir(tmp_path), _owner_dir(tmp_path)

    with pytest.raises(ConfigError) as err:
        recover_org(API, config_dir, PHRASE, owner_dir=owner_dir)

    assert str(err.value) == NO_ORG_FOR_PHRASE
    assert not os.path.exists(os.path.join(config_dir, "keys"))
    assert not has_root(owner_dir)
    assert not os.path.exists(os.path.join(owner_dir, "profiles.json"))


@respx.mock
def test_recover_when_the_clock_is_off_then_the_refusal_names_the_clock_not_the_phrase(tmp_path):
    """A signed assertion refused for its time window is not "no org matches this phrase"."""
    refusal = {"error": "invalid_client", "reason": "clock_skew", "detail": "clock skew"}
    _mock_token(401, refusal)
    config_dir, owner_dir = _config_dir(tmp_path), _owner_dir(tmp_path)

    with pytest.raises(AuthenticationError) as err:
        recover_org(API, config_dir, PHRASE, owner_dir=owner_dir)

    assert "clock skew" in str(err.value)
    assert not has_root(owner_dir)


@respx.mock
def test_recover_when_a_public_key_differs_then_that_agent_mismatches_and_keeps_no_keys(tmp_path):
    """One tampered key refuses that agent alone, and writes no leaf for it."""
    _mock_token()
    _mock_branches()
    _mock_agents()
    tampered = WORLD.keys_response(ALPHA)
    tampered["signing_public_key"] = {**tampered["signing_public_key"], "x": "AAAA"}
    _mock_keys(ALPHA, tampered)
    _mock_keys(BETA)
    config_dir = _config_dir(tmp_path)

    report = recover_org(API, config_dir, PHRASE, owner_dir=_owner_dir(tmp_path))

    alpha, beta = report.agents
    assert alpha.status == AgentRecoveryStatus.MISMATCH
    assert "signing_public_key" in alpha.reason
    assert beta.status == AgentRecoveryStatus.RESTORED
    assert not os.path.isdir(keys_dir(config_dir, ALPHA))
    assert os.path.isdir(keys_dir(config_dir, BETA))


@respx.mock
def test_recover_when_the_agent_cert_is_signed_elsewhere_then_it_does_not_verify(tmp_path):
    """A cert from another branch key is refused as unverifiable."""
    _mock_token()
    _mock_branches()
    _mock_agents()
    other = World(root=bytes([9]) * 32)
    body = WORLD.keys_response(ALPHA)
    body["agent_certificate"] = other.agent_certificate(other.node(ALPHA))
    _mock_keys(ALPHA, body)
    _mock_keys(BETA)

    report = recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=_owner_dir(tmp_path))

    assert report.agents[0].status == AgentRecoveryStatus.MISMATCH
    assert "does not verify" in report.agents[0].reason


@respx.mock
def test_recover_when_the_branch_is_unlisted_then_it_is_not_derivable(tmp_path):
    """An agent on a branch the org does not list cannot be derived from the phrase."""
    _mock_token()
    _mock_branches()
    _mock_agents()
    body = WORLD.keys_response(ALPHA)
    body["branch"] = "release"
    _mock_keys(ALPHA, body)
    _mock_keys(BETA)

    report = recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=_owner_dir(tmp_path))

    assert report.agents[0].status == AgentRecoveryStatus.MISMATCH
    assert "branch is not derivable" in report.agents[0].reason


@respx.mock
def test_recover_when_the_server_serves_an_older_generation_than_the_device_holds_then_it_is_refused(
    tmp_path,
):
    """A rollback to a superseded generation is not stored as current."""
    _mock_happy_routes()
    config_dir = _config_dir(tmp_path)
    save_agent_keys(config_dir, ALPHA, replace(WORLD.keys(ALPHA), key_gen=5))

    report = recover_org(API, config_dir, PHRASE, owner_dir=_owner_dir(tmp_path))

    alpha, beta = report.agents
    assert alpha.status == AgentRecoveryStatus.MISMATCH
    assert "older than the one held" in alpha.reason
    assert load_agent_keys(config_dir, ALPHA).key_gen == 5
    assert beta.status == AgentRecoveryStatus.RESTORED


@respx.mock
def test_recover_when_the_server_serves_a_newer_generation_than_it_reports_then_the_agent_mismatches(
    tmp_path,
):
    """A server that reports an old generation as current while holding newer ones is a rollback."""
    _mock_happy_routes()
    _mock_keys(ALPHA, newer=True)
    config_dir = _config_dir(tmp_path)

    report = recover_org(API, config_dir, PHRASE, owner_dir=_owner_dir(tmp_path))

    alpha, beta = report.agents
    assert alpha.status == AgentRecoveryStatus.MISMATCH
    assert "below one it also serves" in alpha.reason
    assert beta.status == AgentRecoveryStatus.RESTORED
    with pytest.raises(CryptoError):
        load_agent_keys(config_dir, ALPHA)


@respx.mock
def test_recover_when_a_later_agent_cannot_be_read_then_no_leaf_keys_are_written(tmp_path):
    """Nothing is written until every agent has been checked."""
    _mock_token()
    _mock_branches()
    _mock_agents()
    _mock_keys(ALPHA)
    respx.get(f"{API}/agents/{BETA}/keys").mock(
        return_value=httpx.Response(500, json={"detail": "boom"})
    )
    config_dir = _config_dir(tmp_path)

    with pytest.raises(InternalServerError):
        recover_org(API, config_dir, PHRASE, owner_dir=_owner_dir(tmp_path))

    assert not os.path.isdir(keys_dir(config_dir, ALPHA))


@respx.mock
def test_recover_when_the_token_endpoint_rate_limits_then_it_retries(tmp_path, monkeypatch):
    """A 429 is retried like any other token fetch, not reported as a failed recovery."""
    monkeypatch.setattr("rine._http.time.sleep", lambda _s: None)
    _mock_branches()
    _mock_agents()
    _mock_keys(ALPHA)
    _mock_keys(BETA)
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": []}))
    respx.post(f"{API}/oauth/token").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}, json={"detail": "slow"}),
            httpx.Response(200, json={"access_token": "t", "expires_in": 900}),
        ]
    )

    report = recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=_owner_dir(tmp_path))

    assert [a.status for a in report.agents] == [AgentRecoveryStatus.RESTORED] * 2


@respx.mock
def test_recover_when_a_later_request_fails_then_no_root_is_written(tmp_path):
    """A 500 after the token leaves the owner dir without a root."""
    _mock_token()
    _mock_branches()
    respx.get(f"{API}/agents").mock(return_value=httpx.Response(500, json={"detail": "boom"}))
    owner_dir = _owner_dir(tmp_path)

    with pytest.raises(InternalServerError):
        recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=owner_dir)

    assert not has_root(owner_dir)


@respx.mock
def test_recover_when_the_owner_dir_holds_a_root_then_it_refuses_before_any_request(tmp_path):
    """One org per owner dir is checked before the phrase is even decoded."""
    owner_dir = _owner_dir(tmp_path)
    write_owner(owner_dir)

    with pytest.raises(ConfigError):
        recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=owner_dir)

    assert respx.calls.call_count == 0


@respx.mock
def test_recover_when_the_phrase_is_malformed_then_it_refuses_before_any_request(tmp_path):
    """A phrase that is not 24 valid words never reaches the network."""
    with pytest.raises(PhraseError):
        recover_org(API, _config_dir(tmp_path), "one two three", owner_dir=_owner_dir(tmp_path))

    assert respx.calls.call_count == 0


@respx.mock
def test_recover_when_no_org_matches_then_the_refusal_does_not_echo_the_phrase(tmp_path):
    _mock_token(401)

    with pytest.raises(ConfigError) as refused:
        recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=_owner_dir(tmp_path))

    assert PHRASE not in str(refused.value)


@respx.mock
def test_recover_when_the_owner_dir_holds_a_root_then_the_refusal_does_not_echo_the_phrase(
    tmp_path,
):
    owner_dir = _owner_dir(tmp_path)
    write_owner(owner_dir)

    with pytest.raises(ConfigError) as existing:
        recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=owner_dir)

    assert PHRASE not in str(existing.value)


@respx.mock
def test_recover_when_it_succeeds_then_the_report_does_not_echo_the_phrase(tmp_path):
    _mock_happy_routes()

    report = recover_org(API, _config_dir(tmp_path), PHRASE, owner_dir=_owner_dir(tmp_path))

    assert PHRASE not in repr(report)
    assert PHRASE not in str(report)


@pytest.mark.asyncio
@respx.mock
async def test_async_recover_when_the_phrase_matches_then_both_agents_are_restored(tmp_path):
    """The async twin rebuilds the same root and leaves as the sync one."""
    _mock_happy_routes()
    config_dir, owner_dir = _config_dir(tmp_path), _owner_dir(tmp_path)

    report = await async_recover_org(API, config_dir, PHRASE, owner_dir=owner_dir)

    assert report.org_id == WORLD.org_id
    assert [a.status for a in report.agents] == [
        AgentRecoveryStatus.RESTORED,
        AgentRecoveryStatus.RESTORED,
    ]
    assert load_root(owner_dir) == WORLD.root
    assert load_agent_keys(config_dir, ALPHA) == WORLD.keys(ALPHA)
