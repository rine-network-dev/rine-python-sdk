"""The key-package top-up that rides on ``group sync`` — driven for real.

The twin of ``rine-core/test/group-recovery-topup.test.ts``. Both stacks fold
the top-up into the same verb, in the same order, so both carry the same gate; a
top-up that shipped on one stack alone would leave the other's agents un-addable
while every suite read green.

**The ordering is the whole subject.** An agent whose published key packages have
run out is un-addable — no member can mint it a Welcome, so a carried vote seats
it on the roster with no leaf in the ratchet tree — and
:func:`~rine._mls.resync.recover_mls_group` answers exactly that agent by
RAISING, because its local state never existed. A top-up attached to the returned
result would therefore run for every group except the one it exists to fix, and
``tests/test_group_sync.py`` cannot see the difference: it stubs the top-up away,
because its subject is which recovery a group gets.

Lives in ``tests/contract/`` because that is the directory ``ci.sh`` runs for
this package (stage ``[4/8] rine-sdk contract``): ``rine-sdk/tests/`` at large is
gated only by the publish train.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._mls import KEY_PACKAGE_TARGET, reset_mls_heartbeat_gate
from rine._mls.resync import MlsRecoveryResult
from rine._resources.group_sync import _recover_mls_with_top_up
from rine.errors import MlsResyncUnavailableError

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

REPLAYED = MlsRecoveryResult(
    regime="mls",
    rung="replay",
    from_epoch=4,
    epoch=9,
    behind=5,
    processed=5,
    evicted=False,
)


@pytest.fixture(autouse=True)
def _fresh_rescue_gate():
    """Per process by design, so a test must not inherit the last one's rescue."""
    reset_mls_heartbeat_gate()
    yield
    reset_mls_heartbeat_gate()


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _mock_upload(agent_id: str) -> respx.Route:
    return respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(200, json={"stored": KEY_PACKAGE_TARGET})
    )


def _ladder_raises(monkeypatch) -> None:
    """The ladder as an agent with no local state meets it: a refusal."""

    def _refuse(*_args, **_kwargs):
        raise MlsResyncUnavailableError(GROUP_ID)

    monkeypatch.setattr("rine._resources.group_sync.recover_mls_group_or_reseat", _refuse)


def _ladder_returns(monkeypatch, result: MlsRecoveryResult = REPLAYED) -> None:
    monkeypatch.setattr(
        "rine._resources.group_sync.recover_mls_group_or_reseat",
        lambda *_args, **_kwargs: result,
    )


def _recover(sync_client, tmp_config_dir, agent_id):
    return _recover_mls_with_top_up(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)


class TestTheTopUpRidesAheadOfTheLadder:
    @respx.mock
    def test_when_the_state_will_not_load_then_the_refusal_names_the_top_up(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        # The un-addable agent, exactly. Its pool is the thing that has to be
        # refilled before any member can mint it a Welcome, and this verb is the
        # one call in the product that refills it.
        _mock_token()
        upload = _mock_upload(agent_id)
        _ladder_raises(monkeypatch)

        with pytest.raises(MlsResyncUnavailableError) as refusal:
            _recover(sync_client, tmp_config_dir, agent_id)

        # Reached the wire, for the acting agent. Not "a helper was called": a
        # mocked helper would have passed against the build that shipped this.
        assert upload.called
        assert refusal.value.key_packages is not None
        assert refusal.value.key_packages.outcome == "topped-up"

    @respx.mock
    def test_when_the_ladder_succeeds_then_the_result_carries_the_top_up(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        _mock_token()
        upload = _mock_upload(agent_id)
        _ladder_returns(monkeypatch)

        result = _recover(sync_client, tmp_config_dir, agent_id)

        assert upload.called
        assert result.key_packages is not None
        assert result.key_packages.outcome == "topped-up"

    @respx.mock
    def test_when_syncs_repeat_then_the_minting_stops(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        # The server's inventory cap is enforced over a whole batch and the
        # native core writes every private half to disk BEFORE the blobs go up,
        # so a refused batch un-mints nothing. Without a floor, a long-lived
        # client looping ``groups.sync()`` mints ten more ML-KEM-768 private
        # halves per call, into a directory whose only removal path is a Welcome
        # consuming one.
        #
        # Two uploads and not one, and both are bounded: the first sync finds the
        # pool below its low-water mark and tops it up, the second finds it full
        # and spends the process's one additive rescue. Every sync after that
        # publishes nothing — the count staying put as the loop grows is what
        # states it.
        _mock_token()
        upload = _mock_upload(agent_id)
        _ladder_raises(monkeypatch)

        for _ in range(6):
            with pytest.raises(MlsResyncUnavailableError):
                _recover(sync_client, tmp_config_dir, agent_id)

        assert upload.call_count == 2

    @respx.mock
    def test_when_the_server_never_answered_then_the_rescue_is_not_spent(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        # A refused upload published nothing, so the next recovery in this
        # process may try again: the floor is a brake on MINTING, not a quota on
        # attempts. The second upload is the rescue's own — the first is the
        # low-water top-up of a pool that starts empty here — and the refusal it
        # meets is a 4xx, because the client retries a 5xx itself and a retried
        # failure is not the one this is about.
        _mock_token()
        _ladder_raises(monkeypatch)
        answers = [
            httpx.Response(200, json={"stored": KEY_PACKAGE_TARGET}),
            httpx.Response(400, json={"detail": "key package blob was not accepted"}),
            httpx.Response(200, json={"stored": KEY_PACKAGE_TARGET}),
        ]
        upload = respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(side_effect=answers)

        outcomes = []
        for _ in range(3):
            with pytest.raises(MlsResyncUnavailableError) as refusal:
                _recover(sync_client, tmp_config_dir, agent_id)
            outcomes.append(refusal.value.key_packages)

        assert upload.call_count == 3
        assert outcomes[1] is not None and outcomes[1].outcome == "failed"
        assert outcomes[2] is not None and outcomes[2].outcome == "topped-up"
