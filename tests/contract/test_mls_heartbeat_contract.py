"""The key-package heartbeat, Python side — and the seam that makes it structural.

The twin of ``rine-core/test/mls-heartbeat.test.ts``. Both stacks share one
defect and one fix, so both carry the same gate; a top-up that shipped on one
stack alone would leave the other's agents un-addable while every suite read
green.

What goes wrong without it is an absorbing state, not a slow leak. Peers claim
one of an agent's published key packages each time they add it to a group, so a
pool that is never topped up runs out — and at zero the agent is **un-addable**:
no member can mint it a Welcome, every further admission degrades to a
self-join, and a self-join processes no Welcome. The agent that most needs a
top-up is the one that never gets one. A carried vote then seats it on the
roster with no leaf in the ratchet tree, and it reads nothing the group says.

Three kinds of assertion, in descending order of how much they prove:

1. **The wire.** The verbs are driven against the REAL ``rine-mls`` core with
   only the server mocked, and the claim is that ``POST
   /agents/{id}/mls/key-packages`` was actually issued for the ACTING agent.
   A mocked helper asserted here would have passed against every build that
   shipped this defect.
2. **The seam.** No module may post a commit except through
   :func:`rine._mls.commit.post_mls_commit`, and no module may top up except
   through :func:`rine._mls.heartbeat.mls_heartbeat`. This is what makes a verb
   added later inherit the beat rather than have to remember it.
3. **The census.** Every module under ``rine/_mls/`` is classified by the seam
   it takes its beat from, so a new one is red until somebody answers the
   question. Nine near-identical call sites never had that property, which is
   how this shipped.

Lives in ``tests/contract/`` because that is the directory ``ci.sh`` runs for
this package (stage ``[4/8] rine-sdk contract``): ``rine-sdk/tests/`` at large
is gated only by the publish train.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
import respx

from rine._mls import (
    KEY_PACKAGE_TARGET,
    MlsActor,
    mls_group_id_bytes,
    mls_heartbeat,
    open_mls_client,
    process_mls_welcomes,
    reset_mls_heartbeat_gate,
    sync_mls_group,
)
from rine._mls.wire import mls_to_base64
from rine.errors import NoMlsGroupStateError

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
#: A group this agent holds no state for, so a Welcome naming it cannot be read
#: as one it already installed.
OTHER_GROUP_ID = "cccccccc-dddd-eeee-ffff-000000000000"

MLS_SRC = Path(__file__).resolve().parents[2] / "src" / "rine" / "_mls"


@pytest.fixture(autouse=True)
def _fresh_gate():
    """The floor is per process, so a test must not inherit the last one's stamp."""
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


def _mock_handshakes() -> None:
    respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
        return_value=httpx.Response(200, json={"handshakes": []})
    )


def _mock_welcomes(agent_id: str, group_id: str) -> None:
    """One Welcome the server serves and no core can ever open.

    The pass spools it, fails to join, finds no local state for the group it
    names, discards it and ends with no group id — the shape a top-up
    conditioned on a successful install sits out, which is what this used to be.
    """
    respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
        return_value=httpx.Response(
            200,
            json={
                "welcomes": [
                    {
                        "id": "77777777-8888-9999-aaaa-bbbbbbbbbbbb",
                        "group_id": group_id,
                        "blob": mls_to_base64(b"\x01\x02\x03"),
                        "created_at": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _seed_group_state(config_dir: str, agent_id: str) -> None:
    """Local MLS state for GROUP_ID, founded offline — no HTTP, so no beat yet."""
    open_mls_client(config_dir, agent_id).create_group(mls_group_id_bytes(GROUP_ID)).save()


class TestABeatRidesOnEveryMlsOperation:
    @respx.mock
    def test_sync_when_the_group_is_followed_then_key_packages_reach_the_wire(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The structural case, and the one no verb used to cover: a member that
        # only ever reads its group spends nothing of its own, so nothing
        # prompted a top-up and the pool drained to zero under it.
        _mock_token()
        _mock_handshakes()
        upload = _mock_upload(agent_id)
        _seed_group_state(tmp_config_dir, agent_id)

        sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert upload.called

    @respx.mock
    def test_sync_when_the_agent_holds_no_state_then_key_packages_still_reach_the_wire(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The headline population: an agent seated by a carried vote that no
        # member could mint a Welcome for holds NO state, so every sync it runs
        # refuses. The beat is ahead of the handle, so the one verb it can still
        # run is the one that refills the pool that unblocks its re-admission.
        _mock_token()
        upload = _mock_upload(agent_id)

        with pytest.raises(NoMlsGroupStateError):
            sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert upload.called

    @respx.mock
    def test_welcomes_when_the_pass_installed_nothing_then_key_packages_reach_the_wire(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The pass that installs nothing is the pass most likely to have found
        # nothing to install, so conditioning the cure on the symptom's absence
        # is how zero became an absorbing state.
        #
        # 🔴 A REGRESSION GUARD, not a defect probe — and the one place the two
        # stacks did not share the hole. This stack already replenished here
        # unconditionally within a non-empty pass, so this assertion passes
        # against the pre-fix tree; the TypeScript twin did not (it asked
        # `groupIds.length > 0` first) and its version of this test fails there.
        # Kept, and kept on both stacks, because this is the only path on which
        # an agent's own pool shrinks: the behaviour that was right here is the
        # behaviour the seam must not lose while moving the call.
        _mock_token()
        _mock_welcomes(agent_id, OTHER_GROUP_ID)
        upload = _mock_upload(agent_id)

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == ()
        assert upload.called

    @respx.mock
    def test_the_upload_names_the_acting_agent_and_no_other(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        # The pool is per-agent. A beat that published for the wrong one would
        # leave the acting agent exactly as un-addable as before while looking
        # like it worked.
        _mock_token()
        _mock_handshakes()
        mine = _mock_upload(agent_id)
        theirs = _mock_upload(other_agent_id)
        _seed_group_state(tmp_config_dir, agent_id)

        sync_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert mine.called
        assert not theirs.called


class TestTheProcessLocalFloor:
    """The floor, measured at the collaborator rather than at the wire.

    A second beat inside the window cannot be told apart by its uploads: the
    first one left the pool at target, so the low-water check is a no-op whether
    the beat ran or was skipped. What the floor decides is whether a top-up is
    ATTEMPTED, so that is what these record. The wire assertions above are what
    prove the attempt is real.
    """

    @pytest.fixture
    def attempts(self, monkeypatch) -> list[tuple[str, str]]:
        beats: list[tuple[str, str]] = []
        monkeypatch.setattr(
            "rine._mls.heartbeat.ensure_mls_key_packages",
            lambda _client, config_dir, agent_id: beats.append((config_dir, agent_id)),
        )
        return beats

    def test_a_run_of_gated_beats_collapses_into_one(
        self, sync_client, tmp_config_dir, agent_id, attempts
    ):
        # Founding a 500-member group posts one commit per batch of thirteen
        # joiners. Without the floor each of those would sweep the key store and
        # derive three asymmetric public keys for nothing.
        actor = MlsActor(client=sync_client._http, config_dir=tmp_config_dir, agent_id=agent_id)

        for _ in range(3):
            mls_heartbeat(actor, "gated")

        assert attempts == [(tmp_config_dir, agent_id)]

    def test_one_agents_beat_does_not_stand_in_for_anothers(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, attempts
    ):
        # Keyed on the agent because the pool is per-agent: a multi-agent org
        # running one process must not have its second agent silenced by its
        # first.
        http = sync_client._http

        mls_heartbeat(MlsActor(client=http, config_dir=tmp_config_dir, agent_id=agent_id), "gated")
        mls_heartbeat(
            MlsActor(client=http, config_dir=tmp_config_dir, agent_id=other_agent_id), "gated"
        )

        assert attempts == [(tmp_config_dir, agent_id), (tmp_config_dir, other_agent_id)]

    def test_a_forced_beat_runs_inside_the_window_that_would_skip_a_gated_one(
        self, sync_client, tmp_config_dir, agent_id, attempts
    ):
        # `forced` is for the paths that just SPENT a key package — founding,
        # adding members, resuming an admission, processing a Welcome — where
        # waiting out a floor leaves the agent short in exactly the window a peer
        # is most likely to add it.
        actor = MlsActor(client=sync_client._http, config_dir=tmp_config_dir, agent_id=agent_id)
        mls_heartbeat(actor, "gated")

        mls_heartbeat(actor, "forced")

        assert attempts == [(tmp_config_dir, agent_id)] * 2


def _modules_calling(name: str) -> set[str]:
    """Module file names under ``_mls/`` that CALL ``name``.

    A call and not a mention: the docstrings that explain this seam name both
    functions, and a gate that a comment can turn red is a gate somebody edits
    the comment to satisfy.
    """
    call = re.compile(rf"(?<![\w.]){re.escape(name)}\(")
    return {
        path.name
        for path in sorted(MLS_SRC.glob("*.py"))
        if any(call.search(line) for line in path.read_text().splitlines() if not _is_def(line))
    }


def _is_def(line: str) -> bool:
    """Whether the line DEFINES rather than calls — the definition is not a call site."""
    return line.lstrip().startswith(("def ", "async def "))


class TestTheSeamCannotBeBypassed:
    def test_only_the_commit_seam_posts_a_commit(self):
        # `post_mls_commit` is where the beat rides for every verb that commits,
        # so a module reaching past it to `mls_commit` is a verb with no
        # heartbeat — which is what six of them were.
        assert _modules_calling("mls_commit") == {"commit.py"}

    def test_only_the_heartbeat_tops_up_behind_an_mls_operation(self):
        # One place decides the pace, so a verb cannot quietly opt out of the
        # floor by topping up directly. The recovery's top-up is the one other
        # caller and is not a beat at all: an operator asked for it, it reports
        # what it did, and it is additive where the beat is low-water.
        # `key_packages.py` is the third only because the silent wrapper that
        # lives beside it calls it — the module the top-up is DEFINED in cannot
        # be a verb reaching past the seam.
        assert _modules_calling("ensure_mls_key_packages") == {
            "heartbeat.py",
            "key_packages.py",
            "topup.py",
        }

    def test_the_beat_does_not_route_through_the_silent_wrapper(self):
        # `replenish_mls_key_packages` swallows its own failure, so a beat
        # calling it cannot tell a top-up that happened from one that 429'd —
        # and would leave the floor stamped over an agent still at inventory
        # zero. Onboarding keeps the wrapper: it is outside this package and is
        # not an MLS operation at all, minting the FIRST pool with no group, no
        # commit and nothing to be short for.
        assert _modules_calling("replenish_mls_key_packages") == set()


#: Where each ``_mls`` module's key-package beat comes from. The point is the
#: census under it, not the table: a module added without a line here is red
#: until somebody answers the question, and the only answers are seams.
HEARTBEAT_SEAMS: dict[str, tuple[str, ...]] = {
    # Beats inside `post_mls_commit` — every commit this SDK posts.
    "commit": (
        "add_members.py",
        "admission_retry.py",
        "admission_state.py",
        "external_join.py",
        "group_init.py",
        "orphans.py",
        "removal.py",
        "self_update.py",
        "stranded_seat.py",
    ),
    # Beats inside `sync_mls_group` — every read-side catch-up, and the ladder.
    "sync": ("catchup.py", "messages.py", "resync.py", "sync.py"),
    # Calls `mls_heartbeat` itself, forced, having just spent a key package.
    "forced": ("welcomes.py",),
    # Is the key-package machinery, so it publishes as its own purpose.
    "key-packages": (
        "commit.py",
        "heartbeat.py",
        "key_package_cutover.py",
        "key_packages.py",
        "seat_sweep.py",
        "topup.py",
    ),
    # Spends no key package: readers, the wire, local state, words and refusals.
    "no-mls-state": (
        "__init__.py",
        "admission.py",
        "admission_loop.py",
        "actor.py",
        "admission_recheck.py",
        "allowed.py",
        "allowed_history.py",
        "api.py",
        "binding.py",
        "bridge.py",
        "commit_admission.py",
        "commit_wire.py",
        "downgrade.py",
        "escrow_api.py",
        "escrow_answer.py",
        "escrow_atomic.py",
        "escrow_backlog.py",
        "escrow_drain.py",
        "escrow_gap.py",
        "escrow_gap_list.py",
        "escrow_handoff.py",
        "escrow_head.py",
        "escrow_keys.py",
        "escrow_leaves.py",
        "escrow_markers.py",
        "escrow_queued.py",
        "escrow_reopen.py",
        "escrow_report.py",
        "escrow_revoked.py",
        "escrow_retry.py",
        "escrow_seal.py",
        "escrow_scratch.py",
        "escrow_send.py",
        "escrow_settle.py",
        "escrow_snapshots.py",
        "escrow_store.py",
        "escrow_stored.py",
        "escrow_sweep.py",
        "escrow_take.py",
        "escrow_upload.py",
        "failures.py",
        "founding.py",
        "group_access.py",
        "header.py",
        "join.py",
        "join_establish.py",
        "key_current.py",
        "key_not_current.py",
        "leave.py",
        "pending_commit.py",
        "prior_epoch.py",
        "peer_refusal.py",
        "revoked_seats.py",
        "rotated_leaf.py",
        "rotation_marker.py",
        "seat_sweep_backoff.py",
        "seated_groups.py",
        "self_update_outcome.py",
        "settle_guard.py",
        "store_probe.py",
        "sync_api.py",
        "sync_signals.py",
        "tree.py",
        "welcome_guard.py",
        "welcome_install.py",
        "welcome_pick.py",
        "welcome_release.py",
        "welcome_spool.py",
        "wire.py",
    ),
}


class TestEveryModuleIsAnswerableForItsHeartbeat:
    def test_the_census_covers_exactly_the_package(self):
        classified = {name for names in HEARTBEAT_SEAMS.values() for name in names}
        assert classified == {path.name for path in MLS_SRC.glob("*.py")}

    def test_each_module_is_classified_once(self):
        # The check above compares SETS, so a module filed under two seams — one
        # of them "spends no key package" — satisfies it while the question
        # "where does this module beat?" has two contradictory answers on
        # record. The TypeScript census asserts the same thing about names.
        classified = [name for names in HEARTBEAT_SEAMS.values() for name in names]
        assert len(classified) == len(set(classified))

    def test_every_module_that_can_spend_a_key_package_has_a_beating_seam(self):
        beating = set(HEARTBEAT_SEAMS["commit"] + HEARTBEAT_SEAMS["sync"])
        beating |= set(HEARTBEAT_SEAMS["forced"])
        # Named one by one rather than derived: an operator's group membership
        # depends on this list, and deriving it from the table it checks would
        # make the assertion agree with itself.
        for module in (
            "add_members.py",
            "admission_retry.py",
            "admission_state.py",
            "catchup.py",
            "external_join.py",
            "group_init.py",
            "messages.py",
            "orphans.py",
            "removal.py",
            "resync.py",
            "sync.py",
            "welcomes.py",
        ):
            assert module in beating, f"{module} has no heartbeat seam"
