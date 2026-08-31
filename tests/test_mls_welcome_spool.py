"""What the spool keeps, and what having "had its chance" means.

The cap, the age bound and the write-order rule are exercised in
``test_mls_join.py::TestWhatTheSpoolKeeps``, against a fixture of retained
refusals. What lives here is the population question that fixture cannot ask:
an entry a pass spooled and then never processed, which is the shape that made
a bounded spool lose honest Welcomes.

🔴 MEASURED against the real native core: 36 honest Welcomes for 36 real groups,
one ordinary local failure after spooling, then a healthy pass whose fetch is
empty — 32 installed and **4 permanently lost** under a count bound over every
entry, against 36 of 36 with the count bound off. ``GET
/agents/{id}/mls/welcomes`` consumes what it serves, so those four bytes-strings
have no second copy anywhere: only a re-invitation replaces them.

The TypeScript twin is ``rine-core/test/mls-welcome-spool.test.ts``.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from rine._mls import welcomes as welcomes_module
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.welcome_spool import (
    SPOOL_MAX_ENTRIES,
    WelcomeSpool,
    welcome_spool_dir,
)
from rine.errors import CryptoError

GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
DAY_SECONDS = 24 * 60 * 60


def _path(tmp_config_dir: str, agent_id: str, spool_id: str) -> str:
    return os.path.join(welcome_spool_dir(tmp_config_dir, agent_id), f"{spool_id}.json")


def _fill(
    tmp_config_dir: str,
    agent_id: str,
    ids: list[str],
    *,
    age_seconds: float = 0.0,
    refused: bool,
) -> list[str]:
    """Spool one Welcome per id, oldest first, refused or never tried.

    ``refused`` is what a pass that tried an entry and refused it retryably
    leaves behind — the population the count bound holds — so a fixture has to
    say which of the two it is building.
    """
    spool = WelcomeSpool(tmp_config_dir, agent_id)
    now = time.time()
    for offset, spool_id in enumerate(ids):
        spool.store(MlsWelcomeDelivery(id=spool_id, group_id=GROUP_ID, welcome=b"\x01"))
        if refused:
            spool.mark_refused(_path(tmp_config_dir, agent_id, spool_id))
        when = now - age_seconds - (len(ids) - offset)
        os.utime(_path(tmp_config_dir, agent_id, spool_id), (when, when))
    return ids


class TestTheCountBoundsPopulation:
    """Spooling is not the same event as having had a chance."""

    def test_a_carried_over_batch_no_pass_has_tried_is_not_evicted_by_its_own_size(
        self, tmp_config_dir, agent_id
    ):
        ids = _fill(
            tmp_config_dir,
            agent_id,
            [f"w{index:03d}" for index in range(SPOOL_MAX_ENTRIES + 4)],
            refused=False,
        )

        assert WelcomeSpool(tmp_config_dir, agent_id).prune() == 0

        kept = [d.id for _p, d in WelcomeSpool(tmp_config_dir, agent_id).pending()]
        assert kept == ids

    def test_untried_entries_padding_the_spool_are_not_counted_against_the_refusals(
        self, tmp_config_dir, agent_id
    ):
        _fill(
            tmp_config_dir,
            agent_id,
            [f"refused{index:03d}" for index in range(SPOOL_MAX_ENTRIES + 1)],
            refused=True,
        )
        untried = _fill(
            tmp_config_dir, agent_id, [f"untried{index}" for index in range(20)], refused=False
        )

        # 33 refusals over a cap of 32 costs exactly one eviction, and the 20
        # entries waiting for their first attempt are not in the count at all.
        assert WelcomeSpool(tmp_config_dir, agent_id).prune() == 1

        kept = [d.id for _p, d in WelcomeSpool(tmp_config_dir, agent_id).pending()]
        assert len(kept) == SPOOL_MAX_ENTRIES + 20
        assert "refused000" not in kept
        assert all(spool_id in kept for spool_id in untried)

    def test_an_untried_welcome_older_than_the_bound_is_still_dropped(
        self, tmp_config_dir, agent_id
    ):
        # The age bound reaches everything: a week is past the invitation that
        # would corroborate the Welcome, tried or not.
        _fill(tmp_config_dir, agent_id, ["stale"], age_seconds=8 * DAY_SECONDS, refused=False)

        assert WelcomeSpool(tmp_config_dir, agent_id).prune() == 1
        assert WelcomeSpool(tmp_config_dir, agent_id).pending() == []

    def test_marking_a_refusal_twice_rewrites_the_entry_once(self, tmp_config_dir, agent_id):
        spool = WelcomeSpool(tmp_config_dir, agent_id)
        spool.store(MlsWelcomeDelivery(id="once", group_id=GROUP_ID, welcome=b"\x01"))
        spool.mark_refused(_path(tmp_config_dir, agent_id, "once"))
        first = os.stat(_path(tmp_config_dir, agent_id, "once")).st_mtime

        spool.mark_refused(_path(tmp_config_dir, agent_id, "once"))

        # The mtime is both the queue order and the age clock, so a mark that
        # rewrote on every refusal would reset the seven days on every pass.
        assert os.stat(_path(tmp_config_dir, agent_id, "once")).st_mtime == first
        assert [d.id for _p, d in spool.pending()] == ["once"]

    def test_an_entry_written_before_the_flag_existed_is_read_not_dropped(
        self, tmp_config_dir, agent_id
    ):
        # The format changed under files that are the only copy of themselves,
        # so the previous shape reads as "not yet tried" rather than unreadable.
        spool = WelcomeSpool(tmp_config_dir, agent_id)
        spool.store(MlsWelcomeDelivery(id="legacy", group_id=GROUP_ID, welcome=b"\x01"))
        with open(_path(tmp_config_dir, agent_id, "legacy"), "w") as handle:
            json.dump({"id": "legacy", "group_id": GROUP_ID, "welcome": "AQ=="}, handle)

        assert [d.id for _p, d in spool.pending()] == ["legacy"]
        assert spool.prune() == 0


class TestTheDirectoryTheSpoolLivesIn:
    def test_an_agent_id_that_is_a_path_is_refused(self, tmp_config_dir):
        # Defence in depth — the agent id is local, not server-chosen — but it
        # is the other half of the path this module builds, and the TypeScript
        # twin has always asserted it.
        with pytest.raises(CryptoError, match="agent_id"):
            welcome_spool_dir(tmp_config_dir, "../../../elsewhere")
        with pytest.raises(CryptoError, match="agent_id"):
            WelcomeSpool(tmp_config_dir, "not-a-uuid")


class _StubGroup:
    def save(self) -> None:
        return None


class _StubClient:
    def join_from_welcome(self, _welcome: bytes) -> _StubGroup:
        return _StubGroup()


class TestThePassCallsTheBound:
    """The bound is only real if something calls it, and nothing pinned that."""

    def test_a_pass_prunes_the_aged_spool_before_it_opens_a_client(
        self, tmp_config_dir, agent_id, monkeypatch
    ):
        _fill(
            tmp_config_dir,
            agent_id,
            ["aged-0", "aged-1"],
            age_seconds=8 * DAY_SECONDS,
            refused=True,
        )
        monkeypatch.setattr(welcomes_module, "fetch_welcomes", lambda *_a, **_k: [])

        def _refuse_to_open(*_args, **_kwargs):
            raise AssertionError("the pass reached the MLS core with a pruned spool")

        monkeypatch.setattr(welcomes_module, "open_mls_client", _refuse_to_open)

        outcome = welcomes_module.process_mls_welcomes(None, tmp_config_dir, agent_id)

        assert outcome.group_ids == ()
        assert outcome.discarded == 2
        assert WelcomeSpool(tmp_config_dir, agent_id).pending() == []

    def test_a_pass_that_aborted_after_spooling_installs_every_welcome_on_the_next_one(
        self, tmp_config_dir, agent_id, monkeypatch
    ):
        # 🔴 End to end. The abort is the ordinary path: any local failure
        # that is not an unusable Welcome leaves the pass, and the whole batch
        # goes into the next one — whose fetch is empty, because the server
        # already handed the bytes over and marked them consumed.
        batch = [
            MlsWelcomeDelivery(
                id=f"w{index:03d}",
                group_id=f"bbbbbbbb-cccc-dddd-eeee-{index:012d}",
                welcome=b"\x01",
            )
            for index in range(SPOOL_MAX_ENTRIES + 4)
        ]
        served = [batch]

        def _fetch(*_args, **_kwargs):
            return served.pop(0) if served else []

        monkeypatch.setattr(welcomes_module, "fetch_welcomes", _fetch)
        monkeypatch.setattr(welcomes_module, "welcome_refusal", lambda *_a, **_k: None)
        monkeypatch.setattr(welcomes_module, "replenish_mls_key_packages", lambda *_a, **_k: None)
        monkeypatch.setattr(
            welcomes_module,
            "open_mls_client",
            lambda *_a, **_k: (_ for _ in ()).throw(OSError("the store went away mid-pass")),
        )

        with pytest.raises(OSError, match="mid-pass"):
            welcomes_module.process_mls_welcomes(None, tmp_config_dir, agent_id)
        assert len(WelcomeSpool(tmp_config_dir, agent_id).pending()) == len(batch)

        monkeypatch.setattr(welcomes_module, "open_mls_client", lambda *_a, **_k: _StubClient())
        outcome = welcomes_module.process_mls_welcomes(None, tmp_config_dir, agent_id)

        assert outcome.group_ids == tuple(delivery.group_id for delivery in batch)
        assert outcome.discarded == 0
        assert WelcomeSpool(tmp_config_dir, agent_id).pending() == []

    def test_a_retryable_refusal_joins_the_counted_set(
        self, tmp_config_dir, agent_id, monkeypatch
    ):
        # The mark is written by the pass, not by the spool: it is the pass that
        # knows a refusal was retryable and the bytes were kept.
        from rine._mls.welcome_guard import MlsWelcomeRefusedError

        delivery = MlsWelcomeDelivery(id="refused-0", group_id=GROUP_ID, welcome=b"\x01")
        WelcomeSpool(tmp_config_dir, agent_id).store(delivery)
        monkeypatch.setattr(welcomes_module, "fetch_welcomes", lambda *_a, **_k: [])
        monkeypatch.setattr(welcomes_module, "open_mls_client", lambda *_a, **_k: _StubClient())
        monkeypatch.setattr(
            welcomes_module,
            "replenish_mls_key_packages",
            lambda *_a, **_k: None,
        )
        monkeypatch.setattr(
            welcomes_module,
            "welcome_refusal",
            lambda *_a, **_k: MlsWelcomeRefusedError(GROUP_ID, "roster_uncorroborated", "no"),
        )

        with pytest.raises(MlsWelcomeRefusedError):
            welcomes_module.process_mls_welcomes(
                None, tmp_config_dir, agent_id, for_group=GROUP_ID
            )

        # Kept — the bytes are the only copy — and now carrying the flag, so a
        # spool full of these is what the cap actually caps.
        assert len(WelcomeSpool(tmp_config_dir, agent_id).pending()) == 1
        with open(_path(tmp_config_dir, agent_id, "refused-0")) as handle:
            assert json.load(handle)["refused"] is True
