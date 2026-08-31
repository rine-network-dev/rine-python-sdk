"""The eager catch-up an ordinary successful group read runs, and its floor.

What is held here is the GATE, because that is the whole design decision: a
catch-up with nothing to do costs one GET, and a client polling an inbox would
otherwise issue one per row per poll. The sync itself is covered against a real
core elsewhere; substituting it here is what lets the gate be measured on its
own, with time as the only variable.
"""

from __future__ import annotations

import pytest

from rine._mls import catchup
from rine._mls.catchup import (
    MLS_CATCHUP_MIN_INTERVAL_S,
    catch_up_mls_group,
    reset_mls_catch_up_gate,
)
from rine._mls.sync import MlsSyncResult

CONFIG_DIR = "/tmp/rine-catchup"
AGENT = "11111111-1111-1111-1111-111111111111"
OTHER_AGENT = "22222222-2222-2222-2222-222222222222"
GROUP = "33333333-3333-3333-3333-333333333333"
OTHER_GROUP = "44444444-4444-4444-4444-444444444444"


@pytest.fixture
def clock(monkeypatch):
    """A clock the test moves, so the floor is measured rather than waited out."""
    now = {"t": 1000.0}
    monkeypatch.setattr(catchup.time, "monotonic", lambda: now["t"])
    return now


@pytest.fixture
def synced(monkeypatch):
    """Every call the gate let through."""
    calls: list[tuple] = []

    def _sync(client, config_dir, agent_id, group_id, *, cipher_suite=None):
        calls.append((config_dir, agent_id, group_id))
        return MlsSyncResult(epoch=7, processed=3, evicted=False)

    monkeypatch.setattr(catchup, "sync_mls_group", _sync)
    reset_mls_catch_up_gate()
    yield calls
    reset_mls_catch_up_gate()


def test_first_read_when_nothing_cached_then_catches_up(clock, synced):
    """The first successful read of a group advances the epoch."""
    assert catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP) is not None
    assert len(synced) == 1


def test_first_read_when_it_catches_up_then_reports_what_it_applied(clock, synced):
    """The read says what it just did — the commits, the epoch, the eviction."""
    result = catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP)

    assert result is not None
    assert (result.processed, result.epoch, result.evicted) == (3, 7, False)


def test_second_read_when_inside_the_floor_then_skips(clock, synced):
    """Ordinary use catches up; it does not sync per row."""
    catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP)
    clock["t"] += MLS_CATCHUP_MIN_INTERVAL_S - 0.001

    # A twenty-row inbox is twenty reads; without this it would be twenty GETs
    # against one group, per poll.
    assert catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP) is None
    assert len(synced) == 1


def test_read_when_past_the_floor_then_catches_up_again(clock, synced):
    """The floor is a floor, not a one-shot."""
    catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP)
    clock["t"] += MLS_CATCHUP_MIN_INTERVAL_S

    assert catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP) is not None
    assert len(synced) == 2


def test_floor_when_another_group_or_agent_reads_then_does_not_apply(clock, synced):
    """The gate is per (agent, group): one busy group must not silence another."""
    catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP)

    assert catch_up_mls_group(None, CONFIG_DIR, AGENT, OTHER_GROUP) is not None
    assert catch_up_mls_group(None, CONFIG_DIR, OTHER_AGENT, GROUP) is not None
    assert len(synced) == 3


def test_catchup_when_the_sync_fails_then_does_not_raise(clock, monkeypatch):
    """It runs behind a read that already succeeded."""
    attempts: list[str] = []

    def _boom(*_args, **_kwargs):
        attempts.append("tried")
        raise RuntimeError("the server is down")

    monkeypatch.setattr(catchup, "sync_mls_group", _boom)
    reset_mls_catch_up_gate()

    # It runs behind a read that already succeeded, so a failure here must leave
    # that read exactly where it was: nothing raised, and nothing reported —
    # there is no work to report, because none of it landed.
    assert catch_up_mls_group(None, CONFIG_DIR, AGENT, GROUP) is None
    assert attempts == ["tried"]
    reset_mls_catch_up_gate()
