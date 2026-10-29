"""``profiles.json`` writers serialize on ``profiles.json.lock``.

That is the lock the TypeScript writers of the same directory take, so a Python
and a Node writer never drop each other's entry.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import TYPE_CHECKING

from rine._config import PROFILES_FILE
from rine._profiles import add_profile_if_absent, load_profiles

if TYPE_CHECKING:
    from rine._types import Profile

ORG_ID = "00000000-0000-4000-8000-000000000001"


def _entry(agent_id: str) -> Profile:
    return {"org_id": ORG_ID, "principal": f"agent:{agent_id}", "agent_id": agent_id}


def test_add_profile_when_another_process_holds_the_lock_then_waits_for_its_release(
    tmp_path,
) -> None:
    """A writer that finds a live holder waits, then adds to what the holder wrote."""
    config_dir = str(tmp_path)
    lock = os.path.join(config_dir, f"{PROFILES_FILE}.lock")
    with open(lock, "w") as f:
        f.write(json.dumps({"pid": 999999, "acquired_at": int(time.time() * 1000)}) + "\n")
    writer = threading.Thread(
        target=add_profile_if_absent, args=(config_dir, "mine", _entry("mine"))
    )
    writer.start()
    try:
        time.sleep(0.3)
        assert writer.is_alive()
        assert load_profiles(config_dir) == {}
        # The holder writes its own entry, then releases.
        with open(os.path.join(config_dir, PROFILES_FILE), "w") as f:
            json.dump({"theirs": _entry("theirs")}, f)
        os.unlink(lock)
    finally:
        writer.join(timeout=5)
    assert set(load_profiles(config_dir)) == {"theirs", "mine"}
    assert not os.path.exists(lock)
