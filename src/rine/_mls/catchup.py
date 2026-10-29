"""Keeping a member's MLS state current under ORDINARY use.

Until now nothing caught a member up except a failure. :func:`sync_mls_group`
ran on the recovery path — after a decrypt had already failed — and on the
explicit catch-up verb, so a member who joined a group and sent into it could
sit twenty-five epochs behind the room and never be told. That is valid MLS and
still wrong: traffic sealed from a stale epoch is traffic the members who
arrived after it can never open.

So an ordinary successful group read now catches up too — bounded, because
"sync on every read" is the expensive answer, not the cheap one.

**What a catch-up with nothing to do costs.** One
``GET /groups/{id}/mls/handshakes?since_epoch=<our epoch>``, answered with an
empty list: the server returns only commits ABOVE the epoch asked for, so a
current member applies nothing, commits nothing, and bills no other member.
When it is NOT empty the commits it applies are commits this member had to
process anyway — deferring them saves nothing and only lengthens the queue.

**Why :data:`MLS_CATCHUP_MIN_INTERVAL_S` exists, in numbers.** A daemon polling
a twenty-row inbox every five seconds would otherwise issue four catch-ups a
second per member; at the 500-member group ceiling that is 2,000 requests a
second against one group. With a one-minute floor it is 500 requests a minute —
8.3/s — and the server already grants each member 120 requests a minute on this
exact route (``handshake_limiter``, ``limit=120, window_seconds=60``), so one
per minute spends 1/120th of a budget that already exists. Against the roughly
4 GB/day of commit egress a 500-member group carries, an empty GET per member
per minute is not measurable.

The gate is per process and deliberately not persisted: a one-shot script
performs exactly one catch-up, which is the behaviour wanted there, and only a
long-lived client can spin — which is the case the floor bounds. Its TypeScript
twin is ``rine-core/src/mls-catchup.ts``.
"""

from __future__ import annotations

import time
from typing import Any

from rine._logging import logger
from rine._mls.sync import MlsSyncResult, sync_mls_group

#: Shortest gap between two catch-ups for one (agent, group) in one process.
MLS_CATCHUP_MIN_INTERVAL_S = 60.0

_last_attempt: dict[tuple[str, str, str], float] = {}


def catch_up_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
) -> MlsSyncResult | None:
    """Advance local state to the group's current epoch, at most once a minute.

    Best-effort by contract: it runs behind a read that has already succeeded,
    so a failure here must leave that read exactly where it was. Nothing is
    raised, ever.

    What it *reports* is what it just did — the commits it applied, the epoch it
    landed on, whether the member turned out to be evicted — and nothing else.
    It does not say how far behind the client was: that number needs the group's
    confirmed epoch, which is a second round trip on the hottest path in the
    product, to answer a question most reads do not have.
    :meth:`rine.Rine.groups.sync` remains the one place an operator asks that
    distance and gets an answer.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group UUID.

    Returns:
        What the catch-up applied, or ``None`` when there is nothing to report —
        the floor swallowed the attempt, or the attempt failed. A caller cannot
        tell those two apart from here on purpose: neither changed this agent's
        state, and a read is not the place to explain a failure it survived.
        Whether an attempt was *made* is observable where it matters, in the
        calls the sync itself issues.
    """
    key = (config_dir, agent_id, group_id)
    now = time.monotonic()
    previous = _last_attempt.get(key)
    if previous is not None and now - previous < MLS_CATCHUP_MIN_INTERVAL_S:
        return None
    _last_attempt[key] = now
    try:
        return sync_mls_group(client, config_dir, agent_id, group_id, carry_unreported=True)
    except Exception:
        logger.debug("MLS catch-up after a read failed for group %s", group_id, exc_info=True)
        return None


__all__ = ["MLS_CATCHUP_MIN_INTERVAL_S", "catch_up_mls_group"]
