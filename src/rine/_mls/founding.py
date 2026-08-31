"""How many members one commit admits, and claiming their KeyPackages.

The Python twin of ``rine-core/src/mls-founding.ts``, function for function, so
the two stacks split an admission into the same commits. Every constant it
needs is restated once in :mod:`rine._constants` and gated there; nothing in
this module invents a number.

Both entry points of the admission loop use this: founding a group is the
``seated = 1`` case and adding to one later is every other case. The batch is
size-aware because the cost of a batch is the batch times the size of the group
it is joining — a Welcome carries the whole ratchet tree — so a fixed batch
size cannot bound the POST it produces.
"""

from __future__ import annotations

from typing import Any

from rine._constants import (
    MLS_CLAIM_AGENTS_MAX,
    MLS_COMMIT_AND_GROUP_INFO_IN_WELCOMES,
    MLS_FOUNDING_POST_BUDGET_B64,
    MLS_WELCOME_B64_BASE,
    MLS_WELCOME_B64_PER_MEMBER,
    MLS_WELCOMES_PER_COMMIT_MAX,
)
from rine._mls.wire import mls_from_base64


def _founding_post_b64(seated: int, batch: int) -> int:
    """Estimated base64 weight of a commit admitting ``batch`` into ``seated``.

    ``seated`` counts the joiners: a Welcome describes the tree the joiner lands
    in, not the one that existed before the commit.
    """
    welcome = MLS_WELCOME_B64_PER_MEMBER * seated + MLS_WELCOME_B64_BASE
    return welcome * (batch + MLS_COMMIT_AND_GROUP_INFO_IN_WELCOMES)


def _batch_size_at(seated: int) -> int:
    """The largest batch a tree of ``seated`` members can admit within budget."""
    batch = MLS_WELCOMES_PER_COMMIT_MAX
    while batch > 1 and _founding_post_b64(seated + batch, batch) > MLS_FOUNDING_POST_BUDGET_B64:
        batch -= 1
    return batch


def mls_founding_batch_sizes(joiner_count: int, seated: int = 1) -> list[int]:
    """How many members each successive commit admits.

    ``b(N)``: the batch shrinks as the tree grows. Seating 499 joiners onto a
    lone founder takes 39 commits — 32 in the first, 2 in the last, none of them
    weighing more than ~7.8 MB. The batch never falls below 1, so a group at the
    ceiling always founds and always finishes.

    Args:
        joiner_count: Members still to admit.
        seated: The tree's current member count. ``1`` is founding — the
            founder alone — and any other value is an add over an existing
            group, which is the same arithmetic further along.

    Returns:
        One batch size per commit, in order, summing to ``joiner_count``.
    """
    sizes: list[int] = []
    placed = 0
    while placed < joiner_count:
        batch = min(joiner_count - placed, _batch_size_at(seated))
        sizes.append(batch)
        placed += batch
        seated += batch
    return sizes


def claim_founding_key_packages(
    client: Any, agent_ids: list[str], extra_headers: dict[str, str] | None = None
) -> dict[str, bytes]:
    """Claim one KeyPackage each for ``agent_ids``, chunked at the server's cap.

    The claim is destructive server-side (RFC 9420 single-use), so this is
    called **per batch** and never for the whole roster up front: a founding
    refused at its fifth commit would otherwise have burned a KeyPackage for
    every member of the group, and a burned pool does not heal on its own.

    An agent the server holds no KeyPackage for comes back with an empty
    ``packages`` array — not an error and not a missing entry — and is simply
    absent from the returned map, so the admission skips that member instead of
    failing. Keys are lower-cased, so a caller may look them up by whatever
    casing it holds the agent id in.

    Returns:
        Agent id (lower-cased) to KeyPackage blob, for every agent that had one.
    """
    claimed: dict[str, bytes] = {}
    for start in range(0, len(agent_ids), MLS_CLAIM_AGENTS_MAX):
        chunk = agent_ids[start : start + MLS_CLAIM_AGENTS_MAX]
        data = client.post(
            "/agents/mls/key-packages/claim",
            json_body={"agent_ids": chunk},
            extra_headers=extra_headers,
        )
        for claim in data.get("claims", []):
            packages = claim.get("packages") or []
            if packages:
                claimed[str(claim["agent_id"]).lower()] = mls_from_base64(packages[0])
    return claimed


__all__ = ["claim_founding_key_packages", "mls_founding_batch_sizes"]
