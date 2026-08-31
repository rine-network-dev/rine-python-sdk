"""Reading the ratchet tree an admission is about to change.

Two questions, both of which an admission has to answer before it commits
anything:

* **Is this agent already seated?** A leaf is found by the member's basic
  credential identity, which is its raw Ed25519 public key — the same key rine
  publishes as ``signing_public_key`` and the same one that signs its envelopes.
  Adding an agent that already holds a leaf mints a **second** leaf for it, and
  the two are not distinguishable by identity, so this check is what makes the
  admission loop a resume rather than a duplicator.
* **How big is the tree?** ``b(N)`` sizes each commit against the tree it is
  joining, and the tree is members **plus** invitations nobody has accepted yet
  — an invited agent's leaf is committed before they join. That is
  exactly the occupancy the server's own ceiling counts, so it is read from the
  server rather than guessed from the membership count.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._constants import MLS_CLAIM_AGENTS_MAX
from rine._crypto.keys import jwk_to_public_key
from rine._logging import logger
from rine._mls.binding import GroupInactiveError, MlsCoreError, MlsGroup


def fetch_agent_identities(client: Any, agent_ids: list[str]) -> dict[str, bytes]:
    """The MLS credential identity of each agent, chunked at the server's cap.

    ``GET /agents/keys`` refuses more than :data:`MLS_CLAIM_AGENTS_MAX` ids in
    one call, so this chunks rather than trusting the server to take whatever it
    is sent — the same discipline the batch KeyPackage claim follows, and the
    live defect it exists to avoid on the sender-key side.

    An agent the server does not return (revoked, erased, unknown) is absent
    from the map rather than an error: it cannot be seated either way, and the
    admission reports it per member.

    Returns:
        Agent id (lower-cased) to its raw 32-byte Ed25519 public key.
    """
    identities: dict[str, bytes] = {}
    for start in range(0, len(agent_ids), MLS_CLAIM_AGENTS_MAX):
        chunk = agent_ids[start : start + MLS_CLAIM_AGENTS_MAX]
        data = client.get("/agents/keys", params={"ids": ",".join(chunk)})
        for agent_id, keys in (data.get("keys") or {}).items():
            jwk = keys.get("signing_public_key")
            if not jwk:
                continue
            identities[str(agent_id).lower()] = jwk_to_public_key(jwk, expected_crv="Ed25519")
    return identities


def leaf_index(group: MlsGroup, identity: bytes) -> int | None:
    """This identity's leaf in the group, or ``None`` when it holds none.

    Not-seated is an answer, not a failure — it is the normal state of every
    agent an admission is about to add — so the core's refusal is translated
    here instead of being raised at each call site.

    An **eviction** is deliberately not translated. "This agent's own leaf is
    gone" is not an answer about the identity that was asked about, and
    answering ``None`` would report the target as un-seated and send the caller
    down the there-is-nothing-to-remove path. It propagates to the
    :func:`rine._mls.failures.group_failures` block that every caller runs
    inside, which says what actually happened. Its TypeScript twin,
    ``leafIndexOf``, re-raises the same failure for the same reason.
    """
    try:
        return group.member_index(identity)
    except GroupInactiveError:
        raise
    except MlsCoreError:
        return None


@dataclass(frozen=True)
class GroupTree:
    """The populations that occupy this group's ratchet-tree seats.

    Kept apart because they mean different things to a caller: ``member_ids``
    are seated *and* joined, ``invited_ids`` hold a live invitation somebody
    issued, and ``outstanding_ids`` is every live voucher — which is a **wider**
    set and is only ever counted, never admitted.

    🔴 The difference between the last two is a security boundary. A voucher
    with ``status='pending'`` is awaiting a vote — a stranger's self-application
    (``invited_by IS NULL``), or a member's **nomination** of one
    (``invited_by`` set) — and neither is an invitation. Welcoming
    either hands the group's epoch secret to an agent the vote may then deny,
    and no route ever seats a denied applicant, so nothing would reclaim the
    leaf it consumed. The server refuses to offer them to ``/mls/init`` for
    exactly this reason (``invitation_criteria``); splitting them here
    is what stops a client re-opening it by reading the wider set and admitting
    all of it.

    🔴 So ``status`` alone decides which set a row lands in, and ``invited_by``
    only ever narrows ``invited``. Reading a set membership off ``invited_by``
    would put every nomination in ``invited_ids`` and re-open that hole through
    the resume path.
    """

    member_ids: tuple[str, ...]
    invited_ids: tuple[str, ...]
    outstanding_ids: tuple[str, ...] = ()
    outstanding_known: bool = True
    """False when the outstanding read failed, so ``occupancy`` counts members
    alone and **under-states** the tree. A caller sizing a commit against it must
    size conservatively — see :func:`rine._mls.add_members`."""

    @property
    def ids(self) -> set[str]:
        """Every agent holding a seat, lower-cased.

        Distinct across both populations: an agent may hold a membership row and
        a voucher at once, and counting it twice would size a commit against a
        tree bigger than the one it is joining.

        Counts ``outstanding_ids``, not ``invited_ids``: a self-application
        holds a seat against the ceiling just as an invitation does, so leaving
        it out would under-state the tree and mint a commit the server refuses.
        """
        return {
            *(m.lower() for m in self.member_ids),
            *(o.lower() for o in self.outstanding_ids),
        }

    @property
    def occupancy(self) -> int:
        """Seats taken."""
        return len(self.ids)


def _rows(data: Any) -> list[dict[str, Any]]:
    """The rows of a collection route, wrapped in ``items`` or bare."""
    rows = data.get("items", data) if isinstance(data, dict) else data
    return list(rows)


def read_group_tree(client: Any, group_id: str, extra_headers: dict[str, str]) -> GroupTree:
    """Read the whole tree: members, and the invitations still outstanding.

    ``?outstanding=live`` is the only way to see the second population —
    the route's default answers the vote queue, which is a different set and
    excludes every issued invitation. The default is unchanged for every other
    caller; this one asks for what it actually needs.

    A group whose invitations cannot be read still reports its members, with no
    invitations: an admission that then re-admits an already-Welcomed invitee is
    refused by its own leaf check, so the degraded answer costs a round trip. The
    route is member-gated, not admin-gated — it answers 403 to a non-member and
    200 to any member — so the caller that meets this is one reading a group it
    has been invited to and has not joined yet.

    🔴 What it also costs is the **POST budget**, which is why the failure is
    reported rather than merely logged. ``occupancy`` then counts members alone,
    and a batch sized against a tree of 2 when the real one is 302 mints a
    Welcome per seat against the larger tree — several times the budget
    ``MLS_FOUNDING_POST_BUDGET_B64`` exists to hold. The TypeScript twin
    (``mls-admission-tree.ts``) does not catch at all and fails the resume
    loudly; this one keeps going, and hands the caller what it needs to be
    careful.

    ``live`` is split on the way out. Every row counts toward the occupancy the
    ceiling bounds; only rows somebody actually issued are candidates to admit.
    """
    members = _rows(client.get(f"/groups/{group_id}/members", extra_headers=extra_headers))
    outstanding: list[dict[str, Any]] = []
    try:
        outstanding = _rows(
            client.get(
                f"/groups/{group_id}/requests",
                params={"outstanding": "live"},
                extra_headers=extra_headers,
            )
        )
    except Exception:
        logger.debug("Outstanding invitations unreadable for group %s", group_id, exc_info=True)
        return GroupTree(
            member_ids=tuple(str(m["agent_id"]) for m in members),
            invited_ids=(),
            outstanding_ids=(),
            outstanding_known=False,
        )
    return GroupTree(
        member_ids=tuple(str(m["agent_id"]) for m in members),
        invited_ids=tuple(
            str(r["agent_id"])
            for r in outstanding
            if r.get("status") == "invited" and r.get("invited_by")
        ),
        outstanding_ids=tuple(str(r["agent_id"]) for r in outstanding),
    )


__all__ = ["GroupTree", "fetch_agent_identities", "leaf_index", "read_group_tree"]
