"""Casting a vote — and seating the applicant an approving vote just admitted.

A vote that crosses the threshold answers ``approved`` and makes the applicant a
**member** — unless it carried a nomination whose subject has not consented yet,
which answers ``invited`` instead and seats nobody. Everything below
concerns the ``approved`` answer, and the code gates on it. Seating does not,
on its own, make them a member of the group's **ratchet tree**: the server holds
no MLS keys, so the only client that can mint their leaf and their Welcome is one
that already holds the group's state, and the deciding voter is the one client
guaranteed to be present at that moment. Without this the applicant is seated in
the rine group and left outside the MLS one, with no Welcome, losing every
message until something else self-heals.

Two orderings are load-bearing:

* **The applicant is captured BEFORE the vote is cast.** Once the vote crosses
  the threshold the request leaves the pending list, and ``VoteResponse`` carries
  no ``agent_id`` — so after the POST there is nothing left to read it from.
* **The seat is best-effort and never fails the vote.** The membership stands
  either way, and ``resume_admission`` seats whoever an add commit could not
  reach. A vote that raised because a commit failed would leave the caller unable
  to tell a rejected vote from a seated member.

The TypeScript twin is ``GroupsResource.vote`` (``rine-ts-sdk``), which mirrors
the CLI's own pre-vote capture; all three must keep the same two orderings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine.format import group_is_mls
from rine.types import GroupRead, VoteResponse

if TYPE_CHECKING:
    from rine.types import JoinRequestRead

#: What ``choice`` has to be for an admission to follow the vote at all.
APPROVE = "approve"

#: The status the server reports when the vote crossed the threshold.
APPROVED = "approved"


def _applicant_id(requests: list[JoinRequestRead], request_id: str) -> str | None:
    """Whose request this is, read while it is still readable."""
    return next((str(r.agent_id) for r in requests if str(r.id) == request_id), None)


def _log_unseated(applicant_id: str, group_id: str, err: Exception) -> None:
    """Say what did not happen, once, wherever the seat gave up."""
    logger.warning(
        "Approved %s into group %s, but could not seat them in the ratchet tree: %s. "
        "They are a member and will read nothing until a member runs "
        "resume_admission() on the group.",
        applicant_id,
        group_id,
        err,
    )


def _seat_applicant(
    http: Any, config_dir: str, acting: str, group_id: str, applicant_id: str
) -> bool:
    """Mint the newly approved member's leaf and Welcome, best-effort.

    A sender-key group has no ratchet tree to seat anyone in, so it is skipped
    rather than attempted and reported as a failure. Everything else is logged
    and swallowed: the membership already stands, and ``resume_admission`` is the
    remedy for a leaf this call could not mint.

    🔴 Returns whether the leaf and the Welcome were actually minted, and the
    caller puts that on :attr:`rine.types.VoteResponse.mls_seated`. Swallowing
    the failure silently is what let four connector surfaces tell an operator
    "their ratchet-tree leaf and Welcome were minted as part of this vote" for a
    vote that minted nothing. The answer is read off the applicant's own
    **outcome**, not off "the call returned": an admission whose commit landed
    can still skip an agent whose KeyPackage pool was empty, and that agent has
    no leaf either.
    """
    from rine._mls.add_members import add_mls_group_members

    headers = {AGENT_HEADER: acting}
    try:
        group = GroupRead.model_validate(http.get(f"/groups/{group_id}", extra_headers=headers))
        if not group_is_mls(group):
            return False
        result = add_mls_group_members(http, config_dir, acting, group_id, [applicant_id], headers)
        return any(o.agent_id == applicant_id and o.status == "added" for o in result.outcomes)
    except Exception as err:  # noqa: BLE001 — the vote stands; the leaf is retryable
        _log_unseated(applicant_id, group_id, err)
        return False


def _log_capture_failed(request_id: str, group_id: str, err: Exception) -> None:
    """The queue read that names the applicant is part of the SEAT, not the vote."""
    logger.warning(
        "Could not read the applicant for request %s in group %s before voting: %s. "
        "The vote is being cast anyway; if it admits them, a member has to run "
        "resume_admission() on the group to seat them.",
        request_id,
        group_id,
        err,
    )


def _vote_path(group_id: str, request_id: str) -> str:
    """The one route both clients POST the vote to."""
    return f"/groups/{group_id}/requests/{request_id}/vote"


def vote_on_request(
    client: Any, handle_or_id: str, request_id: str, choice: str, *, agent: str | None
) -> VoteResponse:
    """Cast a vote and, when it admits the applicant, seat them (sync)."""
    group_id = client._resolve_group_sync(handle_or_id, agent)
    applicant_id: str | None = None
    capture_failed = False
    if choice == APPROVE:
        # 🔴 Guarded: the capture belongs to the best-effort seat, not to the
        # vote. Unguarded, a transient 5xx or rate-limit on the queue read
        # aborts the whole approve before it is cast — and the caller cannot
        # tell that from a refused vote.
        try:
            applicant_id = _applicant_id(
                client.groups.list_requests(group_id, agent=agent), request_id
            )
        except Exception as err:  # noqa: BLE001 — the vote is the caller's intent
            capture_failed = True
            _log_capture_failed(request_id, group_id, err)
    data = client._http.post(
        _vote_path(group_id, request_id),
        json_body={"vote": choice},
        extra_headers=client._agent_header(agent),
    )
    result = VoteResponse.model_validate(data)
    if result.status == APPROVED and capture_failed:
        # Admitted, and this client never learned whom: nothing was minted.
        result.mls_seated = False
    if result.status == APPROVED and applicant_id is not None:
        # Resolving the acting agent is network work — a handle goes through
        # WebFinger — so it sits INSIDE the guard. Outside it, a transient
        # lookup failure raises out of a vote that has already landed, and the
        # caller cannot tell a refused vote from an irreversibly seated member;
        # the retry then answers 409 and reads as confirmation that nothing
        # happened.
        result.mls_seated = False
        try:
            acting = client._resolve_agent_id(agent)
        except Exception as err:  # noqa: BLE001 — the vote stands; the leaf is retryable
            _log_unseated(applicant_id, group_id, err)
        else:
            result.mls_seated = _seat_applicant(
                client._http, client._config_dir, acting, group_id, applicant_id
            )
    return result


async def vote_on_request_async(
    client: Any, handle_or_id: str, request_id: str, choice: str, *, agent: str | None
) -> VoteResponse:
    """Async counterpart of :func:`vote_on_request`.

    The MLS layer is synchronous, so the seat runs off the event loop through the
    same bridge ``resume_admission_async`` uses.
    """
    from rine._mls.bridge import with_sync_http

    group_id = await client._resolve_group_async(handle_or_id, agent)
    applicant_id: str | None = None
    capture_failed = False
    if choice == APPROVE:
        # Guarded for the same reason as the sync path: the capture is part of
        # the seat, and the seat never fails the vote.
        try:
            applicant_id = _applicant_id(
                await client.groups.list_requests(group_id, agent=agent), request_id
            )
        except Exception as err:  # noqa: BLE001 — the vote is the caller's intent
            capture_failed = True
            _log_capture_failed(request_id, group_id, err)
    data = await client._http.post(
        _vote_path(group_id, request_id),
        json_body={"vote": choice},
        extra_headers=await client._agent_header(agent),
    )
    result = VoteResponse.model_validate(data)
    if result.status == APPROVED and capture_failed:
        result.mls_seated = False
    if result.status == APPROVED and applicant_id is not None:
        # Same reason as the sync path: the resolve is inside the guard, so a
        # transient lookup failure cannot raise out of a vote that has landed.
        result.mls_seated = False
        applicant = applicant_id
        try:
            acting = await client._resolve_agent_id(agent)
        except Exception as err:  # noqa: BLE001 — the vote stands; the leaf is retryable
            _log_unseated(applicant, group_id, err)
        else:
            result.mls_seated = await with_sync_http(
                client,
                lambda http: _seat_applicant(
                    http, client._config_dir, acting, group_id, applicant
                ),
            )
    return result


__all__ = ["vote_on_request", "vote_on_request_async"]
