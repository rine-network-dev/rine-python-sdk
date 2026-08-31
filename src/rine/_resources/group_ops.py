"""The decisions ``client.groups.create`` makes.

Creating a group wraps a plain route in a second step that is *about* the
group's MLS state rather than about the route: it founds it. That step may not
fail the operation the caller actually asked for.

It lives here rather than in :mod:`rine._resources.groups` because there are two
resource classes — sync and async — asking the same questions, and the resource
module is a delegation surface. The sync/async pair mirrors
:func:`rine._mls.group_init.found_mls_state` and its ``_async`` twin: only the
awaits differ, and every message and fallback is stated once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._constants import NOT_GIVEN, NotGiven
from rine._logging import logger
from rine.group_admission import GroupAdmissionReport, GroupCreateWithRoster

if TYPE_CHECKING:
    from rine.types import GroupRead

VISIBILITY_REQUIRED_MESSAGE = (
    "Every rine group states its visibility; there is no default, because the same "
    "call would otherwise mean two different things on two different surfaces. "
    'Choose visibility="private" — the group is not listed at dir.rine.network and '
    'members are signalled when someone joins — or visibility="public" — the group '
    "is listed at dir.rine.network for anyone to find, and the member-joined signal "
    "is off. Name one and make the call again."
)


def require_visibility(visibility: str | NotGiven | None) -> str:
    """The stated visibility, or a refusal that says what to state.

    The SDK used to default to ``private`` while the CLI and MCP defaulted to
    ``public`` for open enrollment, so the same command produced a group that
    was listed in the directory on one surface and not on the other — and the
    directory listing also flips the member-joined signal, so the two differed
    in who gets told about a join as well as in who can find the group.

    No client picks for the caller any more. The cost is paid once, loudly, at
    the call site, which is the only version of this where nobody's group
    changes visibility without them typing it.

    Raises:
        ValueError: When no visibility was named.
    """
    if visibility is None or isinstance(visibility, NotGiven):
        raise ValueError(VISIBILITY_REQUIRED_MESSAGE)
    return visibility


def create_body(
    name: str,
    *,
    description: str | None,
    enrollment: str,
    visibility: str,
    members: list[str] | None = None,
    vote_duration_hours: int | None = None,
    enable_mls: bool | None,
) -> dict[str, Any]:
    """The ``POST /groups`` body.

    ``mls_enabled`` travels ONLY when the caller asked for ``enable_mls=False``.
    A new group is an MLS group on the post-quantum X-Wing ciphersuite unless
    its enrollment policy puts it on the sender-key path, and that is the
    server's own default (``GroupCreate.mls_enabled``,
    ``src/rine/api/group_schemas.py``) — so this SDK states no default of its
    own, and an unset flag makes the same group the old body made.

    🔴 That is a claim about the RESULT and not about the bytes. This body used
    to carry an unconditional ``"mls_enabled": True`` and now omits the key
    entirely, so an unset flag does not leave the request as it was — it leaves
    the group as it was, because the server's declared default for the omitted
    field is the ``True`` that used to be sent. The safety of the drop rests on
    that server-side default and on nothing else: a server change that moved it
    would silently move every group this SDK creates onto the other regime.
    ``buildCreateBody`` in ``rine-ts-sdk`` never sent the key at all, which is
    why the sentence "byte-identical to what it always was" is true over there
    and was false here.

    The ``False`` has to reach the server rather than merely skipping the
    client-side founding: a create that only skipped it would leave a closed row
    still saying "created to run MLS" with no latch, which every surface renders
    as a broken MLS group for the life of the group and no shipped client can
    PATCH back. Same rule, same reason, as ``buildCreateBody`` in
    ``rine-ts-sdk/src/resources/groups-create.ts``.

    ``vote_duration_hours`` rides this body rather than a follow-up ``PATCH``.
    The route has always accepted it at create (1-72, defaulting to 72), and a
    group founded at the default and then edited is a different group for as
    long as the second call has not landed — so a create that names a window and
    a create that does not are one request either way.

    ``members`` is a roster, and a roster **invites**. Every entry mints a
    voucher that holds a ratchet-tree seat until it is accepted or expires; none
    of them creates a membership row, so the creator is still the only member of
    the group this call returns. What the roster buys is that the founding
    commit has somebody to admit — before it, a brand-new group's founding
    roster was always empty and the size-aware batch was unreachable.
    """
    body: dict[str, Any] = {
        "name": name,
        "enrollment_policy": enrollment,
        "visibility": visibility,
    }
    if enable_mls is False:
        body["mls_enabled"] = False
    if description is not None:
        body["description"] = description
    if members:
        body["members"] = list(members)
    if vote_duration_hours is not None:
        body["vote_duration_hours"] = vote_duration_hours
    return body


def parse_create_response(data: Any) -> GroupCreateWithRoster:
    """Read either shape of the create response.

    With no roster the server answers a bare ``GroupRead``, byte-identical to
    what it always answered; with one it answers ``{group, roster}``. Both land
    in one object, so a caller never has to know which shape it got.
    """
    if isinstance(data, dict) and "group" in data and "roster" in data:
        return GroupCreateWithRoster.model_validate(
            {**data["group"], "roster": GroupAdmissionReport.model_validate(data["roster"])}
        )
    return GroupCreateWithRoster.model_validate(data)


def _warn_refresh_failed(group: GroupRead) -> None:
    logger.warning(
        "Group %s was created, but re-reading it after the MLS init failed; "
        "returning the create response, which does not yet carry the group's "
        "MLS latch. Read the group again to see it.",
        group.handle,
        exc_info=True,
    )


def create_group(
    client: Any,
    name: str,
    *,
    description: str | None,
    enrollment: str,
    visibility: str | NotGiven | None = NOT_GIVEN,
    members: list[str] | None = None,
    vote_duration_hours: int | None = None,
    enable_mls: bool | None,
    agent: str | None,
) -> GroupCreateWithRoster:
    """Create a group and found its MLS state (sync). See ``SyncGroups.create``."""
    from rine._mls.group_init import found_mls_state
    from rine._resolve import resolve_to_uuid_sync

    extra = client._agent_header(agent)
    body = create_body(
        name,
        description=description,
        enrollment=enrollment,
        visibility=require_visibility(visibility),
        # The roster is a list of AGENT UUIDs on the wire, and every caller of
        # this — the wrappers included — advertises "handles or UUIDs". A handle
        # sent unresolved comes back as a pydantic ``uuid_parsing`` dump, which
        # is the failure mode rine's named refusals exist to abolish, on the
        # field this wave added. ``invite`` has always resolved; create did not,
        # and the inconsistency lived inside one SDK.
        members=[resolve_to_uuid_sync(client._api_url, m) for m in members] if members else None,
        vote_duration_hours=vote_duration_hours,
        enable_mls=enable_mls,
    )
    group = parse_create_response(
        client._http.post("/groups", json_body=body, extra_headers=extra)
    )
    report = found_mls_state(client, group, agent, enable_mls=enable_mls)
    if not report.landed:
        # Nothing was founded — a sender-key policy, or an init that failed. The
        # create response is already the whole truth, so no round trip is spent
        # on it; a failure travels back on ``mls_init`` instead of being lost.
        return group.model_copy(update={"mls_init": report.failure})
    # The init latches ``mls_group_id`` server-side AFTER the create response was
    # minted, so the object above still says "no MLS". Re-read it, or every
    # surface renders a brand-new MLS group as sender-key. Guarded: the group
    # already exists, and a cosmetic refresh must never destroy it. The roster
    # and the admission are carried across — the re-read route reports neither.
    #
    # ``report.admission`` is the half the roster counts cannot state: a roster
    # invites, and the founding Welcome is what decides whether an invitee can
    # read anything. Computing it and dropping it answered "40 invited, 0
    # skipped" to a founding that left three agents without a leaf.
    carried = {"roster": group.roster, "mls_admission": report.admission}
    try:
        fresh = parse_create_response(client._http.get(f"/groups/{group.id}", extra_headers=extra))
    except Exception:
        _warn_refresh_failed(group)
        return group.model_copy(update={"mls_admission": report.admission})
    return fresh.model_copy(update=carried)


async def create_group_async(
    client: Any,
    name: str,
    *,
    description: str | None,
    enrollment: str,
    visibility: str | NotGiven | None = NOT_GIVEN,
    members: list[str] | None = None,
    vote_duration_hours: int | None = None,
    enable_mls: bool | None,
    agent: str | None,
) -> GroupCreateWithRoster:
    """Async counterpart of :func:`create_group`."""
    from rine._mls.group_init import found_mls_state_async
    from rine._resolve import resolve_to_uuid_async

    extra = await client._agent_header(agent)
    body = create_body(
        name,
        description=description,
        enrollment=enrollment,
        visibility=require_visibility(visibility),
        # Handles resolve here for the same reason they do on the sync path and
        # on invite: the wire field is a list of UUIDs.
        members=[await resolve_to_uuid_async(client._api_url, m) for m in members]
        if members
        else None,
        vote_duration_hours=vote_duration_hours,
        enable_mls=enable_mls,
    )
    group = parse_create_response(
        await client._http.post("/groups", json_body=body, extra_headers=extra)
    )
    report = await found_mls_state_async(client, group, agent, enable_mls=enable_mls)
    if not report.landed:
        return group.model_copy(update={"mls_init": report.failure})
    carried = {"roster": group.roster, "mls_admission": report.admission}
    try:
        fresh = parse_create_response(
            await client._http.get(f"/groups/{group.id}", extra_headers=extra)
        )
    except Exception:
        _warn_refresh_failed(group)
        return group.model_copy(update={"mls_admission": report.admission})
    return fresh.model_copy(update=carried)


def unwrap_items(data: Any) -> Any:
    """The rows of a collection route.

    The server returns them either as a bare array or wrapped in ``items``.
    """
    return data.get("items", data) if isinstance(data, dict) else data


__all__ = [
    "VISIBILITY_REQUIRED_MESSAGE",
    "create_body",
    "create_group",
    "create_group_async",
    "parse_create_response",
    "require_visibility",
    "unwrap_items",
]
