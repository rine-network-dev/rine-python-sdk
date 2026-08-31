"""Which encryption a group send uses, decided once.

A rine group is either MLS-active or on Sender Keys, and the server enforces the
choice: it refuses a ``sender-key-v1`` send to an MLS group, and vice versa. The
group is therefore resolved once here and the branch taken from what it says,
rather than each client guessing and retrying.

``mls_pending`` counts as MLS: the group is frozen mid-init and the MLS commit
that unfreezes it is already in flight. That is
:func:`rine.format.group_accepts_mls_send_only`, the mirror of the server's own
``is_mls_frozen``, and this module asks it rather than restating it.

What the server says is also the only account of a group's encryption a client
gets, which makes it the one account a client must not take at its word: a
server that presents an MLS group as a sender-key group walks every member back
onto a broadcast key it distributes itself. The contradiction is refused here,
between the resolve and the branch — see :func:`encrypt_for_group_sync`.
"""

from __future__ import annotations

from typing import Any

from rine._agent_handles import agent_handles_from_http
from rine._crypto.message import EncryptResult, encrypt_group_message
from rine._group_ref import group_local_part, group_row_by_local_name, sigiled_group_ref
from rine._resolve import is_uuid
from rine._resources.group_ops import unwrap_items
from rine._sender_key_ops import get_or_create_sender_key_sync
from rine.errors import NotAGroupMemberError
from rine.format import group_accepts_mls_send_only
from rine.group_words import (
    ACTING_AGENT_SPELLING,
    NO_SEAT_TO_ACT_AS,
    NOT_A_MEMBER_CLAUSE,
    own_agents_clause,
)
from rine.types import GroupRead


def resolve_group_for_send(client: Any, group_handle: str) -> dict[str, Any]:
    """The group a ``#handle`` send targets, as the server returns it.

    Two rungs. ``GET /groups?handle=`` is an equality test against the stored
    handle and answers all but the mistyped send. When it answers nothing, the
    handle's LOCAL PART goes through the same four-tier ladder every other group
    verb resolves through (:func:`rine._group_ref.group_row_by_local_name`) —
    the refusal quoting what the caller wrote, never the local part it searched
    on.

    🔴 The fallback exists for a FABRICATED org half, which is the shape three
    live-model runs actually produced: the ``@`` is precisely what routes a
    reference down the exact branch, so ``#ops@acme.rine.network`` written at an
    org that is not ``acme`` failed where the bare ``ops`` — strictly less
    information — resolved. This is the send path's share of putting the two
    behind one ladder.

    Bounded by the route rather than by trust: ``GET /groups`` is org-scoped, so
    the ladder reaches only a group this org already holds a seat in, and the
    server refuses a post by an agent holding no seat regardless. Ambiguity
    refuses and names the candidates; it never picks one.

    Args:
        client: Sync HTTP client.
        group_handle: Group handle, with or without the leading ``#``.

    Raises:
        NotFoundError: When no group of this org answers to that handle.
        ConfigError: When more than one does.
    """
    exact = unwrap_items(client.get("/groups", params={"handle": sigiled_group_ref(group_handle)}))
    if exact:
        group: dict[str, Any] = exact[0]
        return group
    return group_row_by_local_name(
        unwrap_items(client.get("/groups")),
        group_local_part(group_handle),
        spelling=group_handle,
    )


def encrypt_for_group_sync(
    client: Any, config_dir: str, agent_id: str, group_handle: str, payload: object
) -> tuple[EncryptResult, GroupRead]:
    """Encrypt one payload for a group, whichever encryption the group uses.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The sending agent's UUID — the identity the sender key is
            ratcheted under and the MLS leaf belongs to.
        group_handle: Group handle, with or without the leading ``#``.
        payload: JSON-serializable message payload.

    Returns:
        The ciphertext (carrying its own ``encryption_version``) and the group
        the reference RESOLVED to.

        🔴 The ROW, and not the id it used to return, because the caller's next
        act is to address the wire. ``POST /messages`` looks ``to_handle`` up by
        exact equality, so a body carrying the spelling the caller *wrote* is
        404'd by the server for every reference this function's own fallback
        widened — encrypted for the right group, refused on the way out. The row
        carries both the handle that body needs and the id, so neither caller
        has to re-resolve or unpack a second bare ``str``.

    Raises:
        MlsDowngradeError: When the server presents the group as sender-key
            while this agent holds local MLS state for it.
    """
    raw = resolve_group_for_send(client, group_handle)
    group = GroupRead.model_validate(raw)
    group_id = str(group.id)
    server_says_mls = group_accepts_mls_send_only(group)

    # Imported here, not at module scope: importing anything under ``rine._mls``
    # loads the compiled MLS core, and this module is on the Sender Keys path.
    from rine._mls.downgrade import assert_no_mls_downgrade

    # The guard goes HERE — after the resolve, before the branch. Reaching the
    # sender-key branch at all already hands a server-chosen recipient list a
    # sender key (``rine._sender_key_ops.get_or_create_sender_key_sync`` fans the
    # key out to whatever membership the server returns), so a guard placed after
    # the branch guards nothing. There is no fallback and no sender-key retry: a
    # server contradicting this agent's own MLS state is refused outright.
    assert_no_mls_downgrade(config_dir, agent_id, group_id, server_says_mls)

    if server_says_mls:
        from rine._mls.messages import encrypt_mls_group_message

        return encrypt_mls_group_message(client, config_dir, agent_id, group, payload), group

    refuse_if_not_seated(client, group, agent_id)
    state = get_or_create_sender_key_sync(client, config_dir, agent_id, raw)
    result, _ = encrypt_group_message(config_dir, agent_id, group_id, state, payload)
    return result, group


def refuse_if_not_seated(client: Any, group: GroupRead, agent_id: str) -> None:
    """Refuse a Sender Keys send by an agent that holds no seat in the group.

    A refused group send is not a no-op on this path.
    :func:`rine._sender_key_ops.get_or_create_sender_key_sync` fans the sender
    key out to every member the server lists, as ordinary 1:1 messages, *before*
    anything is posted — so an unseated agent wrote real message and delivery
    rows into the inbox of every member, other orgs included, and was then told
    by the ``403`` that it was not a member. Nothing undoes them. This
    comparison is what stops it, and it is made before the first write.

    🔴 **"The server did not answer" and "none of your agents is seated" are
    different facts, and only one of them refuses.** ``member_agent_ids`` is a
    young field: a server that predates it omits the key, and
    :attr:`rine.types.GroupRead.member_agent_ids` defaults to ``[]`` so that
    such a server still parses — so after validation both cases hold the same
    empty list, and a guard that could not tell them apart would refuse
    **every** open-group send made against an older server. ``model_fields_set``
    is what tells them apart: pydantic records which fields the payload
    actually carried, so an omitted key is absent from it and an explicit ``[]``
    is present. An absent key is not an answer, so this returns.

    🔴 **A caller this client could not resolve to a UUID is also not an
    answer.** :func:`rine._resolve.resolve_handle_sync` returns the handle it
    was given when WebFinger is unreachable, so *agent_id* can arrive as a
    handle — which matches no seat in a list of UUIDs and would accuse a
    genuinely seated agent of not being a member. That send falls through
    instead and fails, if it fails, on the honest error further down.

    Placement is the other half. This runs *after*
    :func:`rine._mls.downgrade.assert_no_mls_downgrade` and only on the
    sender-key branch: above it, a server could answer ``member_agent_ids: []``
    and convert a downgrade attack into a benign "you are not seated", spending
    the alarm the guard exists to raise. The MLS branch carries no fan-out and
    is left alone.

    The refusal has **two arms**, because the remedy does. When a sibling of
    this org is seated, the sentence names it by **handle** — the spelling the
    remedy in the next clause tells the caller to act as, since printing UUIDs
    there and asking for a handle in the same breath is ruled out. The group
    this guard holds was validated inside the send path and carries no handle
    map, so one is fetched here, from the client this call is already using and
    only once that arm is certain:
    :func:`rine._agent_handles.agent_handles_from_http`
    answers an empty map for every failure, and an empty map renders the UUIDs
    the server sent. A refusal never becomes a connection error because a
    courtesy lookup could not be made.

    When **no** agent of this org is seated, that advice has no exit — there is
    no sibling to act as — and the acting-agent clause is replaced by
    :data:`rine.group_words.NO_SEAT_TO_ACT_AS`, which names the only thing that
    changes the answer. That arm spells no handle, so it buys no agent list
    either: the lookup stays on the sentence that has something to spell.

    Args:
        client: Sync HTTP client, read once — on the seated arm of the refusal
            only — to spell the seats as handles.
        group: The group as this call validated it, for the seats and the
            handle — and, through ``model_fields_set``, for whether the server
            answered this question at all.
        agent_id: The acting agent's UUID, as this call resolved it.

    Raises:
        NotAGroupMemberError: The server answered which agents of this org hold
            a seat and this one is not among them — naming the seated siblings
            to act as instead, or, when there are none, what has to happen
            before this org can post at all.
    """
    if "member_agent_ids" not in group.model_fields_set:
        return
    acting = agent_id.strip().lower()
    if not is_uuid(acting):
        return
    seated = {str(seat).strip().lower() for seat in group.member_agent_ids}
    if acting in seated:
        return
    refused = f"Refusing to send to {group.handle} as {agent_id}: it {NOT_A_MEMBER_CLAUSE}."
    nothing_happened = "Nothing was sent, and no sender key was distributed."
    if not seated:
        # The seat set this guard already built is the branch: empty means no
        # agent of the org holds a seat, which is exactly the arm
        # ``own_agents_clause`` answers ``NO_OWN_AGENTS`` for. Asked here rather
        # than off that clause because this arm names no handle, so buying
        # ``GET /agents`` to spell a seat that does not exist would be a
        # round-trip whose result is thrown away.
        raise NotAGroupMemberError(f"{refused} {NO_SEAT_TO_ACT_AS} {nothing_happened}")
    seats = own_agents_clause(group, agent_handles_from_http(client))
    raise NotAGroupMemberError(
        f"{refused} Seated agents of your org: {seats}. {ACTING_AGENT_SPELLING} {nothing_happened}"
    )
