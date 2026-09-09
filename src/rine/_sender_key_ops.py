"""Sender key distribution, rotation, retirement, and auto-recovery.

Ports rine-core's ``sender-key-ops.ts`` — handles distributing sender keys
to group members via encrypted 1:1 messages.
"""

from __future__ import annotations

import os
from typing import Any

from rine._actor import AGENT_HEADER
from rine._config import sender_keys_dir
from rine._constants import MessageType
from rine._crypto._agent_keys import fetch_recipient_keys_sync
from rine._crypto.keys import _validate_path_id
from rine._crypto.message import encrypt_message
from rine._crypto.sender_keys import (
    SenderKeyState,
    generate_sender_key,
    needs_rotation,
)
from rine._crypto.sender_keys_helpers import (
    lift_retirement_if_member,
    load_sender_key_states,
    mark_sender_keys_retired,
    save_sender_key_state,
)
from rine._crypto.sender_keys_store import merge_sender_key_states, states_from_sender
from rine._logging import logger
from rine._utils import to_base64url


def distribute_sender_key_sync(
    client: Any,
    config_dir: str,
    sender_agent_id: str,
    state: SenderKeyState,
    group_id: str,
    recipient_ids: list[str],
) -> tuple[list[str], list[str]]:
    """Distribute a sender key to recipients via encrypted 1:1 DMs.

    Args:
        client: SyncHttpClient for API calls.
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        state: SenderKeyState to distribute.
        group_id: Group UUID.
        recipient_ids: List of recipient agent UUIDs.

    Returns:
        Tuple of (succeeded agent IDs, failed agent IDs).
    """
    distribution_payload = {
        "group_id": group_id,
        "sender_key_id": state.sender_key_id,
        "chain_key": to_base64url(state.chain_key),
        "message_index": state.message_index,
        "sender_agent_id": sender_agent_id,
    }

    succeeded: list[str] = []
    failed: list[str] = []

    for recipient_id in recipient_ids:
        try:
            recipient = fetch_recipient_keys_sync(client, recipient_id)
            result = encrypt_message(config_dir, sender_agent_id, recipient, distribution_payload)
            client.post(
                "/messages",
                json_body={
                    "to_agent_id": recipient_id,
                    "type": MessageType.SENDER_KEY_DISTRIBUTION,
                    "encrypted_payload": result.encrypted_payload,
                    "encryption_version": result.encryption_version,
                    "sender_signing_kid": result.sender_signing_kid,
                },
                # The distribution DM is sent BY the sender-key owner. Without
                # this the server cannot pick a sender in a multi-agent org and
                # 422s, so every recipient silently misses the key.
                extra_headers={AGENT_HEADER: sender_agent_id},
            )
            succeeded.append(recipient_id)
        except Exception:
            logger.warning("Failed to distribute SK to %s", recipient_id, exc_info=True)
            failed.append(recipient_id)

    return succeeded, failed


def get_or_create_sender_key_sync(
    client: Any,
    config_dir: str,
    sender_agent_id: str,
    group: dict[str, Any],
) -> SenderKeyState:
    """Get or create a sender key for a group, distributing as needed.

    Handles rotation triggers (message limit, age, member changes).

    Args:
        client: SyncHttpClient for API calls.
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        group: The resolved group, as ``rine._group_send`` read it. Whether the
            group is on Sender Keys at all is decided there, so reaching here
            means it is.

    Returns:
        The sender key to encrypt with.
    """
    group_id = str(group["id"])

    # Get members
    members_data = client.get(f"/groups/{group_id}/members")
    member_items = (
        members_data.get("items", members_data) if isinstance(members_data, dict) else members_data
    )
    member_ids = [
        str(m["agent_id"]) for m in member_items if str(m["agent_id"]) != sender_agent_id
    ]

    # A retirement this agent left behind on a previous departure is spent once
    # the server's own member list names it again. The read path lifts
    # it on the same fact — see ``lift_retirement_if_member`` — because a
    # re-admitted agent that reads before it sends, or never sends at all, would
    # otherwise refuse every distribution its new peers make it, forever.
    lift_retirement_if_member(
        config_dir,
        sender_agent_id,
        group_id,
        (str(m["agent_id"]) for m in member_items),
    )

    # Load existing states
    states = load_sender_key_states(config_dir, sender_agent_id, group_id)
    # 🔴 The LAST own state is the current one, and reading the FIRST is a defect
    # with two heads. The rotation below is the only writer that decides this: it
    # appends the new key and retains the one state it superseded BELOW it.
    # ``rine._crypto.message.encrypt_group_message`` writes this agent's row back
    # IN PLACE and so never changes which own row is last — it used to re-append
    # it, which is precisely how a superseded key got back to the end and became
    # what the next send sealed under. Reading the first would select the
    # SUPERSEDED key, whose
    # ``distributed_to`` still names whoever was removed, so the member-removal
    # check below would fire on every send and turn one departure into a rekey per
    # message; and where no trigger fired it would seal under a key this agent has
    # already rotated away from. Taking the last also heals an array an older
    # client left stacked. Twin: ``sender-key-ops.ts``, last-own for the same
    # reasons. Own-vs-peer is by ``sender_agent_id``, as everywhere in this file.
    own_states = [s for s in states if s.sender_agent_id == sender_agent_id]
    own_state = own_states[-1] if own_states else None

    should_rotate = own_state is None or needs_rotation(own_state)

    # Check member changes
    if own_state and not should_rotate:
        distributed_set = set(own_state.distributed_to)
        current_set = set(member_ids)
        if not current_set.issubset(distributed_set):
            # New members need the key
            undistributed = list(current_set - distributed_set)
            if undistributed:
                succeeded, _ = distribute_sender_key_sync(
                    client, config_dir, sender_agent_id, own_state, group_id, undistributed
                )
                # 🔴 Both of these, and neither is redundant. The extend is the
                # IN-MEMORY half and it is load-bearing: this object is what this
                # function returns, and ``rine._crypto.message.encrypt_group_message``
                # re-asserts this agent's own row from it at the end of the send
                # (see ``_record_distribution``'s first 🔴). Delete it as dead code
                # and the send tail writes the pre-fan-out ``distributed_to`` back,
                # so the next send re-distributes to members that already hold the
                # key. ``_record_distribution`` is the DURABLE half, and it is what
                # keeps every other row in the file. The TypeScript twin has the
                # identical pair (``sender-key-ops.ts``).
                own_state.distributed_to.extend(succeeded)
                _record_distribution(
                    config_dir, sender_agent_id, group_id, own_state.sender_key_id, succeeded
                )

        # Check if members were removed (triggers rotation)
        if distributed_set and not distributed_set.issubset(current_set | {sender_agent_id}):
            should_rotate = True

    if should_rotate:
        new_state = generate_sender_key(group_id, sender_agent_id)
        succeeded, _ = distribute_sender_key_sync(
            client, config_dir, sender_agent_id, new_state, group_id, member_ids
        )
        new_state.distributed_to = succeeded

        # Replace or append state.
        #
        # 🔴 Re-derived from a FRESH read, never from the ``states`` array above:
        # the fan-out is one DM per member, so the file can have moved under this
        # call several times over — a peer's key an ingest installed meanwhile,
        # or another sender's ratchet a concurrent decrypt advanced, would be
        # dropped by an array read from before the fan-out started. That is the
        # same lost update a racing decrypt has, and it is not a torn write, so
        # the atomic save does nothing for it.
        #
        # 🔴 The PREDICATE is re-derived from that same fresh read too, and it has
        # to be: it picks this agent's rows by IDENTITY, never by the one id
        # ``own_state`` carried in from before the fan-out. A rotation another
        # writer ran meanwhile leaves an own row that stale id does not match, so
        # it would be KEPT beside the one appended here — one extra own row per
        # racing rotation, unbounded — and it is which own row ends up LAST that
        # decides what the next send encrypts under.
        #
        # 🔴 Exactly ONE superseded own state is retained, BELOW the new one.
        # Nothing is ever sent under it again — the reader above takes the last own
        # row — but ``rine._crypto.message.encrypt_group_message`` caches this
        # agent's own self-read key in that row's ``skipped_keys`` on every send,
        # so dropping it makes this agent's own recent posts unopenable TO ITSELF:
        # the render answers ``sender_key_unavailable``, and both explanations that
        # refusal offers are false of one's own post — a sender never distributes
        # its key to itself, so there is no distribution DM for the recovery path
        # to re-ingest and the loss is permanent. Retention is bounded HERE and
        # nowhere else: this write leaves two own rows and drops whatever older
        # stack an older client left behind. That makes "at most two own rows" a
        # property of THIS LINE'S OUTPUT, never an invariant of the file — a file
        # already holding three keeps all three until the next rotation runs, and
        # the compare just below is case-SENSITIVE where the TypeScript twin
        # lower-cases, so an agent id that reached this stack upper-cased
        # classifies this agent's own past rows as peers, which this drop never
        # touches (a known pre-existing defect; the bound is only as good as the
        # count). What can no longer add a third is the merge:
        # ``merge_sender_key_states`` skips an own state whose (sender, key) pair
        # is not already on disk, so a decrypt carrying the row this rotation just
        # dropped no longer resurrects it ABOVE the new one — which is what
        # decides what the next send encrypts under. What is NOT bounded by any of
        # this is history — a post two rotations old stays unreadable, on this
        # stack as on the TypeScript one. Twin: ``sender-key-ops.ts``, which retains one the
        # same way and additionally drops departed members' peer rows on a removal
        # rotation, which this stack does not.
        current = load_sender_key_states(config_dir, sender_agent_id, group_id)
        current_own = [s for s in current if s.sender_agent_id == sender_agent_id]
        peer_states = [s for s in current if s.sender_agent_id != sender_agent_id]
        save_sender_key_state(
            config_dir,
            sender_agent_id,
            group_id,
            [*peer_states, *current_own[-1:], new_state],
        )
        return new_state

    assert own_state is not None
    return own_state


def _record_distribution(
    config_dir: str,
    sender_agent_id: str,
    group_id: str,
    sender_key_id: str,
    succeeded: list[str],
) -> None:
    """Record that this key reached ``succeeded``, onto the row as the file has it.

    The distribution that produced this list is a DM per member, so re-asserting
    the array read before it discards every write the fan-out raced — a peer's
    key the ingest installed, another sender's ratchet a concurrent decrypt
    advanced. Nothing here advances a ratchet: the only change is a union onto
    ``distributed_to``, so applying it to the live row is the same answer, minus
    the lost updates.

    🔴 **This function never writes the caller's pre-fan-out object back. The
    send does, two statements later.** A
    :class:`~rine._crypto.sender_keys.SenderKeyState` carries chain material, so
    saving the copy this call started with would ROLL BACK an advance or a
    rotation that landed on disk while the fan-out ran; what is mutated here is
    the row as the file has it, which is why the load happens here and not at the
    call site. That protection is permanent for every OTHER row — the peer keys
    and the other senders' ratchets — and it stops at this agent's OWN row.
    :func:`get_or_create_sender_key_sync` returns the pre-fan-out ``own_state``,
    ``rine._group_send.encrypt_for_group_sync`` hands that object straight to
    :func:`rine._crypto.message.encrypt_group_message`, and its tail overwrites
    the own row from it wherever the file still has it. So a ``distributed_to``
    another writer unioned on during the fan-out is merged here and dropped
    there — the tail preserves the row's POSITION, not its contents — and the union
    this call makes survives the send only because the caller ALSO extends the
    in-memory list it is about to hand on.

    🔴 **A key rotated away while the fan-out ran has nothing left to record
    against**, so a miss returns rather than appending: re-adding it here would
    resurrect a state the rotation retired on purpose. The same return covers a
    ``group leave`` that has already unlinked the file when the load below runs —
    it reads nothing — and a leave that completes between that load and the merge
    is refused by the merge, which never re-creates a retired group's file. Both
    are properties of THIS function, and the send tail now holds the same two:
    ``encrypt_group_message`` writes this agent's row back only where the file
    still has it, so it neither restores a rotated-away key nor re-creates the
    state file of a group this agent has left. It still consults no retirement
    marker — it does not need one, because a retired group has no file and a
    rotated-away key is not in it. Verify a leave by the file even so: absence is
    what both functions actually test, and only the file can report it.

    :func:`rine._crypto.sender_keys_store.merge_sender_key_states` rather than a
    whole-array save because the union is an UPDATE of one row and expresses no
    deletion — exactly what that merge is entitled to assert — and it carries the
    retired-group refusal with it.

    🔴 No lock, deliberately.
    :func:`rine._crypto.sender_keys_store.with_sender_key_states` is an ``async``
    context manager and this function is sync, run on a WORKER THREAD by the
    async client (residual 1 of that module): excluding a thread from a
    coroutine's region is a design change, not a re-read. So the window between
    this load and the merge's own is narrow but real, and the honest sentence
    about it is "no coroutine interleaves with it", never "nothing else in this
    process runs". The TypeScript twin is ``recordDistribution``
    (``rine-core/src/sender-key-ops.ts``), which closes the same half and takes
    its lock on top.

    Args:
        config_dir: Config directory path.
        sender_agent_id: The distributing agent's UUID.
        group_id: The rine group UUID.
        sender_key_id: The key that was distributed, as the id to find it by.
        succeeded: Agent ids the distribution actually reached.
    """
    if not succeeded:
        return
    current = states_from_sender(
        load_sender_key_states(config_dir, sender_agent_id, group_id), sender_agent_id
    )
    live = next((s for s in current if s.sender_key_id == sender_key_id), None)
    if live is None:
        return
    # ``dict.fromkeys`` for the union because ``distributed_to`` is an ordered
    # list on the wire and a ``set`` would reshuffle it on every write.
    live.distributed_to = list(dict.fromkeys([*live.distributed_to, *succeeded]))
    merge_sender_key_states(config_dir, sender_agent_id, group_id, [live])


def _state_paths(config_dir: str, agent_id: str, group_id: str) -> list[str]:
    """Every path this agent's sender-key state for one group could be at.

    The group id is a FILENAME here, and ``_validate_path_id`` accepts a UUID in
    either case while every writer takes the id from the server, which spells it
    lower-case. A caller that upper-cases the same group — the SDK passes an
    ``is_uuid`` argument straight through without normalising it — would
    otherwise read or unlink a path that does not exist and report that there
    was nothing to retire, while all of it is still on disk. Both spellings,
    always; the one that is not there costs nothing.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    directory = sender_keys_dir(config_dir, agent_id)
    return [
        os.path.join(directory, f"{spelling}.json")
        for spelling in dict.fromkeys([group_id, group_id.lower()])
    ]


def sender_key_state_exists(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether this agent holds any local sender-key material for one group.

    The sender-key twin of :func:`rine._mls.group_access.holds_mls_state`, and
    it exists for the same reason: a leave has to say which encryption's
    material it just retired, and these two answers are what tell a closed
    group's leave from an open one's without reading the group back.

    Args:
        config_dir: Config directory path.
        agent_id: The agent whose material is in question.
        group_id: The rine group UUID.

    Returns:
        True when a state file exists under either spelling of the group id.
    """
    return any(os.path.exists(path) for path in _state_paths(config_dir, agent_id, group_id))


def delete_sender_key(config_dir: str, agent_id: str, group_id: str) -> None:
    """Retire this agent's local sender-key material for one group.

    The key it sends under, the one state that key superseded, every peer key it
    ingested for that group, and the cached message keys all of them left behind
    — including the self-read cache :func:`rine._crypto.message.encrypt_group_message`
    writes on every send — all of which live in the single
    ``keys/{agent}/sender_keys/{group}.json`` state file, so retiring the group
    is removing that file. Retiring a group this agent holds no material for is
    **not an error**: a member of a closed group has none, and leaving must not
    fail on account of what it did not have to clean up.

    The wipe alone was point-in-time, so it no longer travels alone. Every peer
    key it deletes still sits in this agent's inbox as a
    ``rine.v1.sender_key_distribution`` DM and used to be re-ingested by the next
    group read that missed (``rine._sync_client._fetch_pending_sk_distributions``).
    So this also writes a RETIREMENT MARKER
    (:func:`rine._crypto.sender_keys_helpers.mark_sender_keys_retired`) and every
    later ingest of a sender key for this group is refused. The marker is written
    whether or not there was anything to delete: a distribution DM this agent
    never opened is material the wipe never saw, and it is in the same inbox.

    What does not come back is the cached message keys, so a message delivered
    before the wipe and never OPENED does not open afterwards.

    What the marker buys is LOCAL and it is not an eviction. Membership in an
    open group is enforced by the server's delivery filter; the marker binds
    this client's own future behaviour and nothing else, and no surface may
    describe it as putting the material beyond a departed member's reach — a
    client that never had the marker, or an operator who deletes it, is
    unaffected. What bounds a departed member's reach into later traffic is each
    remaining member ROTATING on their next send (see
    :func:`get_or_create_sender_key_sync`). Deleting one's own state on the way
    out is neither a rekey nor a cryptographic removal. The TypeScript twin is
    ``deleteSenderKey`` (``rine-core/src/sender-key-ops.ts``), with the same
    semantics.

    Args:
        config_dir: Config directory path.
        agent_id: The departing agent's UUID.
        group_id: The rine group UUID.
    """
    for path in _state_paths(config_dir, agent_id, group_id):
        try:
            os.remove(path)
        except FileNotFoundError:
            # Nothing held under this spelling. The point of the call is the
            # end state, not that it did any work.
            continue
    mark_sender_keys_retired(config_dir, agent_id, group_id)
