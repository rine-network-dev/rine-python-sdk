"""Getting out of a group — the departing member's local state.

A member that left keeps no group keys **on this client**. Its leaf stays in the
ratchet tree until an admin's Remove commit lands, so a client that kept its
epoch secrets could still read group traffic in the meantime; rine's own clients
retire that state on the way out instead.

What retirement costs differs by group type, and this module wipes both:

* **Closed (MLS).** Unrecoverable. The epoch secrets are the only copy, no peer
  re-sends them, and returning takes a fresh invitation and a new Welcome from
  an admin.
* **Open (sender keys).** The wipe alone was point-in-time: every peer key it
  deletes still sits in this agent's inbox as a
  ``rine.v1.sender_key_distribution`` DM, and the next group read that missed
  re-ingested all of them. So the wipe now also writes a retirement marker
  (:func:`rine._crypto.sender_keys_helpers.mark_sender_keys_retired`) and this
  client refuses that group's key material from then on. That refusal is LOCAL:
  nothing cryptographic ever kept a departed member out, rejoining is not gated
  on it, and what bounds a departed member's reach into later traffic is each
  remaining member ROTATING on their next send.

So retirement is not "the only way back in" — that sentence was true only of the
MLS half and false for every open group — and for an open group what it binds
is this client, not the departed member.

Both types lose the cached message keys with everything else, so a message that
was delivered before the leave and never OPENED does not open afterwards. That
is stated rather than softened: sparing it would mean retaining peer key
material past a leave, which is the thing this wipe exists to remove. The
same goes for the group read cache (:mod:`rine._crypto.group_read_cache`), the
plaintext this client kept so an already-read message could be read again — a
re-read buffer that outlived the wipe would make the sentence a leave prints
false.

This is the only sanctioned retirement point, and it invalidates the memo behind
the downgrade guard itself, so no leave path can retire state and leave a stale
"holds MLS state" behind.
"""

from __future__ import annotations

from dataclasses import dataclass

from rine._crypto.group_read_cache import delete_group_read_cache
from rine._crypto.keys import agent_keys_exist
from rine._mls.binding import open_mls_client
from rine._mls.group_access import holds_mls_state, mls_group_id_bytes, note_mls_state_changed
from rine._sender_key_ops import delete_sender_key, sender_key_state_exists


def wipe_mls_state(config_dir: str, agent_id: str, group_id: str) -> None:
    """Retire one agent's local MLS state for one group.

    Current state, every retained epoch secret, and the plaintext the self-read
    cache held. Retiring a group whose state was never installed is not an error.

    Args:
        config_dir: Config directory path.
        agent_id: The departing agent's UUID.
        group_id: The rine group UUID — the MLS state key, never the server's
            opaque ``mls_group_id`` latch.
    """
    if not agent_keys_exist(config_dir, agent_id):
        # No local key material ⇒ no MLS store to retire.
        return
    try:
        open_mls_client(config_dir, agent_id).delete_group_state(mls_group_id_bytes(group_id))
    finally:
        # In ``finally``: a delete that threw part-way may still have removed the
        # state, and a remembered "this agent holds MLS state" that outlives it
        # refuses a legitimate billboard read for the rest of the process.
        note_mls_state_changed(config_dir, agent_id, group_id)


@dataclass(frozen=True)
class RetiredGroupState:
    """Which local key material a retirement found, and therefore removed.

    Both flags false is an outcome, not a failure: a kick retires nothing by
    design, and a member of an MLS group whose Welcome was never installed had
    nothing to retire either. A surface that reported "your keys are gone" for
    those would be reporting something that did not happen — and this is also
    how a leave tells a closed group's wipe from an open group's without reading
    the group back.
    """

    mls: bool
    sender_key: bool


def retire_local_group_state(
    config_dir: str, group_id: str, removed_agent_id: str, acting_agent_id: str
) -> RetiredGroupState:
    """Retire every local key this agent held for a group it just left.

    Both encryptions, because a surface does not have to know which one the
    group ran: the MLS store for a closed group and the sender-key file for an
    open one. Whichever it did not hold is a no-op.

    Removing somebody else is a kick and leaves this agent's own keys alone. The
    caller runs the server removal **first**, so a refused leave never leaves a
    still-member without the keys to read its own group.

    What the sender-key half is **not**: a cryptographic removal. Membership in
    an open group is enforced by the server's delivery filter, and what bounds a
    departed member's reach is each remaining member rotating on their next send.

    Args:
        config_dir: Config directory path.
        group_id: The rine group UUID the removal targeted.
        removed_agent_id: The member the caller asked to remove.
        acting_agent_id: The agent the caller acted as.

    Returns:
        What was found and removed, per encryption.
    """
    if removed_agent_id.lower() != acting_agent_id.lower():
        return RetiredGroupState(mls=False, sender_key=False)
    # Sampled BEFORE the wipe: afterwards there is nothing left to ask, and a
    # caller reporting what a leave retired has to be told what was there. It
    # costs one extra store open on a leave, which is not a hot path.
    held_mls = agent_keys_exist(config_dir, acting_agent_id) and holds_mls_state(
        config_dir, acting_agent_id, group_id
    )
    held_sender_key = sender_key_state_exists(config_dir, acting_agent_id, group_id)
    wipe_mls_state(config_dir, acting_agent_id, group_id)
    delete_sender_key(config_dir, acting_agent_id, group_id)
    # The plaintext this client kept so an inbox entry could be read twice goes
    # with the keys: a re-read buffer that outlived the wipe would make "this
    # group's messages no longer open" false.
    delete_group_read_cache(config_dir, acting_agent_id, group_id)
    return RetiredGroupState(mls=held_mls, sender_key=held_sender_key)


__all__ = ["RetiredGroupState", "retire_local_group_state", "wipe_mls_state"]
