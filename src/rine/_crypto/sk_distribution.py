"""What a sender-key distribution's own plaintext is allowed to say.

A ``rine.v1.sender_key_distribution`` DM is verified against the sender the SERVER
stamped on the row, and its stored identity comes from the verified kid — but every
other field in it is the sender's own plaintext, chosen freely by any agent that can
DM this one. This module is where those fields stop being taken at their word.

It lives beside the state it builds rather than in either client because the sync and
async scans are hand-mirrored copies of one pass
(:meth:`rine._sync_client.SyncRineClient._scan_pending_sk_distributions` and its async
twin), and a check written twice is a check that gets corrected once. The TypeScript
twin has a single ingest — ``ingestSenderKeyDistribution``
(``rine-core/src/crypto/ingest.ts``) — and carries the same three rules inline.

Every refusal here raises :class:`~rine.errors.CryptoError`, which both scans already
catch per row: a distribution that cannot be trusted is skipped and the pass carries
on, so one hostile DM cannot cost the reader the honest keys behind it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._crypto.keys import _validate_path_id
from rine._crypto.sender_keys import MESSAGE_INDEX_SIZE, SenderKeyState
from rine._utils import from_base64url
from rine.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

#: Bytes in a chain key. It is an HMAC-SHA256 ratchet root and every honest producer
#: mints exactly this many (:func:`rine._crypto.sender_keys.generate_sender_key`), but
#: HMAC accepts a key of any length — so nothing downstream would ever notice a
#: 0-byte or a 1 MiB one, and the reader would store what it was sent.
CHAIN_KEY_SIZE = 32

#: The largest index the wire format can name: it carries the message index in a
#: big-endian uint32 (``rine._crypto.sender_keys``), so a state above this can never
#: be reached by a real message, and one below zero can never be reached at all.
MAX_MESSAGE_INDEX = 2 ** (8 * MESSAGE_INDEX_SIZE) - 1


def _canonical_id(value: Any, label: str) -> str:
    """One UUID, spelled the one way every other reader of it spells it.

    🔴 Lower-casing is not cosmetic. ``_validate_path_id`` accepts either case, and
    the group id from a distribution becomes a FILENAME — while the retirement marker
    and the group read cache both lower-case theirs, and every honest reader passes
    the server's own lower-case spelling. Leaving the payload's spelling intact gave a
    single logical group one state-file namespace per casing: a file no reader looks
    in, no leave-time cleanup unlinks, and whose contents do not count as "already
    held" against the canonical file.
    """
    if not isinstance(value, str):
        raise CryptoError(f"Invalid {label}: expected a UUID string, got {type(value).__name__}")
    _validate_path_id(value, label)
    return value.lower()


def distribution_group_id(payload: Mapping[str, Any]) -> str:
    """The group this distribution names, in the spelling everything else uses."""
    return _canonical_id(payload.get("group_id"), "group_id")


def sender_key_state_from_distribution(
    payload: Mapping[str, Any], group_id: str, signer_agent_id: str
) -> SenderKeyState:
    """One peer's ratchet state, built from a distribution that has been checked.

    *signer_agent_id* is the identity the envelope's signature established — never
    ``payload["sender_agent_id"]``, which the sender writes for itself.

    Raises:
        CryptoError: The payload names a key id that is not a UUID, a chain key that
            is not :data:`CHAIN_KEY_SIZE` bytes, or a message index that no message
            could ever carry.
    """
    chain_key = from_base64url(payload["chain_key"])
    if len(chain_key) != CHAIN_KEY_SIZE:
        raise CryptoError(
            f"Invalid chain_key: expected {CHAIN_KEY_SIZE} bytes, got {len(chain_key)}"
        )
    message_index = payload.get("message_index", 0)
    # ``bool`` is an ``int`` in Python and ``True`` would silently ratchet to 1.
    if isinstance(message_index, bool) or not isinstance(message_index, int):
        raise CryptoError(f"Invalid message_index: expected an integer, got {message_index!r}")
    if not 0 <= message_index <= MAX_MESSAGE_INDEX:
        raise CryptoError(f"Invalid message_index: {message_index} is outside the wire's uint32")
    return SenderKeyState(
        sender_key_id=_canonical_id(payload.get("sender_key_id"), "sender_key_id"),
        group_id=group_id,
        sender_agent_id=signer_agent_id,
        chain_key=chain_key,
        message_index=message_index,
    )


def already_held(states: Iterable[SenderKeyState], candidate: SenderKeyState) -> bool:
    """Whether this agent already holds *candidate*'s key — FROM ITS OWN SENDER.

    🔴 Scoped to the pair, never to the key id alone. A sender key id is minted by
    whoever sends it, so a check that asks only "do I hold this id" makes the first
    distribution to claim an id the owner of that slot for good: an attacker who reads
    a peer's id out of its own copy of that peer's distribution, then sends one of its
    own, silently displaces the genuine key. The inbox lists newest-first and the scan
    imposes no ordering, so the later DM is processed first and no race is needed. The
    peer's group posts then refuse to open, permanently — re-scanning re-skips the DM
    that would have fixed it — and the refusal reads as a crypto regression.

    Agent ids compare case-insensitively, as the TypeScript own-row test already does:
    ``agent_id_from_kid`` preserves whatever case the signer put in its kid, so a
    case-sensitive comparison would hand one sender a fresh slot per spelling of its
    own id.
    """
    sender = candidate.sender_agent_id.lower()
    return any(
        s.sender_key_id == candidate.sender_key_id and s.sender_agent_id.lower() == sender
        for s in states
    )


__all__ = [
    "CHAIN_KEY_SIZE",
    "MAX_MESSAGE_INDEX",
    "already_held",
    "distribution_group_id",
    "sender_key_state_from_distribution",
]
