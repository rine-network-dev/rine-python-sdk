"""The operator pin: which agent is the operator's console seat, and its full public key.

Configuration the agent cannot write supplies it. The key is compared in full, as bytes: a
fingerprint of it, however it is truncated, is a weaker statement, and 48 bits can be ground
to a collision. Twin of ``rine-core/src/operator-pin.ts``.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

from rine._crypto._sender_verdict import sender_matches
from rine._utils import from_base64url, to_base64url

#: The local part Rine Fleet gives the operator console seat.
_SEAT_LOCAL_PART = "ops"
#: Characters in an agent or group handle (``name@org.rine.network``, ``#group@org``).
_OUTSIDE_HANDLE = re.compile(r"[^A-Za-z0-9#@._-]")
#: The longest handle shown to a model or compared with a pin; anything longer is cut.
_MAX_HANDLE_LENGTH = 128
_ED25519_KEY_BYTES = 32
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True, slots=True)
class OperatorPin:
    """The seat the agent trusts as its operator."""

    #: The seat's agent id, a UUID.
    agent_id: str
    #: The seat's 32-byte Ed25519 public key as unpadded base64url.
    signing_key: str
    #: The seat's handle, when the host knows it. It drives only :func:`looks_like_seat`;
    #: authority compares the id and the key, never a handle.
    handle: str | None = None


def pin_matches_sender(pin: OperatorPin, from_agent_id: str) -> bool:
    """Whether ``from_agent_id`` is the pinned seat. Ids only: a handle is never compared."""
    if _UUID.fullmatch(pin.agent_id.strip().lower()) is None:
        return False
    return sender_matches(pin.agent_id, from_agent_id)


def pin_matches_key(pin: OperatorPin, verifying_key: bytes | None) -> bool:
    """Whether ``verifying_key``, the key that verified a signature, is the pinned key.

    Fails closed on every input that is not a real key: a missing verifying key, a pin that is
    not canonical unpadded base64url of exactly 32 bytes, or a length mismatch.
    """
    if verifying_key is None or len(verifying_key) != _ED25519_KEY_BYTES:
        return False
    try:
        pinned = from_base64url(pin.signing_key)
    except ValueError:
        return False
    if len(pinned) != _ED25519_KEY_BYTES or to_base64url(pinned) != pin.signing_key:
        return False
    return hmac.compare_digest(pinned, verifying_key)


def clean_handle(handle: str) -> str:
    """A handle as it may appear in a wake line or be compared with the pinned seat handle.

    Every character the server would not have issued becomes ``_`` and the length is capped.
    Twin of ``cleanHandle`` in ``rine-core``.
    """
    return _OUTSIDE_HANDLE.sub("_", handle)[:_MAX_HANDLE_LENGTH]


def looks_like_seat(pin: OperatorPin | None, handle: str) -> bool:
    """Whether ``handle``, a sender handle, is written like the operator's console seat.

    Needs a pin: with none, nothing is the operator's, so no handle is its look-alike. A
    handle matches when it equals the pinned seat handle or, whatever the pin carries, when
    its local part is ``ops``. Both handles go through :func:`clean_handle` and compare
    case-insensitively, so a long or out-of-set seat handle still matches the same sender
    handle. Only a display decision: a look-alike shows the sender's agent id instead of its
    handle.
    """
    if pin is None:
        return False
    lowered = clean_handle(handle).lower()
    pinned = clean_handle((pin.handle or "").strip()).lower()
    if pinned and lowered == pinned:
        return True
    return lowered.partition("@")[0] == _SEAT_LOCAL_PART
