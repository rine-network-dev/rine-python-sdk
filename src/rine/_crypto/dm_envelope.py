"""Sealing and opening the 1:1 DM envelope.

There is one DM envelope, ``hpke-hybrid-v2``: X25519 and ML-KEM-768 in parallel,
bound to the recipient agent through its associated data. A recipient is always
a chain-verified agent (:mod:`rine._crypto.certs`) and every verified agent
publishes both keys, so there is nothing to negotiate and no classical fallback.
The version byte is still checked on open, so the retired envelopes are refused
by name.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._constants import EncryptionVersion
from rine._crypto import hybrid
from rine.errors import CryptoError

if TYPE_CHECKING:
    from rine._crypto.certs import VerifiedAgentKeys
    from rine._crypto.keys import AgentKeys


def seal_to_recipient(recipient: VerifiedAgentKeys, envelope: bytes) -> tuple[bytes, str]:
    """Seal an inner envelope to a verified recipient.

    Args:
        recipient: The recipient's chain-verified keys.
        envelope: The signed inner envelope.

    Returns:
        A ``(ciphertext, encryption_version)`` pair.
    """
    sealed = hybrid.seal(
        recipient.encryption_public_key,
        recipient.pq_encryption_public_key,
        envelope,
        hybrid.AgentMessage(recipient.agent_id),
    )
    return sealed, EncryptionVersion.HPKE_HYBRID_V2


def seal_to_self(keys: AgentKeys, agent_id: str, envelope: bytes) -> bytes:
    """Seal an inner envelope to the sender's own keys, for self-read.

    Purely additive: the recipient's ciphertext is unaffected.

    Args:
        keys: The sender's own keys.
        agent_id: The sender's own agent id, which is the context it is sealed under.
        envelope: The signed inner envelope.

    Returns:
        The self-sealed ciphertext.
    """
    return hybrid.seal(
        keys.encryption.public_key,
        keys.pq_encryption.public_key,
        envelope,
        hybrid.AgentMessage(agent_id),
    )


def open_dm(keys: AgentKeys, agent_id: str, encrypted: bytes) -> bytes:
    """Open a 1:1 payload addressed to ``agent_id``.

    Args:
        keys: The reader's own keys.
        agent_id: The reader's own agent id, which the payload must be bound to.
        encrypted: The raw encrypted payload.

    Returns:
        The signed inner envelope.

    Raises:
        CryptoError: If the payload is empty, is not ``hpke-hybrid-v2``, or
            does not open under this reader and context.
    """
    if not encrypted:
        raise CryptoError("Encrypted payload is empty")
    return hybrid.open(
        keys.encryption.private_key,
        keys.pq_encryption.private_key,
        encrypted,
        hybrid.AgentMessage(agent_id),
    )
