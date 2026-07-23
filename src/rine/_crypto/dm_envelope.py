"""Choosing, sealing and opening the 1:1 DM envelope.

rine has two DM envelopes and negotiates between them without asking the
caller: ``hpke-hybrid-v1`` (post-quantum) whenever the recipient publishes an
ML-KEM key, ``hpke-v1`` (classical) otherwise. Both stacks negotiate the same
way, so which one a message ends up in depends only on the recipient's
published keys, never on which SDK sent it.

Opening runs the other way round: the version byte in the payload picks the
envelope, so a reader never has to be told which one it is looking at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._constants import EncryptionVersion
from rine._crypto import hybrid
from rine._crypto.hpke import open as hpke_open
from rine._crypto.hpke import seal as hpke_seal
from rine._crypto.keys import AgentKeys, jwk_to_public_key
from rine._crypto.pq_keys import jwk_to_pq_public_key
from rine.errors import CryptoError


@dataclass(frozen=True)
class RecipientKeys:
    """A recipient's published encryption keys.

    ``pq_encryption`` is ``None`` for an agent that publishes no ML-KEM key,
    which is the whole of the classical-or-hybrid decision.
    """

    encryption: bytes
    pq_encryption: bytes | None = None


def recipient_keys_from_response(data: dict[str, Any]) -> RecipientKeys:
    """Read a ``/agents/{id}/keys`` response into a :class:`RecipientKeys`."""
    pq_jwk = data.get("pq_encryption_public_key")
    return RecipientKeys(
        encryption=jwk_to_public_key(data["encryption_public_key"], expected_crv="X25519"),
        pq_encryption=None if not pq_jwk else jwk_to_pq_public_key(pq_jwk),
    )


def seal_to_recipient(recipient: RecipientKeys, envelope: bytes) -> tuple[bytes, str]:
    """Seal an inner envelope to a recipient, choosing the envelope version.

    Args:
        recipient: The recipient's published encryption keys.
        envelope: The signed inner envelope.

    Returns:
        A ``(ciphertext, encryption_version)`` pair.
    """
    if recipient.pq_encryption:
        return (
            hybrid.seal(recipient.encryption, recipient.pq_encryption, envelope),
            EncryptionVersion.HPKE_HYBRID_V1,
        )
    return hpke_seal(recipient.encryption, envelope), EncryptionVersion.HPKE_V1


def seal_to_self(keys: AgentKeys, envelope: bytes) -> bytes:
    """Seal an inner envelope to the sender's own keys, for self-read.

    Negotiates on the SENDER's own post-quantum capability, independent of the
    recipient's: the sender is the only reader of this copy. Purely additive —
    the recipient's ciphertext is unaffected.

    Args:
        keys: The sender's own keys.
        envelope: The signed inner envelope.

    Returns:
        The self-sealed ciphertext.
    """
    if keys.pq_encryption is not None:
        return hybrid.seal(keys.encryption.public_key, keys.pq_encryption.public_key, envelope)
    return hpke_seal(keys.encryption.public_key, envelope)


def open_dm(keys: AgentKeys, encrypted: bytes) -> bytes:
    """Open a 1:1 payload, dispatching on its version byte.

    Args:
        keys: The reader's own keys.
        encrypted: The raw encrypted payload.

    Returns:
        The signed inner envelope.

    Raises:
        CryptoError: If the payload is empty, if it is post-quantum and the
            reader has no ML-KEM key, or if decryption fails.
    """
    if not encrypted:
        raise CryptoError("Encrypted payload is empty")

    if encrypted[0] != hybrid.VERSION_HYBRID:
        return hpke_open(keys.encryption.private_key, encrypted)

    if keys.pq_encryption is None:
        raise CryptoError(
            "Received an hpke-hybrid-v1 message but this agent has no ML-KEM key. "
            "It was onboarded before rine published post-quantum DM keys; rotate "
            "its keys to publish one, after which peers seal to it."
        )
    return hybrid.open(keys.encryption.private_key, keys.pq_encryption.private_key, encrypted)
