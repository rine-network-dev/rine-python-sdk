"""Ed25519 message signatures, bound to the scope they are made for.

A rine message signature covers a context prefix, the scope it is addressed to
and the payload::

    "rine.v1.msg-sig"   || 0x00 || ASCII(recipient agent id) || 0x00 || payload   (1:1)
    "rine.v1.group-sig" || 0x00 || ASCII(group id)           || 0x00 || payload   (group)

The scope is the recipient agent id for a 1:1 message and the group id for a
group message, so a signature made for one recipient or group verifies for no
other. The two prefixes differ, so a client-minted agent id equal to a
group id cannot make a 1:1 signature and a group signature interchangeable, and
no raw Ed25519 signature over bare plaintext is accepted. Both prefixes are
disjoint from every JWS ``typ``, so a message signature is never a valid
certificate or assertion signature either. There is deliberately no unprefixed
signing or verifying path. Verification is strict (:mod:`rine._crypto.ed25519_strict`).
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto.derive import canonical_uuid
from rine._crypto.ed25519_strict import verify_ed25519_strict

_MESSAGE_PREFIX = b"rine.v1.msg-sig"
_GROUP_PREFIX = b"rine.v1.group-sig"
_SEP = b"\x00"


@dataclass(frozen=True, slots=True)
class MessageSig:
    """A 1:1 message signature, scoped to its recipient agent."""

    recipient_agent_id: str


@dataclass(frozen=True, slots=True)
class GroupSig:
    """A group message signature, scoped to its group."""

    group_id: str


SigScope = MessageSig | GroupSig


def signing_input(scope: SigScope, payload: bytes) -> bytes:
    """Build the bytes a message signature covers.

    Args:
        scope: The recipient agent or group the signature is addressed to.
        payload: The plaintext being signed.

    Returns:
        ``prefix || 0x00 || ASCII(scope id) || 0x00 || payload``, with the 1:1
        or the group prefix by scope kind.
    """
    if isinstance(scope, MessageSig):
        prefix, scope_id = _MESSAGE_PREFIX, scope.recipient_agent_id
    else:
        prefix, scope_id = _GROUP_PREFIX, scope.group_id
    scope_bytes = canonical_uuid(scope_id, "signature scope id").encode()
    return prefix + _SEP + scope_bytes + _SEP + payload


def sign_message(private_key: bytes, scope: SigScope, payload: bytes) -> bytes:
    """Sign a payload for a scope with Ed25519.

    Args:
        private_key: 32-byte Ed25519 private seed.
        scope: The recipient agent or group the signature is addressed to.
        payload: Raw plaintext bytes to sign.

    Returns:
        64-byte Ed25519 signature.
    """
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(signing_input(scope, payload))


def verify_message_signature(
    public_key: bytes, scope: SigScope, payload: bytes, signature: bytes
) -> bool:
    """Verify a message signature for a scope, strictly.

    Never raises on verification failure — returns ``False`` instead.

    Args:
        public_key: 32-byte Ed25519 public key.
        scope: The recipient agent or group the message is addressed to.
        payload: The original signed plaintext.
        signature: 64-byte signature to verify.

    Returns:
        ``True`` if the signature is valid for this scope, ``False`` otherwise.
    """
    return verify_ed25519_strict(public_key, signing_input(scope, payload), signature)
