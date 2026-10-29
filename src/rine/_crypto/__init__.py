"""Crypto layer — re-exports for internal use."""

from rine._crypto._agent_keys import fetch_recipient_keys_async, fetch_recipient_keys_sync
from rine._crypto.certs import ChainError, VerifiedAgentKeys
from rine._crypto.envelope import InnerEnvelope, decode_envelope, encode_envelope
from rine._crypto.escrow_key import EscrowKeyError
from rine._crypto.keys import (
    AgentKeys,
    KeyPair,
    agent_id_from_kid,
    agent_keys_exist,
    encryption_public_key_to_jwk,
    jwk_to_public_key,
    load_agent_keys,
    make_kid,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.message import (
    DecryptResult,
    EncryptResult,
    decrypt_group_message_async,
    decrypt_group_message_sync,
    decrypt_message_async,
    decrypt_message_sync,
    encrypt_group_message,
    encrypt_message,
)
from rine._crypto.pq_keys import jwk_to_pq_public_key, pq_public_key_to_jwk
from rine._crypto.sender_keys import (
    SenderKeyState,
    derive_message_key,
    generate_sender_key,
    needs_rotation,
    open_group,
    seal_group,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._crypto.sign import GroupSig, MessageSig, sign_message, verify_message_signature

__all__ = [
    "AgentKeys",
    "ChainError",
    "DecryptResult",
    "EncryptResult",
    "EscrowKeyError",
    "GroupSig",
    "InnerEnvelope",
    "KeyPair",
    "MessageSig",
    "SenderKeyState",
    "VerifiedAgentKeys",
    "agent_id_from_kid",
    "agent_keys_exist",
    "decode_envelope",
    "decrypt_group_message_async",
    "decrypt_group_message_sync",
    "decrypt_message_async",
    "decrypt_message_sync",
    "derive_message_key",
    "encode_envelope",
    "encrypt_group_message",
    "encrypt_message",
    "encryption_public_key_to_jwk",
    "fetch_recipient_keys_async",
    "fetch_recipient_keys_sync",
    "generate_sender_key",
    "jwk_to_pq_public_key",
    "jwk_to_public_key",
    "load_agent_keys",
    "load_sender_key_states",
    "make_kid",
    "needs_rotation",
    "open_group",
    "pq_public_key_to_jwk",
    "save_agent_keys",
    "save_sender_key_state",
    "seal_group",
    "sign_message",
    "signing_public_key_to_jwk",
    "verify_message_signature",
]
