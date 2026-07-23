"""Crypto layer — re-exports for internal use."""

from rine._crypto.dm_envelope import RecipientKeys
from rine._crypto.envelope import InnerEnvelope, decode_envelope, encode_envelope
from rine._crypto.hpke import open as hpke_open
from rine._crypto.hpke import seal as hpke_seal
from rine._crypto.keys import (
    AgentKeys,
    KeyPair,
    agent_id_from_kid,
    agent_keys_exist,
    encryption_public_key_to_jwk,
    generate_agent_keys,
    generate_encryption_keypair,
    generate_signing_keypair,
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
    fetch_recipient_keys_async,
    fetch_recipient_keys_sync,
    get_agent_public_keys,
)
from rine._crypto.pq_keys import (
    generate_pq_keypair,
    jwk_to_pq_public_key,
    pq_public_key_to_jwk,
)
from rine._crypto.sender_keys import (
    SenderKeyState,
    derive_message_key,
    generate_sender_key,
    needs_rotation,
    open_group,
    seal_group,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._crypto.sign import sign_payload, verify_signature

__all__ = [
    "AgentKeys",
    "DecryptResult",
    "EncryptResult",
    "InnerEnvelope",
    "KeyPair",
    "RecipientKeys",
    "SenderKeyState",
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
    "generate_agent_keys",
    "generate_encryption_keypair",
    "generate_pq_keypair",
    "generate_sender_key",
    "generate_signing_keypair",
    "get_agent_public_keys",
    "hpke_open",
    "hpke_seal",
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
    "sign_payload",
    "signing_public_key_to_jwk",
    "verify_signature",
]
