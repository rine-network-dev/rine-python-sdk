"""secp256k1 payment wallet — a 4th agent key type (REQ-W01).

The private key is stored base64url-encoded (32 raw bytes) at
``keys/{agent_id}/wallet.key`` with 0o600 perms, in the same directory and with
the same atomic-write helpers as the signing/encryption keys. The on-disk format
is byte-identical to ``rine-core``'s wallet, so a key created by either SDK is
readable by the other (verified in ``tests/test_x402/test_wallet_interop.py``).

Address derivation and signing use ``eth_account`` (imported lazily so the base
SDK does not require the ``payments`` extra). The derived EVM address and the
65-byte ``r||s||v`` signature match the rine-core noble implementation exactly.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from rine._config import _ensure_dir, _write_atomic, keys_dir
from rine._crypto.keys import _validate_path_id
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

if TYPE_CHECKING:
    from eth_account import Account as _Account
    from eth_account.signers.local import LocalAccount

_SECP256K1_PRIVATE_KEY_SIZE = 32


def _import_account() -> type[_Account]:
    """Return ``eth_account.Account``, raising a friendly error if unavailable."""
    try:
        from eth_account import Account
    except ImportError as exc:  # pragma: no cover - exercised via import guard
        raise CryptoError(
            "Payment wallets require the 'payments' extra: pip install rine[payments]"
        ) from exc
    return Account


def _wallet_key_path(config_dir: str, agent_id: str) -> str:
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(keys_dir(config_dir, agent_id), "wallet.key")


def generate_wallet_key() -> bytes:
    """Generate a fresh secp256k1 wallet private key (32 bytes)."""
    account = _import_account()
    return bytes(account.create().key)


def derive_evm_address(private_key: bytes) -> str:
    """Derive the EIP-55 checksummed EVM address for a wallet key."""
    account = _import_account()
    local: LocalAccount = account.from_key(private_key)
    return local.address


def save_wallet_key(config_dir: str, agent_id: str, private_key: bytes) -> None:
    """Persist the wallet key beside the agent's other keys (0o700/0o600)."""
    if len(private_key) != _SECP256K1_PRIVATE_KEY_SIZE:
        raise CryptoError(f"Invalid wallet key: expected 32 bytes, got {len(private_key)}")
    path = _wallet_key_path(config_dir, agent_id)
    _ensure_dir(os.path.dirname(path))
    _write_atomic(path, to_base64url(private_key))


def load_wallet_key(config_dir: str, agent_id: str) -> bytes:
    """Load the wallet private key from disk (32 raw bytes)."""
    path = _wallet_key_path(config_dir, agent_id)
    try:
        with open(path) as f:
            priv = from_base64url(f.read().strip())
    except FileNotFoundError:
        raise CryptoError(f"Wallet key not found: {path}. Create a wallet first.") from None
    except Exception as exc:
        raise CryptoError(f"Corrupt wallet key: {path}. {exc}") from exc
    if len(priv) != _SECP256K1_PRIVATE_KEY_SIZE:
        raise CryptoError(f"Corrupt wallet key: expected 32 bytes, got {len(priv)}")
    return priv


def wallet_key_exists(config_dir: str, agent_id: str) -> bool:
    """Whether a wallet key exists on disk for the agent."""
    return os.path.isfile(_wallet_key_path(config_dir, agent_id))


def get_wallet_address(config_dir: str, agent_id: str) -> str:
    """Derive the EVM address for the agent's stored wallet key."""
    return derive_evm_address(load_wallet_key(config_dir, agent_id))


def create_wallet(config_dir: str, agent_id: str) -> str:
    """Create a wallet for an agent, refusing to clobber an existing key.

    Returns:
        The derived EIP-55 checksummed EVM address.
    """
    if wallet_key_exists(config_dir, agent_id):
        raise CryptoError(f"Wallet already exists for agent {agent_id}")
    priv = generate_wallet_key()
    save_wallet_key(config_dir, agent_id, priv)
    return derive_evm_address(priv)


def sign_digest(private_key: bytes, digest: bytes) -> str:
    """Sign a 32-byte digest, returning a 0x 65-byte ``r||s||v`` signature.

    ``v = 27 + recovery``; the signature is canonical low-s — byte-identical to
    the rine-core noble signer for the same key and digest.
    """
    account = _import_account()
    signed = account.unsafe_sign_hash(digest, private_key)
    return "0x" + bytes(signed.signature).hex()
