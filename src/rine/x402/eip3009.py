"""EIP-712 typed-data hashing for EIP-3009 ``transferWithAuthorization``.

Python mirror of ``rine-core/src/x402/eip3009.ts``. Produces a byte-identical
32-byte digest, verified against the rine-core noble implementation (see
``tests/test_x402/test_eip3009.py``), so a payload signed here is indistinguishable
from one signed by the TypeScript wallet.

``keccak`` comes from ``eth_utils`` (the Ethereum keccak-256, NOT NIST SHA3-256).
It is imported lazily so the base SDK does not require the ``payments`` extra.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine.x402.types import Eip3009Authorization

_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
_TRANSFER_TYPE = (
    "TransferWithAuthorization(address from,address to,uint256 value,"
    "uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)


def _keccak() -> Callable[[bytes], bytes]:
    """Return ``eth_utils.keccak``, raising a friendly error if unavailable."""
    try:
        from eth_utils import keccak  # type: ignore[attr-defined]
    except ImportError as exc:  # pragma: no cover - exercised via import guard
        raise ImportError(
            "x402 payments require the 'payments' extra: pip install rine[payments]"
        ) from exc
    return keccak


@dataclass(frozen=True)
class Eip712Domain:
    """The token's EIP-712 domain (name, version, chain id, verifying contract)."""

    name: str
    version: str
    chain_id: int
    verifying_contract: str


def _word(b: bytes) -> bytes:
    """Left-pad bytes into a 32-byte ABI word."""
    return b.rjust(32, b"\x00")


def _encode_address(addr: str) -> bytes:
    raw = bytes.fromhex(addr[2:] if addr.lower().startswith("0x") else addr)
    if len(raw) != 20:
        raise ValueError(f"Invalid address for EIP-712 encoding: {addr}")
    return _word(raw)


def _encode_uint256(value: str | int) -> bytes:
    return int(value).to_bytes(32, "big")


def _encode_bytes32(hex_str: str) -> bytes:
    raw = bytes.fromhex(hex_str[2:] if hex_str.lower().startswith("0x") else hex_str)
    if len(raw) != 32:
        raise ValueError(f"Invalid bytes32 for EIP-712 encoding: {hex_str}")
    return raw


def domain_separator(domain: Eip712Domain) -> bytes:
    """The 32-byte EIP-712 domain separator."""
    keccak = _keccak()
    return keccak(
        keccak(_DOMAIN_TYPE.encode())
        + keccak(domain.name.encode())
        + keccak(domain.version.encode())
        + _encode_uint256(domain.chain_id)
        + _encode_address(domain.verifying_contract)
    )


def hash_transfer_with_authorization(auth: Eip3009Authorization) -> bytes:
    """The 32-byte struct hash of a ``TransferWithAuthorization``."""
    keccak = _keccak()
    return keccak(
        keccak(_TRANSFER_TYPE.encode())
        + _encode_address(str(auth["from"]))
        + _encode_address(str(auth["to"]))
        + _encode_uint256(auth["value"])
        + _encode_uint256(auth["validAfter"])
        + _encode_uint256(auth["validBefore"])
        + _encode_bytes32(str(auth["nonce"]))
    )


def eip3009_digest(domain: Eip712Domain, auth: Eip3009Authorization) -> bytes:
    """The 32-byte EIP-712 digest to sign: keccak(0x1901 || domainSep || struct)."""
    keccak = _keccak()
    return keccak(b"\x19\x01" + domain_separator(domain) + hash_transfer_with_authorization(auth))
