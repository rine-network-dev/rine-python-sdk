"""Wallet key format + address/signature interoperability with rine-core.

The reference vectors (address, EIP-712 digest, 65-byte signature) were produced
by the rine-core noble wallet for private key ``0x00..01`` and the fixed EURC/Base
domain + authorization below. A byte-for-byte match proves the Python wallet writes
and reads the same ``wallet.key`` file and signs identically to the TypeScript SDK.
"""

from __future__ import annotations

import stat
from uuid import uuid4

from rine._crypto.wallet import (
    create_wallet,
    derive_evm_address,
    get_wallet_address,
    load_wallet_key,
    save_wallet_key,
    sign_digest,
    wallet_key_exists,
)
from rine._utils import from_base64url, to_base64url
from rine.x402.eip3009 import Eip712Domain, eip3009_digest

# priv = 0x00..01 → the canonical secp256k1 generator vector.
KNOWN_PRIV = bytes(31) + b"\x01"
KNOWN_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
KNOWN_DIGEST = "0x9adf1c3407f4f4c384542c0f22766ef8361322897829524144bbf5e2bbbe9a9a"
KNOWN_SIG = (
    "0x318c0d10fbfdcb8c3c7fd273a9cff3800331ceffad9eb1fff844d51a9efbe7ab"
    "724f6bff022fcda93ac6b120b3bdf2ccb5ad3ade4df67e5977e239cd46a7947d1c"
)

_DOMAIN = Eip712Domain(
    name="EURC",
    version="2",
    chain_id=8453,
    verifying_contract="0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
)
_AUTH = {
    "from": KNOWN_ADDRESS,
    "to": "0x808456652fdb597867f38412077a9182bf77359f",
    "value": "100000",
    "validAfter": "1740672089",
    "validBefore": "1740672154",
    "nonce": "0x" + "ab" * 32,
}


def test_derive_address_when_known_key_matches_core_vector() -> None:
    """Derive address when known key matches core vector."""
    assert derive_evm_address(KNOWN_PRIV) == KNOWN_ADDRESS


def test_eip3009_digest_when_fixed_domain_matches_core_vector() -> None:
    """Eip3009 digest when fixed domain matches core vector."""
    assert "0x" + eip3009_digest(_DOMAIN, _AUTH).hex() == KNOWN_DIGEST


def test_sign_digest_when_known_key_matches_core_signature() -> None:
    """Sign digest when known key matches core signature."""
    digest = eip3009_digest(_DOMAIN, _AUTH)
    assert sign_digest(KNOWN_PRIV, digest) == KNOWN_SIG


def test_load_wallet_key_when_core_written_file_reads_same_bytes(tmp_path) -> None:
    """Load wallet key when core written file reads same bytes."""
    # A wallet.key written the way rine-core writes it (base64url of 32 bytes).
    agent_id = str(uuid4())
    kdir = tmp_path / "keys" / agent_id
    kdir.mkdir(parents=True)
    (kdir / "wallet.key").write_text(to_base64url(KNOWN_PRIV))
    assert load_wallet_key(str(tmp_path), agent_id) == KNOWN_PRIV
    assert get_wallet_address(str(tmp_path), agent_id) == KNOWN_ADDRESS


def test_save_wallet_key_when_written_uses_interoperable_base64url(tmp_path) -> None:
    """Save wallet key when written uses interoperable base64url."""
    agent_id = str(uuid4())
    save_wallet_key(str(tmp_path), agent_id, KNOWN_PRIV)
    raw = (tmp_path / "keys" / agent_id / "wallet.key").read_text()
    assert from_base64url(raw.strip()) == KNOWN_PRIV


def test_save_wallet_key_when_written_has_0600_perms(tmp_path) -> None:
    """Save wallet key when written has 0600 perms."""
    agent_id = str(uuid4())
    save_wallet_key(str(tmp_path), agent_id, KNOWN_PRIV)
    mode = (tmp_path / "keys" / agent_id / "wallet.key").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_create_wallet_when_key_exists_refuses_to_clobber(tmp_path) -> None:
    """Create wallet when key exists refuses to clobber."""
    import pytest

    from rine.errors import CryptoError

    agent_id = str(uuid4())
    addr = create_wallet(str(tmp_path), agent_id)
    assert addr.startswith("0x") and wallet_key_exists(str(tmp_path), agent_id)
    with pytest.raises(CryptoError):
        create_wallet(str(tmp_path), agent_id)
