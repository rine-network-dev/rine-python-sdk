"""The single place the SDK touches the ``rine-mls`` wheel's MLS surface.

Every other module imports MLS types, constants and clients from here (or from
``rine._mls``), never from ``rine_mls`` directly, so a change in the wheel's
shape lands in one file. The wheel's other surface — the raw ML-KEM-768
primitives the 1:1 ``hpke-hybrid-v2`` DM envelope uses — is owned the same way
by ``rine._crypto._mlkem``, kept separate because importing this package pulls
in the whole group stack and the DM path must not.

The wheel is the same Rust core the TypeScript stack binds through napi, which
is what keeps the two stacks on one implementation of the ciphersuite, the
KeyPackage policy and the self-read cache rather than on two that drift.
"""

from __future__ import annotations

import os
import threading

from rine._crypto.derive import UUID_RE, canonical_agent_label_id
from rine.errors import ConfigError, CryptoError

try:
    import rine_mls
except ImportError as exc:  # pragma: no cover - depends on the install platform
    raise CryptoError(
        "rine's group encryption needs the `rine-mls` wheel, which is not "
        "importable. Install `rine-mls` for this platform (linux x64/arm64 "
        "glibc+musl, macOS arm64/x64; Windows is not published yet)."
    ) from exc


#: The ciphersuite a NEW rine group is created with — post-quantum X-Wing at
#: private-use code point 0xF057. Read it; never restate the number, or the two
#: stacks eventually create groups of different suites.
DEFAULT_CIPHER_SUITE: int = rine_mls.CIPHER_SUITE_DEFAULT

#: Leading byte of an ``mls-v1`` ``encrypted_payload``.
APP_MESSAGE_TAG: int = rine_mls.APP_MESSAGE_TAG

#: KeyPackage pool policy, owned by the core and shared with the TS stack.
KEY_PACKAGE_TARGET: int = rine_mls.KEY_PACKAGE_TARGET
KEY_PACKAGE_LOW_WATER: int = rine_mls.KEY_PACKAGE_LOW_WATER
KEY_PACKAGE_MAX_BATCH: int = rine_mls.KEY_PACKAGE_MAX_BATCH

#: Core types, re-exported so no other module imports the wheel.
MlsClient = rine_mls.MlsClient
AllowedIdentities = rine_mls.AllowedIdentities
EpochReader = rine_mls.EpochReader
EscrowBacklog = rine_mls.EscrowBacklog
EscrowGapReason = rine_mls.EscrowGapReason
MlsGroup = rine_mls.MlsGroup
CommitBundle = rine_mls.CommitBundle
AppMessage = rine_mls.AppMessage

#: Base class for every failure raised by the MLS core. Re-exported so callers
#: can catch MLS failures without importing the wheel.
MlsCoreError = rine_mls.RineMlsError
EpochConflictError = rine_mls.EpochConflictError
UnreadableKeyPackageError = rine_mls.UnreadableKeyPackageError
KeyPackageBatchTooLargeError = rine_mls.KeyPackageBatchTooLargeError
CipherSuiteMismatchError = rine_mls.CipherSuiteMismatchError
MlsProtocolError = rine_mls.MlsProtocolError
PeerNotAdmittedError = rine_mls.PeerNotAdmittedError
UnexpectedBlobError = rine_mls.UnexpectedBlobError
MlsStoreError = rine_mls.MlsStoreError
MlsPanicError = rine_mls.MlsPanicError
MlsPoisonedError = rine_mls.MlsPoisonedError
GroupInactiveError = rine_mls.GroupInactiveError
SelfMessageNotCachedError = rine_mls.SelfMessageNotCachedError
NoSeatToReplaceError = rine_mls.NoSeatToReplaceError
LeafAlreadyCurrentError = rine_mls.LeafAlreadyCurrentError
SignerLeafMismatchError = rine_mls.SignerLeafMismatchError
ResyncChangesKeyError = rine_mls.ResyncChangesKeyError
CommitPendingError = rine_mls.CommitPendingError
AllowedGenerationConflictError = rine_mls.AllowedGenerationConflictError
key_package_signature_key = rine_mls.key_package_signature_key

#: Environment knob for epoch retention. Unset is rine's shipped window, which the
#: native core owns so both stacks agree; it covers 90 days at peak churn, a
#: client-side budget independent of the server's message retention. There is no
#: "keep everything" setting: a smaller integer keeps only that many epochs, giving
#: up backlog reach for good, because the epoch secret is the only copy.
EPOCH_RETENTION_ENV = "RINE_MLS_EPOCH_RETENTION"

#: One allowed set per ``(config_dir, agent_id)`` per process. The native core
#: holds the set **by reference**, so a client opened before a peer was admitted
#: must see the peer afterwards: every caller gets the SAME object.
_allowed_by_actor: dict[tuple[str, str], rine_mls.AllowedIdentities] = {}
_allowed_lock = threading.Lock()


def epoch_retention_limit() -> int | None:
    """Read the configured epoch-retention limit.

    Returns:
        The number of epochs to retain, or ``None`` for the shipped window.

    Raises:
        ConfigError: If the environment value is not a positive integer.
    """
    raw = os.environ.get(EPOCH_RETENTION_ENV, "").strip()
    if not raw:
        return None
    try:
        limit = int(raw)
    except ValueError:
        raise ConfigError(
            f"{EPOCH_RETENTION_ENV} must be a positive integer (epochs to retain), "
            f"got {raw!r}. Leave it unset for rine's shipped window."
        ) from None
    if limit < 1:
        raise ConfigError(
            f"{EPOCH_RETENTION_ENV} must be at least 1; {limit} would make every "
            "message after the next commit undecryptable."
        )
    return limit


def credential_identity(agent_id: str) -> bytes:
    """The MLS credential identity of an agent: the ASCII of its canonical id.

    The id is the lowercase hyphenated string every surface uses (36 bytes), so
    an identity read off a leaf maps back to an agent with no key lookup.

    Raises:
        CryptoError: If ``agent_id`` is not a canonical agent id.
    """
    return canonical_agent_label_id(agent_id).encode("ascii")


def local_allowed_identities(
    config_dir: str, allowed: rine_mls.AllowedIdentities | None = None
) -> rine_mls.AllowedIdentities:
    """The ``(agent id, leaf key)`` pairs of every agent whose keys live here.

    They are this device's own keys, so they need no chain check. A peer's pair
    does, and belongs in the set only after :func:`rine._crypto.certs.verify_agent_chain`
    accepted it; pass such a set to :func:`open_mls_client`.

    Args:
        config_dir: Config directory path.
        allowed: A set to add the pairs to. Defaults to a new, empty one.
    """
    from rine._crypto.keys import agent_keys_exist, load_agent_keys

    allowed = rine_mls.AllowedIdentities() if allowed is None else allowed
    root = os.path.join(config_dir, "keys")
    for agent_id in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        if UUID_RE.fullmatch(agent_id) and agent_keys_exist(config_dir, agent_id):
            keys = load_agent_keys(config_dir, agent_id)
            allowed.insert(credential_identity(agent_id), keys.mls.public_key, keys.key_gen)
    return allowed


def allowed_for(config_dir: str, agent_id: str) -> rine_mls.AllowedIdentities:
    """The shared allowed set of one acting agent, topped up with the local agents.

    Adding :func:`local_allowed_identities` on every call lets an agent open a
    client before any peer is known, and sees an agent created on this device
    after the set first existed: those pairs need no chain check.

    The same object is returned on every later call (see ``_allowed_by_actor``).

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        The process-wide allowed set for this ``(config_dir, agent_id)``.
    """
    key = (config_dir, canonical_agent_label_id(agent_id))
    with _allowed_lock:
        allowed = _allowed_by_actor.setdefault(key, rine_mls.AllowedIdentities())
        return local_allowed_identities(config_dir, allowed)


def open_mls_client(
    config_dir: str,
    agent_id: str,
    *,
    allowed: rine_mls.AllowedIdentities | None = None,
    store_dir: str | None = None,
) -> MlsClient:
    """Open this agent's MLS client over its own on-disk store.

    The credential identity is the ASCII of the canonical agent id and the leaf
    signature key is the agent's derived MLS key (``mls.key``), the one its
    org-signed certificate commits to. The core refuses any credential outside
    ``allowed``.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        allowed: The chain-verified ``(agent id, leaf key)`` pairs this client
            accepts. Defaults to :func:`allowed_for`, the shared set seeded from
            the agents whose keys live in ``config_dir``.
        store_dir: A store root other than the agent's own, for reading a
            snapshot that was set aside (:mod:`rine._mls.escrow_backlog`).

    Returns:
        An ``MlsClient`` rooted at ``keys/{agent_id}/mls2/`` (or ``store_dir``).

    Raises:
        CryptoError: If the agent's keys are missing or corrupt.
    """
    from rine._config import mls_store_dir
    from rine._crypto.keys import load_agent_keys

    keys = load_agent_keys(config_dir, agent_id)
    return rine_mls.MlsClient(
        store_dir or mls_store_dir(config_dir, agent_id),
        credential_identity(agent_id),
        keys.mls.private_key,
        allowed_for(config_dir, agent_id) if allowed is None else allowed,
        DEFAULT_CIPHER_SUITE,
        epoch_retention_limit=epoch_retention_limit(),
    )


__all__ = [
    "APP_MESSAGE_TAG",
    "DEFAULT_CIPHER_SUITE",
    "EPOCH_RETENTION_ENV",
    "KEY_PACKAGE_LOW_WATER",
    "KEY_PACKAGE_MAX_BATCH",
    "KEY_PACKAGE_TARGET",
    "AllowedGenerationConflictError",
    "AllowedIdentities",
    "AppMessage",
    "CipherSuiteMismatchError",
    "CommitBundle",
    "CommitPendingError",
    "EpochConflictError",
    "EpochReader",
    "EscrowBacklog",
    "EscrowGapReason",
    "GroupInactiveError",
    "KeyPackageBatchTooLargeError",
    "LeafAlreadyCurrentError",
    "MlsClient",
    "MlsCoreError",
    "MlsGroup",
    "MlsPanicError",
    "MlsPoisonedError",
    "MlsProtocolError",
    "MlsStoreError",
    "NoSeatToReplaceError",
    "PeerNotAdmittedError",
    "ResyncChangesKeyError",
    "SelfMessageNotCachedError",
    "SignerLeafMismatchError",
    "UnexpectedBlobError",
    "UnreadableKeyPackageError",
    "allowed_for",
    "credential_identity",
    "epoch_retention_limit",
    "key_package_signature_key",
    "local_allowed_identities",
    "open_mls_client",
]
