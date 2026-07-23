"""The single place the SDK touches the ``rine-mls`` wheel's MLS surface.

Every other module imports MLS types, constants and clients from here (or from
``rine._mls``), never from ``rine_mls`` directly, so a change in the wheel's
shape lands in one file. The wheel's other surface — the raw ML-KEM-768
primitives the 1:1 ``hpke-hybrid-v1`` DM envelope uses — is owned the same way
by ``rine._crypto._mlkem``, kept separate because importing this package pulls
in the whole group stack and the DM path must not.

The wheel is the same Rust core the TypeScript stack binds through napi, which
is what keeps the two stacks on one implementation of the ciphersuite, the
KeyPackage policy and the self-read cache rather than on two that drift.
"""

from __future__ import annotations

import os

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

#: The RFC-mandatory classical suite, kept for groups that were created on it.
CLASSICAL_CIPHER_SUITE: int = rine_mls.CIPHER_SUITE_CLASSICAL

#: Leading byte of an ``mls-v1`` ``encrypted_payload``.
APP_MESSAGE_TAG: int = rine_mls.APP_MESSAGE_TAG

#: KeyPackage pool policy, owned by the core and shared with the TS stack.
KEY_PACKAGE_TARGET: int = rine_mls.KEY_PACKAGE_TARGET
KEY_PACKAGE_LOW_WATER: int = rine_mls.KEY_PACKAGE_LOW_WATER
KEY_PACKAGE_MAX_BATCH: int = rine_mls.KEY_PACKAGE_MAX_BATCH

#: Core types, re-exported so no other module has to import the wheel.
MlsClient = rine_mls.MlsClient
MlsGroup = rine_mls.MlsGroup
CommitBundle = rine_mls.CommitBundle
AppMessage = rine_mls.AppMessage

#: Base class for every failure raised by the MLS core. Re-exported so callers
#: can catch MLS failures without importing the wheel.
MlsCoreError = rine_mls.RineMlsError
UnreadableKeyPackageError = rine_mls.UnreadableKeyPackageError
KeyPackageBatchTooLargeError = rine_mls.KeyPackageBatchTooLargeError
CipherSuiteMismatchError = rine_mls.CipherSuiteMismatchError
MlsProtocolError = rine_mls.MlsProtocolError
MlsStoreError = rine_mls.MlsStoreError
MlsPanicError = rine_mls.MlsPanicError
MlsPoisonedError = rine_mls.MlsPoisonedError
GroupInactiveError = rine_mls.GroupInactiveError
SelfMessageNotCachedError = rine_mls.SelfMessageNotCachedError

#: Environment knob for epoch retention. Unset (the default) retains the
#: full backlog, so an agent returning after many commits can still decrypt
#: everything the undelivered queue held for it. Set it to a positive integer to
#: keep only that many epochs — a narrower forward-secrecy window bought by
#: giving up backlog reach.
EPOCH_RETENTION_ENV = "RINE_MLS_EPOCH_RETENTION"


def epoch_retention_limit() -> int | None:
    """Read the configured epoch-retention limit.

    Returns:
        The number of epochs to retain, or ``None`` for the full backlog.

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
            f"got {raw!r}. Leave it unset to retain the full backlog."
        ) from None
    if limit < 1:
        raise ConfigError(
            f"{EPOCH_RETENTION_ENV} must be at least 1; {limit} would make every "
            "message after the next commit undecryptable."
        )
    return limit


def open_mls_client(
    config_dir: str,
    agent_id: str,
    *,
    cipher_suite: int | None = None,
) -> MlsClient:
    """Open this agent's MLS client over its own on-disk store.

    The MLS identity is the agent's existing Ed25519 signing key — the same key
    that signs rine envelopes — so an MLS leaf and a rine sender are provably the
    same agent.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        cipher_suite: Suite to operate under. Defaults to the core's default
            (post-quantum); pass a group's own ``mls_cipher_suite`` when working
            with a group created on another suite.

    Returns:
        An ``MlsClient`` rooted at ``keys/{agent_id}/mls2/``.

    Raises:
        CryptoError: If the agent's signing key is missing or corrupt.
    """
    from rine._config import mls_store_dir
    from rine._crypto.keys import load_agent_keys

    keys = load_agent_keys(config_dir, agent_id)
    return rine_mls.MlsClient(
        mls_store_dir(config_dir, agent_id),
        keys.signing.private_key,
        DEFAULT_CIPHER_SUITE if cipher_suite is None else cipher_suite,
        epoch_retention_limit=epoch_retention_limit(),
    )


__all__ = [
    "APP_MESSAGE_TAG",
    "CLASSICAL_CIPHER_SUITE",
    "DEFAULT_CIPHER_SUITE",
    "EPOCH_RETENTION_ENV",
    "KEY_PACKAGE_LOW_WATER",
    "KEY_PACKAGE_MAX_BATCH",
    "KEY_PACKAGE_TARGET",
    "AppMessage",
    "CipherSuiteMismatchError",
    "CommitBundle",
    "GroupInactiveError",
    "KeyPackageBatchTooLargeError",
    "MlsClient",
    "MlsCoreError",
    "MlsGroup",
    "MlsPanicError",
    "MlsPoisonedError",
    "MlsProtocolError",
    "MlsStoreError",
    "SelfMessageNotCachedError",
    "UnreadableKeyPackageError",
    "epoch_retention_limit",
    "open_mls_client",
]
