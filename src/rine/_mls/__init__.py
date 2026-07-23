"""rine's MLS group encryption, over the ``rine-mls`` core.

``binding`` is the only module in the SDK that touches the compiled wheel; the
rest of this package (and the rest of the SDK) goes through the names re-exported
here. New groups run the post-quantum X-Wing ciphersuite by default.
"""

from rine._mls.api import (
    MlsCommit,
    MlsGroupInfo,
    MlsMemberStatus,
    MlsWelcome,
    MlsWelcomeDelivery,
    claim_key_package,
    claim_key_packages,
    fetch_group_info,
    fetch_welcomes,
    mls_commit,
    mls_init,
    read_group,
    upload_key_packages,
)
from rine._mls.binding import (
    APP_MESSAGE_TAG,
    CLASSICAL_CIPHER_SUITE,
    DEFAULT_CIPHER_SUITE,
    EPOCH_RETENTION_ENV,
    KEY_PACKAGE_LOW_WATER,
    KEY_PACKAGE_MAX_BATCH,
    KEY_PACKAGE_TARGET,
    MlsCoreError,
    epoch_retention_limit,
    open_mls_client,
)
from rine._mls.external_join import ExternalJoin, external_join_mls_group
from rine._mls.failures import is_recoverable_mls_failure, is_unprocessable_commit
from rine._mls.group_access import load_mls_group, mls_group_id_bytes, open_mls_group
from rine._mls.group_init import MlsInitOutcome, init_mls_group
from rine._mls.join import (
    install_mls_state,
    install_mls_state_by_id,
    join_mls_state,
    join_mls_state_async,
)
from rine._mls.key_packages import (
    MlsCutoverResult,
    MlsKeyPackageStatus,
    drain_and_republish_mls_key_packages,
    ensure_mls_key_packages,
    publish_mls_key_packages,
    replenish_mls_key_packages,
)
from rine._mls.messages import decrypt_mls_group_message, encrypt_mls_group_message
from rine._mls.sync import MlsSyncResult, sync_mls_group
from rine._mls.sync_api import MlsHandshake, fetch_handshakes, mls_ack, mls_nack
from rine._mls.welcomes import MlsWelcomeOutcome, process_mls_welcomes
from rine._mls.wire import api_error_code, mls_from_base64, mls_to_base64

__all__ = [
    "APP_MESSAGE_TAG",
    "CLASSICAL_CIPHER_SUITE",
    "DEFAULT_CIPHER_SUITE",
    "EPOCH_RETENTION_ENV",
    "KEY_PACKAGE_LOW_WATER",
    "KEY_PACKAGE_MAX_BATCH",
    "KEY_PACKAGE_TARGET",
    "ExternalJoin",
    "MlsCommit",
    "MlsCoreError",
    "MlsCutoverResult",
    "MlsGroupInfo",
    "MlsHandshake",
    "MlsInitOutcome",
    "MlsKeyPackageStatus",
    "MlsMemberStatus",
    "MlsSyncResult",
    "MlsWelcome",
    "MlsWelcomeDelivery",
    "MlsWelcomeOutcome",
    "api_error_code",
    "claim_key_package",
    "claim_key_packages",
    "decrypt_mls_group_message",
    "drain_and_republish_mls_key_packages",
    "encrypt_mls_group_message",
    "ensure_mls_key_packages",
    "epoch_retention_limit",
    "external_join_mls_group",
    "fetch_group_info",
    "fetch_handshakes",
    "fetch_welcomes",
    "init_mls_group",
    "install_mls_state",
    "install_mls_state_by_id",
    "is_recoverable_mls_failure",
    "is_unprocessable_commit",
    "join_mls_state",
    "join_mls_state_async",
    "load_mls_group",
    "mls_ack",
    "mls_commit",
    "mls_from_base64",
    "mls_group_id_bytes",
    "mls_init",
    "mls_nack",
    "mls_to_base64",
    "open_mls_client",
    "open_mls_group",
    "process_mls_welcomes",
    "publish_mls_key_packages",
    "read_group",
    "replenish_mls_key_packages",
    "sync_mls_group",
    "upload_key_packages",
]
