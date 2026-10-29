"""The refusal an agent meets when it publishes key packages from a stale device.

A device that holds an earlier key generation than the agent's current one would put a
package in the pool that no Welcome could ever be opened with. The server refuses it with a
coded 422, and the drain that replaces the whole pool checks the same fact before it claims
anything, so a refused upload can never leave the agent with an empty pool. Both surface as
this one typed error, matched by its code and not by its sentence.

The TypeScript twin is ``MlsKeyNotCurrentError`` in ``rine-core/src/crypto/mls-key-not-current.ts``.
"""

from __future__ import annotations

from rine.errors import MlsError

#: The code the server's refusal carries, shared byte-for-byte with ``rine-core``'s
#: ``MLS_ERR_KEY_NOT_CURRENT``. A value to branch on, never a message to parse.
MLS_ERR_KEY_NOT_CURRENT = "mls_key_not_current"

#: The one sentence every surface shows for it.
KEY_NOT_CURRENT_MESSAGE = (
    "Key packages were not published: this device holds an earlier key generation "
    "than the agent's current one."
)


class MlsKeyNotCurrentError(MlsError):
    """Key packages were refused, or never minted, because this device's key is not current."""

    def __init__(self) -> None:
        """Build the refusal; it carries no state beyond its code and sentence."""
        super().__init__(MLS_ERR_KEY_NOT_CURRENT, KEY_NOT_CURRENT_MESSAGE)


def is_mls_key_not_current(err: BaseException) -> bool:
    """True for :class:`MlsKeyNotCurrentError`, matched on its code."""
    return getattr(err, "code", None) == MLS_ERR_KEY_NOT_CURRENT


__all__ = [
    "KEY_NOT_CURRENT_MESSAGE",
    "MLS_ERR_KEY_NOT_CURRENT",
    "MlsKeyNotCurrentError",
    "is_mls_key_not_current",
]
