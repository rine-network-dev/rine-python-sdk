"""Sealing a take's exports into the pending store, and zeroing what was sealed.

Part of the drain (:mod:`rine._mls.escrow_drain`). The native group hands out each
export's plaintext as one ``bytearray``, the only copy of the epoch's secrets
outside the group's own state, so it is sealed in place and overwritten with zeros
once the drain is done with it, on every path out.

The TypeScript twin is ``sealTaken`` in ``rine-core/src/mls-escrow-drain.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from rine._crypto.escrow import EscrowSlot, EscrowUploader, seal_escrow
from rine._mls.escrow_store import PendingEscrow, list_pending, write_pending

if TYPE_CHECKING:
    from collections.abc import Sequence

    from rine._crypto.escrow_key import VerifiedEscrowKey
    from rine._crypto.keys import AgentKeys
    from rine._mls.heartbeat import MlsActor


class EscrowExportLike(Protocol):
    """The native group's per-epoch escrow export, structurally."""

    @property
    def epoch(self) -> int: ...
    @property
    def fp(self) -> bytes: ...
    @property
    def plaintext(self) -> bytearray: ...


def zero(buffer: bytearray) -> None:
    """Overwrite a secret in place; the native side hands out the same object on every read."""
    buffer[:] = bytes(len(buffer))


def seal_taken(
    actor: MlsActor,
    group_id: str,
    key: VerifiedEscrowKey,
    keys: AgentKeys,
    taken: Sequence[EscrowExportLike],
) -> int:
    """Seal each taken export into the pending store, then zero every plaintext; returns new files.

    Sealing is randomised, so a second file for one slot would be a different
    row and the server answers 409 to it: the first sealing of a slot wins. If
    sealing or a write fails, the exports not yet reached are zeroed too: the
    caller does not save, so the next load yields them again.
    """
    held = {(p.epoch, p.fp) for p in list_pending(actor.config_dir, actor.agent_id, group_id)}
    uploader = EscrowUploader(actor.agent_id, keys.key_gen)
    sealed = 0
    try:
        for export in taken:
            if (export.epoch, export.fp) in held:
                continue
            slot = EscrowSlot(group_id, export.epoch, export.fp)
            write_pending(
                actor.config_dir,
                actor.agent_id,
                PendingEscrow(
                    group_id,
                    export.epoch,
                    export.fp,
                    seal_escrow(key, slot, uploader, export.plaintext),
                ),
            )
            sealed += 1
    finally:
        for export in taken:
            zero(export.plaintext)
    return sealed
