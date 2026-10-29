"""The upload half of the MLS read-escrow drain: send pending files, settle each by the answer.

A file is uploaded oldest epoch first, per group. The signature is computed
HERE, not at seal time: the server answers 422 when ``key_gen`` is not the
uploader's current generation, so a file sealed before a rotation must be signed
under the current key. A :class:`RineApiError` is the server's answer about one
file, so the next file is still tried; any other error is the network and stops
the loop. The server answers 409 ``escrow_slot_taken`` when the slot already
holds this agent's own row, which is all the send gate asks for, so that file is
done. A terminal code (escrow_no_seat, group_not_found, branch_revoked,
agent_revoked, escrow_fork_limit) never changes, so the file is given up on; so does a 401
naming a revoked agent or branch, which carries no escrow code. Any other
refusal, a bare 403 or 404 included, is retried on an exponential schedule and given up
on after 16 attempts. Giving up files a gap marker for the epoch
(:func:`rine._mls.escrow_gap.give_up_pending`) and then deletes the file. A 429 or a 5xx
says nothing about this file and everything about the server, so it ends the loop like
a network failure and the remaining files wait.

The TypeScript twin is ``uploadPending`` in ``rine-core/src/mls-escrow-upload.ts``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._crypto.escrow import EscrowSlot, EscrowUploader, sign_escrow
from rine._logging import logger
from rine._mls.escrow_answer import Answer, EscrowCode, classify_refusal, escrow_code
from rine._mls.escrow_api import EscrowUploadBody, upload_escrow
from rine._mls.escrow_gap import DrainGap, EscrowLoss, LocatedGap, clear_gap, give_up_pending
from rine._mls.escrow_keys import drop_cached_escrow_key
from rine._mls.escrow_retry import is_due, is_exhausted, note_failure, read_attempts
from rine._mls.escrow_revoked import names_other_principal, revoked_loss
from rine._mls.escrow_store import PendingEscrow, delete_pending, pending_path
from rine._utils import to_base64url
from rine.errors import RineApiError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._crypto.escrow_key import VerifiedEscrowKey
    from rine._crypto.keys import AgentKeys
    from rine._mls.heartbeat import MlsActor

#: Logged when a pending escrow is given up on (it will not be retried).
REFUSED_LOG = "MLS escrow for group %s epoch %d given up (%s); epoch recorded as lost"


@dataclass(frozen=True, slots=True)
class Upload:
    """What uploading a set of pending files did."""

    uploaded: int
    """Files the server now holds, uploaded or already stored, and deleted."""

    failures: tuple[Exception, ...]
    """Failures. A file the server may yet accept stays for the next upload; one it
    refused for good is deleted and listed here once."""

    located: tuple[LocatedGap, ...] = ()
    """Epochs given up on this call, each already filed as a marker, with its group."""

    @property
    def gaps(self) -> tuple[DrainGap, ...]:
        """The epochs given up on, without their groups."""
        return tuple(located.gap for located in self.located)


def _last_answer(exc: RineApiError, code: EscrowCode | None) -> str:
    """The sidecar's ``last`` string: the status, plus the code when one is known."""
    return f"{exc.status} {code.value}" if code is not None else str(exc.status)


def _give_up(
    actor: MlsActor, pending: PendingEscrow, loss: EscrowLoss, failures: list[Exception]
) -> tuple[LocatedGap, ...]:
    """File the loss of one pending escrow and delete it; no gap when the marker failed.

    A marker that cannot be made durable keeps the file, so the next pass tries again,
    and the failure is listed for the caller.
    """
    try:
        gap = give_up_pending(actor.config_dir, actor.agent_id, pending, loss)
    except Exception as exc:
        failures.append(exc)
        logger.warning(
            "MLS escrow gap marker for group %s epoch %d not written",
            pending.group_id,
            pending.epoch,
            exc_info=True,
        )
        return ()
    logger.warning(REFUSED_LOG, pending.group_id, pending.epoch, loss.value)
    return (LocatedGap(pending.group_id, gap),)


def _stored(actor: MlsActor, pending: PendingEscrow) -> None:
    """The server holds this fork's escrow: drop the file, and any marker that said it was lost."""
    delete_pending(actor.config_dir, actor.agent_id, pending)
    clear_gap(actor.config_dir, actor.agent_id, pending.group_id, pending.epoch, pending.fp)


def resolve_refusal(
    actor: MlsActor,
    pending: PendingEscrow,
    exc: RineApiError,
    now: float,
    failures: list[Exception],
) -> tuple[Answer, tuple[LocatedGap, ...]]:
    """Settle one pending file by the server's refusal of it.

    A slot the server already holds is done and the file goes. A terminal refusal
    gives the file up. Any other refusal is one more failure on its schedule, and the
    sixteenth gives it up. A 429 or a 5xx touches nothing: it says nothing about this
    file. A revoked-branch answer drops the cached escrow key. A marker that cannot be
    written is added to ``failures``. A revocation of a principal other than the uploading
    agent says nothing about this file, so it backs the pass off and keeps the file.

    Returns:
        What the refusal meant, and the gap filed when the file was given up.
    """
    if names_other_principal(actor, exc):
        return Answer.BACKOFF, ()
    answer = classify_refusal(exc)
    code = escrow_code(exc)
    revoked = revoked_loss(exc)
    if revoked is EscrowLoss.BRANCH_REVOKED:
        drop_cached_escrow_key(actor)
    if answer is Answer.STORED:
        _stored(actor, pending)
        return answer, ()
    path = pending_path(actor.config_dir, actor.agent_id, pending)
    retries_used = answer is Answer.RETRY and is_exhausted(
        note_failure(path, _last_answer(exc, code), now=now)
    )
    if answer is not Answer.REFUSED and not retries_used:
        return answer, ()
    return answer, _give_up(actor, pending, revoked or EscrowLoss.REFUSED, failures)


def give_up_files(actor: MlsActor, files: Iterable[PendingEscrow], loss: EscrowLoss) -> Upload:
    """Give up on every file in ``files`` because the server will never take them.

    Used when the branch is revoked: the escrow key cannot be read, so no upload can
    even be tried. Each file's epoch is filed as lost before the file is deleted.
    """
    failures: list[Exception] = []
    located = tuple(gap for p in files for gap in _give_up(actor, p, loss, failures))
    return Upload(0, tuple(failures), located)


def upload_files(
    actor: MlsActor,
    files: Iterable[PendingEscrow],
    key: VerifiedEscrowKey,
    keys: AgentKeys,
    *,
    due_only: bool = False,
    now: float | None = None,
) -> Upload:
    """Upload ``files`` in the order given, deleting each one the server holds."""
    if now is None:
        now = time.time()
    uploader = EscrowUploader(actor.agent_id, keys.key_gen)
    uploaded = 0
    failures: list[Exception] = []
    located: list[LocatedGap] = []
    for p in files:
        record = read_attempts(pending_path(actor.config_dir, actor.agent_id, p))
        if is_exhausted(record):
            located.extend(_give_up(actor, p, EscrowLoss.REFUSED, failures))
            continue
        if due_only and not is_due(record, now):
            continue
        slot = EscrowSlot(p.group_id, p.epoch, p.fp)
        body: EscrowUploadBody = {
            "fp": to_base64url(p.fp),
            "sealed": to_base64url(p.sealed),
            "key_gen": keys.key_gen,
            "sig": to_base64url(
                sign_escrow(key, slot, uploader, keys.signing.private_key, p.sealed)
            ),
        }
        try:
            upload_escrow(actor.client, actor.agent_id, p.group_id, p.epoch, body)
        except RineApiError as exc:
            answer, filed = resolve_refusal(actor, p, exc, now, failures)
            located.extend(filed)
            if answer is Answer.STORED:
                uploaded += 1
                continue
            failures.append(exc)
            if answer is Answer.BACKOFF:
                break
            continue
        except Exception as exc:
            failures.append(exc)
            break
        _stored(actor, p)
        uploaded += 1
    return Upload(uploaded, tuple(failures), tuple(located))
