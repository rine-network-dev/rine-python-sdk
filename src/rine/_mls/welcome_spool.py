"""A Welcome's landing place between the server's one-shot fetch and the join.

``GET /agents/{id}/mls/welcomes`` marks every Welcome it returns consumed in the
same transaction that returns it, and there is no acknowledgement endpoint, so
the bytes in that response are the only copy: an agent that loses them can never
join the group they were minted for. The response is therefore written to disk
before it is used for anything, and an entry is removed only once the join it
carries has a final outcome — including a refusal a later attempt could clear
(:func:`rine._mls.welcome_guard.refusal_is_retryable`).

The server chooses both the names and the volume of what lands here, so two
things bound it: :func:`is_spoolable_id` decides what may become a file name,
and :meth:`WelcomeSpool.prune` decides how many entries and how old. The
residual window is the one no client can close: a crash between the server
committing ``consumed_at`` and this file landing loses the Welcome.

An entry therefore carries one bit of its own history — whether a pass has
already tried it and refused it (:meth:`WelcomeSpool.mark_refused`) — because
that is what separates the population the count bound exists to cap from a
Welcome that has not had its chance yet.

The TypeScript twin is ``rine-core/src/mls-welcome-spool.ts`` — same directory,
same file names, same JSON keys, same bounds, so one stack's spool is readable
by the other's.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._config import _write_atomic
from rine._crypto.keys import _validate_path_id
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.wire import mls_from_base64, mls_to_base64

if TYPE_CHECKING:
    from collections.abc import Callable

SPOOL_SUFFIX = ".json"

#: How long a retained Welcome keeps its place, and how many places there are.
#:
#: Retention is what makes a refusal non-terminal, and a ``roster_uncorroborated``
#: refusal for a genuinely substituted Welcome never clears — so unbounded
#: retention hands a hostile server a permanent, linearly growing tax on the
#: victim: every later pass re-joins and re-reads the roster for every entry
#: held. The count bound is therefore on the REFUSED entries alone — the exact
#: population that tax comes from — so no batch, however large, is evicted by its
#: own size: not this pass's arrivals, and not a batch a pass that aborted before
#: processing it carried over.
#:
#: 🔴 Running the count over every entry instead is silent data loss with no
#: adversary in it: MEASURED, 36 honest Welcomes for 36 real groups, one ordinary
#: local failure after spooling, then a healthy pass — 32 installed and **4
#: permanently lost**, where the same run with the count bound off held all 36. A
#: Welcome is the only copy of itself, so an entry no pass has tried yet must
#: never be evicted to make room.
#:
#: 🔴 What the bound still costs: an honest Welcome whose refusal has not cleared
#: in a week, or which is the oldest of more than a commit's worth of
#: simultaneously retained refusals, is dropped and can only be replaced by a
#: re-invitation — which is the remedy the refusal messages already name. Seven
#: days is the server's own invitation lifetime, after which the invitation that
#: would have corroborated the Welcome has expired anyway. The age bound applies
#: to every entry, refused or not: a Welcome nothing has managed to process in a
#: week is past the invitation that would justify it either way.
SPOOL_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
SPOOL_MAX_ENTRIES = 32

#: A plain file name: no separator, no traversal, no leading dot, nothing the
#: host filesystem reads as anything but a name. Deliberately wider than
#: ``_validate_path_id``'s UUID, and the difference is the point: the honest
#: server types this column as a UUID, but the id is not a rine identifier this
#: stack ever resolves, so the rule that matters is only "it can be a file name
#: here". Narrower than a UUID would refuse a delivery an honest server is free
#: to reformat; wider admits the traversal.
_SPOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def is_spoolable_id(delivery_id: str) -> bool:
    """Whether a server-chosen delivery id may be used as a spool file name.

    🔴 The id IS the file name and the server chooses it. Without this a
    delivery id of ``../../../../elsewhere/poison`` writes outside the spool dir
    — MEASURED, and on this stack ``_write_atomic`` creates the traversed
    directories on the way, so it does not even raise. Callers ask before
    storing so that one poisoned id costs its own Welcome and not the rest of
    the batch.
    """
    return bool(_SPOOL_ID_RE.match(delivery_id))


def welcome_spool_dir(config_dir: str, agent_id: str) -> str:
    """Where this agent's unprocessed Welcomes wait.

    Beside the MLS store rather than inside it: the store root belongs to the
    native core, which owns every byte under it. The id check matches the
    TypeScript twin's, which has always asserted it here.
    """
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(config_dir, "keys", agent_id, "mls_welcomes")


class WelcomeSpool:
    """The on-disk queue of Welcomes fetched but not yet joined."""

    def __init__(self, config_dir: str, agent_id: str) -> None:
        self._dir = welcome_spool_dir(config_dir, agent_id)

    def store(self, delivery: MlsWelcomeDelivery) -> None:
        """Persist one fetched Welcome. Storing the same delivery twice is a no-op.

        Raises:
            ValueError: The delivery id cannot be a file name, so this call
                would write outside the spool dir — see :func:`is_spoolable_id`.
        """
        if not is_spoolable_id(delivery.id):
            raise ValueError(
                f"Invalid welcome delivery ID: must be a plain file name, got {delivery.id!r}"
            )
        _write_atomic(
            os.path.join(self._dir, f"{delivery.id}{SPOOL_SUFFIX}"),
            _serialize(delivery, refused=False),
        )

    def mark_refused(self, path: str) -> None:
        """Record that a pass kept this Welcome without opening it.

        That is a refusal a later attempt could clear, or an invitation the agent
        has not accepted yet.

        What moves an entry into the population :meth:`prune`'s count bound
        holds. A no-op once the flag is set, so the entry is rewritten at most
        once and its mtime — which is both its place in the queue and its age —
        moves only on the pass that first refused it.
        """
        entry = _read(path)
        if entry is None or entry.refused:
            return
        _write_atomic(path, _serialize(entry.delivery, refused=True))

    def prune(self, release: Callable[[bytes], None]) -> int:
        """Drop the retained Welcomes past the bound, oldest first. Returns how many.

        Each one's private key package half goes through ``release`` first
        (:mod:`rine._mls.welcome_release`): it was never opened, so nothing else frees it.

        Call it BEFORE storing a fetch, so nothing it reaches is a Welcome this
        pass is about to process.

        🔴 The count bound reaches **refused entries only**. Spooling is not the
        same event as having had a chance: a pass that aborts after the fetch
        carries its whole batch forward, and a count over every entry then
        evicts honest, installable Welcomes to make room for nothing (MEASURED,
        4 of 36). The age bound reaches everything — a week is past the
        invitation that would corroborate any of it.
        """
        files = self._files()
        cutoff = time.time() - SPOOL_MAX_AGE_SECONDS
        refused = [path for path, _mtime in files if _is_refused(path)]
        overflow = max(0, len(refused) - SPOOL_MAX_ENTRIES)
        evicted = set(refused[:overflow])
        dropped = 0
        for path, mtime in files:
            if path not in evicted and mtime >= cutoff:
                continue
            self.drop(path, release)
            dropped += 1
        return dropped

    def pending(self) -> list[tuple[str, MlsWelcomeDelivery]]:
        """Every spooled Welcome, oldest first, with the path to discard it by.

        An entry that cannot be read back is dropped: it is a torn or hand-edited
        file, and there is no version of it left to process.
        """
        entries: list[tuple[str, MlsWelcomeDelivery]] = []
        for path, _mtime in self._files():
            entry = _read(path)
            if entry is None:
                self.discard(path)
            else:
                entries.append((path, entry.delivery))
        return entries

    def drop(self, path: str, release: Callable[[bytes], None]) -> None:
        """Drop a spooled Welcome that was never opened, releasing its key package half.

        An entry too torn to read has no Welcome to release and is only discarded.
        """
        entry = _read(path)
        if entry is not None:
            release(entry.delivery.welcome)
        self.discard(path)

    def discard(self, path: str) -> None:
        """Drop a spooled Welcome whose private half is already spent or unknowable."""
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    def _files(self) -> list[tuple[str, float]]:
        """Every spool file, oldest write first.

        Ordered by write time and not by name, because the name is the delivery
        id and the server chooses it: a name-ordered queue let the server decide
        which Welcome was processed — and which refusal was raised. Names break
        ties, so the order is total.
        """
        try:
            names = sorted(n for n in os.listdir(self._dir) if n.endswith(SPOOL_SUFFIX))
        except FileNotFoundError:
            return []
        files: list[tuple[str, float]] = []
        for name in names:
            path = os.path.join(self._dir, name)
            try:
                files.append((path, os.stat(path).st_mtime))
            except OSError:
                continue  # Gone between the listdir and the stat.
        files.sort(key=lambda entry: entry[1])
        return files


@dataclass(frozen=True)
class _SpoolEntry:
    """One spool file as it sits on disk: the Welcome, and what a pass made of it."""

    delivery: MlsWelcomeDelivery

    refused: bool
    """A pass has already tried this Welcome and refused it retryably.

    The one bit that separates the retained-refusal tax from a Welcome nothing
    has had a chance at. Absent from a file written before the flag existed, and
    the default is ``False`` on purpose: an entry the reader cannot classify is
    exempt from the count bound for exactly one pass and carries the flag from
    its next refusal on, so the bound re-establishes itself instead of dropping
    bytes nobody can re-mint.
    """


def _serialize(delivery: MlsWelcomeDelivery, *, refused: bool) -> str:
    """The one on-disk shape, written in one place so the two stacks cannot drift."""
    return json.dumps(
        {
            "id": delivery.id,
            "group_id": delivery.group_id,
            "welcome": mls_to_base64(delivery.welcome),
            "refused": refused,
        }
    )


def _is_refused(path: str) -> bool:
    entry = _read(path)
    return entry is not None and entry.refused


def _read(path: str) -> _SpoolEntry | None:
    try:
        with open(path) as f:
            entry = json.load(f)
        return _SpoolEntry(
            delivery=MlsWelcomeDelivery(
                id=str(entry["id"]),
                group_id=str(entry["group_id"]),
                welcome=mls_from_base64(entry["welcome"]),
            ),
            # A file the previous format wrote carries no ``refused`` key, and
            # reads as "not yet tried" rather than as unreadable: the bytes are
            # still the only copy of that Welcome.
            refused=entry.get("refused") is True,
        )
    except (OSError, ValueError, KeyError, AttributeError):
        return None
