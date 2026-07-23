"""A Welcome's landing place between the server's one-shot fetch and the join.

``GET /agents/{id}/mls/welcomes`` marks every Welcome it returns consumed in the
same transaction that returns it. There is no second read and no acknowledgement
endpoint, so the bytes in that response are the only copy: an agent that loses
them can never join the group they were minted for, and no peer can mint another
without noticing the first one went unused.

So the response is written to disk before it is used for anything, and an entry
is removed only once the join it carries has a final outcome. A crash between
the two leaves the Welcome on disk and the next attempt replays it.

The residual window is the one the server's design leaves open and no client can
close: a crash between the server committing ``consumed_at`` and this file
landing loses the Welcome. Closing it needs a server-side acknowledgement the
protocol does not have.
"""

from __future__ import annotations

import contextlib
import json
import os

from rine._config import _write_atomic
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.wire import mls_from_base64, mls_to_base64

SPOOL_SUFFIX = ".json"


def welcome_spool_dir(config_dir: str, agent_id: str) -> str:
    """Where this agent's unprocessed Welcomes wait.

    Beside the MLS store rather than inside it: the store root belongs to the
    native core, which owns every byte under it.
    """
    return os.path.join(config_dir, "keys", agent_id, "mls_welcomes")


class WelcomeSpool:
    """The on-disk queue of Welcomes fetched but not yet joined."""

    def __init__(self, config_dir: str, agent_id: str) -> None:
        self._dir = welcome_spool_dir(config_dir, agent_id)

    def store(self, delivery: MlsWelcomeDelivery) -> None:
        """Persist one fetched Welcome. Storing the same delivery twice is a no-op."""
        _write_atomic(
            os.path.join(self._dir, f"{delivery.id}{SPOOL_SUFFIX}"),
            json.dumps(
                {
                    "id": delivery.id,
                    "group_id": delivery.group_id,
                    "welcome": mls_to_base64(delivery.welcome),
                }
            ),
        )

    def pending(self) -> list[tuple[str, MlsWelcomeDelivery]]:
        """Every spooled Welcome, oldest server id first, with the path to discard it by.

        An entry that cannot be read back is dropped: it is a torn or hand-edited
        file, and there is no version of it left to process.
        """
        try:
            names = sorted(n for n in os.listdir(self._dir) if n.endswith(SPOOL_SUFFIX))
        except FileNotFoundError:
            return []
        entries: list[tuple[str, MlsWelcomeDelivery]] = []
        for name in names:
            path = os.path.join(self._dir, name)
            delivery = _read(path)
            if delivery is None:
                self.discard(path)
            else:
                entries.append((path, delivery))
        return entries

    def discard(self, path: str) -> None:
        """Drop a spooled Welcome whose join has a final outcome."""
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def _read(path: str) -> MlsWelcomeDelivery | None:
    try:
        with open(path) as f:
            entry = json.load(f)
        return MlsWelcomeDelivery(
            id=str(entry["id"]),
            group_id=str(entry["group_id"]),
            welcome=mls_from_base64(entry["welcome"]),
        )
    except (OSError, ValueError, KeyError):
        return None
