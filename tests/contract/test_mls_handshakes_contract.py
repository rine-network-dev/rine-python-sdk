"""SDK-side handshakes contract: replay the pending-commit goldens through the feed reader.

An agent holding its own key update asks the handshakes route where that commit stands and
applies, holds or drops its local state on the answer. The five standings are plain strings, so
a server that renamed one would read here as an unknown standing while every stubbed client
suite stayed green. The goldens are recorded from the real router (``tests/contract`` at the
repo root); the TypeScript core replays the same files.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.sync_api import MlsHandshakeFeed, OwnCommitStanding, fetch_handshake_feed
from rine._mls.wire import mls_from_base64
from tests.contract._loader import load

STANDINGS = ["tentative", "confirmed", "rolled_back", "superseded", "absent"]
SINCE, PENDING = 1, 2


class _Served:
    """A client whose one route answers the golden's body and remembers the query."""

    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body
        self.params: dict[str, int] = {}

    def get(self, _path: str, params: dict[str, int], **_kwargs: Any) -> dict[str, Any]:
        self.params = params
        return self.body


def _replay(standing: str) -> tuple[dict[str, Any], _Served, MlsHandshakeFeed]:
    body = load(f"mls_handshakes_200_pending_{standing}")["body"]
    client = _Served(body)
    feed = fetch_handshake_feed(client, "g1", SINCE, {}, pending_epoch=PENDING)
    return body, client, feed


@pytest.mark.parametrize("standing", STANDINGS)
def test_fetch_handshake_feed_when_the_server_golden_is_replayed_then_the_standing_is_read(
    standing,
):
    body, client, feed = _replay(standing)

    assert client.params == {"since_epoch": SINCE, "pending_epoch": PENDING}
    assert feed.pending_commit is OwnCommitStanding(body["pending_commit"])
    assert feed.pending_commit is not None
    assert feed.pending_commit.value == standing
    assert [(h.id, h.epoch, h.blob) for h in feed.handshakes] == [
        (h["id"], h["epoch"], mls_from_base64(h["blob"])) for h in body["handshakes"]
    ]


def test_own_commit_standing_when_the_goldens_are_replayed_then_it_holds_exactly_their_five_strings():
    assert {s.value for s in OwnCommitStanding} == set(STANDINGS)
