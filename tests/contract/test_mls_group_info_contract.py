"""SDK-side group-info contract: replay the server goldens through the SDK's readers.

The sync's settle and the resync read ``confirmed_epoch``, the join-token pointer the server
serves with the group's GroupInfo. A reader that gets ``None`` treats the epoch as unknown, so a
renamed key would leave every client suite green while the resync lost its anchor. Replaying the
server's own goldens, recorded from the real router, pins the name from the client's side. The
goldens also carry ``latch_epoch``, which the server still sends and no client reads: the hold
decision rests on the handshakes read's pending standing (``test_mls_handshakes_contract``).
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.api import fetch_group_info
from rine._mls.sync_api import GroupEpochs, fetch_group_epochs
from rine._mls.wire import mls_from_base64
from tests.contract._loader import load

GOLDENS = ["mls_group_info_200_settled", "mls_group_info_200_tentative"]


class _Served:
    """A client whose one route answers the golden's body."""

    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body
        self.paths: list[str] = []

    def get(self, path: str, **_kwargs: Any) -> dict[str, Any]:
        self.paths.append(path)
        return self.body


@pytest.mark.parametrize("name", GOLDENS)
def test_fetch_group_info_when_the_server_golden_is_replayed_then_every_read_field_is_read(name):
    body = load(name)["body"]
    client = _Served(body)

    info = fetch_group_info(client, "g1", {})

    assert client.paths == ["/groups/g1/mls/group-info"]
    assert info.blob == mls_from_base64(body["group_info"])
    assert (info.epoch, info.confirmed_epoch) == (body["epoch"], body["confirmed_epoch"])


@pytest.mark.parametrize("name", GOLDENS)
def test_fetch_group_epochs_when_the_server_golden_is_replayed_then_the_confirmed_epoch_is_read(
    name,
):
    body = load(name)["body"]

    epochs = fetch_group_epochs(_Served(body), "g1", {})

    assert epochs == GroupEpochs(confirmed=body["confirmed_epoch"])


def test_fetch_group_epochs_when_a_field_is_renamed_then_it_reads_as_unknown():
    body = dict(load("mls_group_info_200_tentative")["body"])
    body["confirmed"] = body.pop("confirmed_epoch")

    assert fetch_group_epochs(_Served(body), "g1", {}).confirmed is None
