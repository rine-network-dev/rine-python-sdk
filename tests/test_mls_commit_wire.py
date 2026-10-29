"""The commit answer's `confirmed` flag, the group row's two epochs, a held update's refusal."""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.actor import MlsActor
from rine._mls.api import MlsCommit
from rine._mls.binding import CommitPendingError
from rine._mls.commit import post_mls_commit, post_mls_commit_bundle
from rine._mls.commit_wire import MlsCommitAccepted, mls_commit
from rine._mls.failures import group_failures
from rine._mls.sync_api import GroupEpochs, fetch_group_epochs
from rine.errors import ConflictError, MlsError, RineApiError
from tests.rotation_world import G1, A

HEADERS = {"X-Rine-Agent": A}


class _Client:
    """A client that answers each call with a canned value or raises it."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.posted: list[dict[str, Any]] = []

    def post(self, path: str, **kwargs: Any) -> Any:
        self.posted.append(kwargs["json_body"])
        return self._reply()

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._reply()

    def _reply(self) -> Any:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _commit() -> MlsCommit:
    return MlsCommit(commit=b"c", group_info=b"g", epoch=4, cipher_suite=1)


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ({"epoch": 4}, MlsCommitAccepted(4, True)),
        ({"epoch": 5, "confirmed": False}, MlsCommitAccepted(5, False)),
        ({"epoch": 4, "confirmed": True}, MlsCommitAccepted(4, True)),
        ({}, MlsCommitAccepted(4, True)),
    ],
    ids=["field absent", "tentative", "confirmed", "no epoch echoed"],
)
def test_mls_commit_when_the_server_answers_then_confirmed_defaults_to_true(
    answer: dict[str, Any], expected: MlsCommitAccepted
) -> None:
    """A server that predates the field confirms, as the response schema's default does."""
    assert mls_commit(_Client(answer), G1, _commit(), HEADERS) == expected


def test_post_mls_commit_when_the_commit_is_tentative_then_it_still_returns_the_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The applying callers keep their integer, and the bundle keeps the flag."""
    monkeypatch.setattr("rine._mls.commit.mls_heartbeat", lambda *_a: None)
    actor = MlsActor(
        client=_Client({"epoch": 5, "confirmed": False}), config_dir="c", agent_id="a"
    )
    assert post_mls_commit(actor, G1, _commit(), HEADERS) == 5
    bundle = post_mls_commit_bundle(actor, G1, _commit(), HEADERS)
    assert bundle == MlsCommitAccepted(5, False)


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ({"epoch": 6, "confirmed_epoch": 5, "latch_epoch": 6}, GroupEpochs(5)),
        ({"epoch": 6}, GroupEpochs(None)),
        ({"epoch": 6, "confirmed_epoch": 0, "latch_epoch": 0}, GroupEpochs(0)),
    ],
    ids=["tentative", "server predates the fields", "epoch zero is an epoch"],
)
def test_fetch_group_epochs_when_the_group_answers_then_only_the_confirmed_epoch_is_read(
    answer: dict[str, Any], expected: GroupEpochs
) -> None:
    """The confirmed epoch never falls back to the group's own `epoch`; the latch is not read."""
    assert fetch_group_epochs(_Client(answer), G1, HEADERS) == expected


def test_fetch_group_epochs_when_confirmation_is_pending_then_the_epoch_is_unknown() -> None:
    """A group awaiting its first ACK serves no confirmed GroupInfo; that is not a failure."""
    err = ConflictError("awaiting", '{"error": "pending_confirmation"}')
    assert fetch_group_epochs(_Client(err), G1, HEADERS) == GroupEpochs(None)


def test_fetch_group_epochs_when_another_conflict_comes_back_then_it_propagates() -> None:
    """Only the pending-confirmation 409 reads as unknown."""
    with pytest.raises(ConflictError):
        fetch_group_epochs(_Client(ConflictError("x", '{"error": "other"}')), G1, HEADERS)


def test_fetch_group_epochs_when_the_server_fails_then_it_propagates() -> None:
    """A transport or 5xx failure must not read as an unknown epoch."""
    with pytest.raises(RineApiError):
        fetch_group_epochs(_Client(RineApiError(503, "down")), G1, HEADERS)


def test_group_failures_when_a_commit_is_already_pending_then_it_says_to_retry_later() -> None:
    """The core's own message names no group and no wait; this names both."""
    with pytest.raises(MlsError) as caught, group_failures(G1):
        raise CommitPendingError("a commit is pending")
    assert caught.value.code == "RINE_MLS_COMMIT_PENDING"
    assert str(caught.value) == (
        f"This agent's key update in group {G1} is awaiting a member's acknowledgement; "
        "retry after it settles, at most 15 minutes."
    )
