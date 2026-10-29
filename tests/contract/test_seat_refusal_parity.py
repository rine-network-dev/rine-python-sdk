"""The refusal sentences and the marker file are one set of bytes on both client stacks.

The twin of ``test_seat_vocabulary_parity.py``: what a refused rotated leaf, a held update, a
skipped admission, a removal without a leaf and an uncorroborated Welcome say, and the
rotation marker both stacks read on one host. The TypeScript sources are read, never restated.
"""

from __future__ import annotations

import re
import typing
import uuid
from types import SimpleNamespace

import pytest

from rine._mls import welcome_guard
from rine._mls.admission import MlsAdmissionSkipReason
from rine._mls.binding import CommitPendingError
from rine._mls.failures import group_failures
from rine._mls.key_not_current import (
    KEY_NOT_CURRENT_MESSAGE,
    MLS_ERR_KEY_NOT_CURRENT,
    MlsKeyNotCurrentError,
)
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine._mls.rotated_leaf import MLS_ERR_ROTATED_LEAF, MlsRotatedLeafError
from rine._mls.rotation_marker import _MARKER_FILE
from rine.admission_words import _MLS_ADMISSION_SENTENCES
from rine.errors import MlsError
from rine.group_removal import removal_message
from tests.contract.ts_twin import (
    CORE_SRC,
    TS_SDK_SRC,
    constant,
    function_body,
    literals,
    source,
)

pytestmark = pytest.mark.skipif(not CORE_SRC.is_dir(), reason="rine-core is not checked out")

AGENT = "a1a1a1a1-0000-4000-8000-000000000001"
GROUP = "11111111-0000-4000-8000-0000000000a1"
EPOCH_SENTINEL = 31337


def test_the_rotated_leaf_message_when_compared_with_the_typescript_twin_then_it_is_equal() -> (
    None
):
    """The remove-and-invite remedy reads the same on both stacks."""
    ts = literals(function_body(source("mls-rotated-leaf.ts"), "rotatedLeafMessage"))
    expected = ts.replace("${agentId}", AGENT).replace("${groupId}", GROUP)
    assert str(MlsRotatedLeafError(AGENT, GROUP)) == expected
    assert (
        re.search(r'MLS_ERR_ROTATED_LEAF\s*=\s*"([^"]+)"', source("crypto/mls-errors.ts"))[1]
        == MLS_ERR_ROTATED_LEAF
    )


def test_the_commit_pending_sentence_when_compared_with_the_typescript_twin_then_it_is_equal() -> (
    None
):
    """A held update refuses other commits with the same words on both stacks."""
    ts = literals(function_body(source("mls-commit-pending.ts"), "commitPendingMessage"))

    def refuse() -> None:
        with group_failures(GROUP):
            raise CommitPendingError("a commit is pending")

    with pytest.raises(MlsError) as caught:
        refuse()
    assert str(caught.value) == ts.replace("${groupId}", GROUP)
    assert (
        caught.value.code
        == re.search(r'MLS_ERR_COMMIT_PENDING\s*=\s*"([^"]+)"', source("crypto/mls-errors.ts"))[1]
    )


def test_the_superseded_package_sentence_when_compared_with_the_twin_then_it_is_equal() -> None:
    """A skipped admission explains the spent package in the same words."""
    ts = source("group-admission.ts")
    entry = re.search(r"key_package_not_current:\s*((?:\"[^\"]*\"\s*\+?\s*)+),", ts)
    assert entry is not None
    assert literals(entry[1]) == _MLS_ADMISSION_SENTENCES["key_package_not_current"]


def test_the_revoked_seat_sentence_when_compared_with_the_twin_then_it_is_equal() -> None:
    """A held admission explains the unreclaimed seat in the same words, under a shared reason."""
    entry = re.search(
        r"revoked_seat_unreclaimed:\s*((?:\"[^\"]*\"\s*\+?\s*)+),", source("group-admission.ts")
    )
    assert entry is not None
    assert literals(entry[1]) == _MLS_ADMISSION_SENTENCES["revoked_seat_unreclaimed"]
    ts = source("mls-admission.ts")
    union = ts[
        ts.index("type MlsAdmissionSkipReason") : ts.index("export interface MlsAdmissionOutcome")
    ]
    assert '"revoked_seat_unreclaimed";' in union
    assert "revoked_seat_unreclaimed" in typing.get_args(MlsAdmissionSkipReason)


def test_the_peer_not_admitted_refusal_when_compared_with_the_twin_then_it_is_equal() -> None:
    """A tree holding a member this agent cannot verify earns the same refusal on both stacks."""
    body = function_body(source("mls-peer-refusal.ts"), "peerNotAdmittedRefusal")
    reason, _, text = body.partition('"peer_not_admitted",')
    assert reason
    refusal = peer_not_admitted_refusal(GROUP)
    assert (refusal.reason, str(refusal)) == (
        "peer_not_admitted",
        literals(text).replace("${groupId}", GROUP),
    )


def test_the_removal_without_a_leaf_when_compared_with_the_twin_then_it_is_equal() -> None:
    """A Remove commit that took no leaf reads the same in both SDKs."""
    ts = (TS_SDK_SRC / "resources" / "groups-removal-message.ts").read_text(encoding="utf-8")
    block = ts[ts.index("if (removal !== undefined) {") : ts.index("if (mls) {")]
    expected = literals(block).replace("${agentId}", AGENT).replace("${name}", "grp")
    expected = expected.replace("${removal.epoch}", str(EPOCH_SENTINEL))
    assert (
        removal_message(
            "grp", AGENT, left=False, encryption="mls", epoch=EPOCH_SENTINEL, removed_leaf=False
        )
        == expected
    )


def test_the_uncorroborated_welcome_when_compared_with_the_twin_then_it_is_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Welcome the roster contradicts earns the same refusal on both stacks."""
    ts = literals(function_body(source("mls-welcome-guard.ts"), "uncorroboratedDetail"))
    monkeypatch.setattr(welcome_guard, "_corroborate_roster", lambda *_: "uncorroborated")
    joined = SimpleNamespace(group_id=lambda: uuid.UUID(GROUP).bytes)
    refusal = welcome_guard.welcome_refusal(
        None, None, joined, SimpleNamespace(group_id=GROUP), AGENT
    )
    assert refusal is not None
    assert str(refusal) == ts.replace("${groupId}", GROUP)


def test_the_rotation_marker_when_compared_with_the_twin_then_file_and_fields_are_equal() -> None:
    """Both stacks read and write one marker file on a host."""
    ts = source("mls-rotation-marker.ts")
    assert re.search(r'MARKER_FILE\s*=\s*"([^"]+)"', ts)[1] == _MARKER_FILE
    for field in ("key_packages", "seats"):
        assert f'record["{field}"]' in ts


def test_the_key_not_current_refusal_when_compared_with_the_typescript_twin_then_it_is_equal() -> (
    None
):
    """The code and the sentence the server's refusal and the drain's pre-check share."""
    text = source("crypto/mls-key-not-current.ts")
    assert (
        re.search(r'MLS_ERR_KEY_NOT_CURRENT\s*=\s*"([^"]+)"', text)[1] == MLS_ERR_KEY_NOT_CURRENT
    )
    assert literals(constant(text, "KEY_NOT_CURRENT_MESSAGE")) == KEY_NOT_CURRENT_MESSAGE
    error = MlsKeyNotCurrentError()
    assert (error.code, str(error)) == (MLS_ERR_KEY_NOT_CURRENT, KEY_NOT_CURRENT_MESSAGE)
