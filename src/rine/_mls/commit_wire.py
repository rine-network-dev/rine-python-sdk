"""The commit endpoint: one epoch-advancing commit in, the server's verdict out.

Split from :mod:`rine._mls.api` so neither file outgrows what one screen holds.
Same encoding rules: every blob is standard base64, via :mod:`rine._mls.wire`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine._mls.wire import mls_to_base64

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit


@dataclass(frozen=True)
class MlsCommitAccepted:
    """What the server answered a commit it accepted."""

    epoch: int
    """The epoch the server committed to."""

    confirmed: bool
    """Whether the commit is final. ``False`` only in an open-enrollment group,
    where the commit stays tentative until a member acknowledges it and the server
    may still roll it back. A server that predates the field answers ``True``,
    which is the response schema's own default."""


def mls_commit(
    client: Any, group_id: str, commit: MlsCommit, extra_headers: dict[str, str]
) -> MlsCommitAccepted:
    """Publish a commit, its Welcomes and the epoch's fresh GroupInfo.

    Returns:
        The epoch the server committed to, and whether it is final.
    """
    body: dict[str, Any] = {
        "commit": mls_to_base64(commit.commit),
        "group_info": mls_to_base64(commit.group_info),
        "cipher_suite": commit.cipher_suite,
        "epoch": commit.epoch,
        "welcomes": [
            {"agent_id": w.agent_id, "welcome": mls_to_base64(w.welcome)} for w in commit.welcomes
        ],
        "removes": list(commit.removes),
    }
    data = client.post(
        f"/groups/{group_id}/mls/commit", json_body=body, extra_headers=extra_headers
    )
    epoch = data.get("epoch")
    return MlsCommitAccepted(
        epoch=commit.epoch if epoch is None else int(epoch),
        confirmed=bool(data.get("confirmed", True)),
    )
