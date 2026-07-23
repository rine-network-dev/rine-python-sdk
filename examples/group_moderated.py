"""Closed/moderated group enrollment: list_requests() + vote() approval.

`enrollment="majority"` (also available: `"unanimity"`) means a peer calling
`client.groups.join(handle)` does not join immediately — it gets back a
`PendingJoinResult` and a `JoinRequestRead` is created. An existing member
then reviews pending requests with `list_requests()` and casts a vote with
`vote()`; the request resolves once enough votes are in.

This script runs both roles against the group it creates: it submits a join
request as a second config dir (`.rine-peer`, generated via `onboard.py`
against a different `org_slug` if you want a truly separate identity) and
then, using the group creator's own credentials, approves it. Point
`PEER_CONFIG_DIR` at any onboarded identity that isn't already a member.

Prereqs: `pip install rine`; an onboarded identity in `.rine` (run
`onboard.py` first) plus a second onboarded identity for the peer role.
Run: `python group_moderated.py`
"""

from __future__ import annotations

from rine import ConflictError, SyncRineClient
from rine.types import PendingJoinResult

ADMIN_CONFIG_DIR = ".rine"
PEER_CONFIG_DIR = ".rine-peer"  # a second onboarded identity


def main() -> None:
    with SyncRineClient(config_dir=ADMIN_CONFIG_DIR) as admin:
        try:
            group = admin.groups.create(
                "moderated-example",
                enrollment="majority",
                visibility="public",
            )
            print(f"created moderated group {group.handle}")
        except ConflictError:
            group = next(g for g in admin.groups.list() if g.name == "moderated-example")
            print(f"reusing existing group {group.handle}")

        try:
            with SyncRineClient(config_dir=PEER_CONFIG_DIR) as peer:
                result = peer.groups.join(group.handle)
                if isinstance(result, PendingJoinResult):
                    print(f"peer join is pending: request {result.request.id}")
                else:
                    print("peer joined immediately (enrollment was not majority/unanimity)")
        except Exception as e:  # noqa: BLE001 — demo tolerates a missing peer identity
            print(f"peer join skipped ({e}); set up {PEER_CONFIG_DIR} to see this step")

        requests = admin.groups.list_requests(group.handle)
        pending = [r for r in requests if r.status == "pending"]
        if not pending:
            print("no pending join requests to vote on")
            return

        request = pending[0]
        vote = admin.groups.vote(group.handle, str(request.id), "approve")
        print(f"voted approve on {vote.request_id}: status={vote.status}")


if __name__ == "__main__":
    main()
