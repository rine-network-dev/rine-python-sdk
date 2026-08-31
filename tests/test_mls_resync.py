"""The recovery ladder: replaying a backlog, and resyncing when replay cannot help.

These drive the real ``rine-mls`` core — only the server is mocked — so the
commit asserted here is the one the server would receive, built by the core
against a GroupInfo a real peer published.

The wedged agent is a Welcome joiner the group left behind, which is the case the
server's own refusal names first. It is deliberately not the founder: the two
differ in what their local store holds, and that difference exposes a measured
limit in the native core.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from rine._crypto.keys import generate_agent_keys, save_agent_keys
from rine._mls import (
    DEFAULT_CIPHER_SUITE,
    load_mls_group,
    mls_group_id_bytes,
    open_mls_client,
    process_mls_welcomes,
    publish_mls_key_packages,
    recover_mls_group,
)
from rine._mls.binding import MlsGroup
from rine.errors import MlsResyncUnavailableError

#: The tree-query and resync surface lands in ``rine-mls`` 0.1.1, and reaching
#: Python needs a wheel built from it — a ``--native`` artifact build, not a
#: source change. Every installed wheel at the time of writing predates it, so
#: these tests are skipped rather than silently passing against a binding that
#: cannot answer. The TypeScript twin (``rine-core/test/mls-resync.test.ts``)
#: runs against a rebuilt napi addon and covers the same ladder.
pytestmark = pytest.mark.skipif(
    not hasattr(MlsGroup, "current_member_index"),
    reason=(
        "the installed rine-mls wheel predates the tree-query surface "
        "(MlsGroup.current_member_index); rebuild it with "
        "./scripts/build-mls-artifacts.sh and reinstall to run these"
    ),
)

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
WELCOME_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
THIRD_ID = "12121212-3434-5656-7878-909090909090"


def _b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _peer_client(tmp_path, agent: str):
    peer_dir = str(tmp_path / f"peer-{agent}")
    save_agent_keys(peer_dir, agent, generate_agent_keys())
    return open_mls_client(peer_dir, agent)


def _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path):
    """A peer founds the group with us in it, and we install the Welcome."""
    _mock_token()
    route = respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(201, json={"stored": 4})
    )
    publish_mls_key_packages(sync_client._http, tmp_config_dir, agent_id, count=4)
    ours = base64.b64decode(
        json.loads(route.calls[0].request.content)["packages"][0], validate=True
    )
    peer = _peer_client(tmp_path, other_agent_id)
    group = peer.create_group_with_members(mls_group_id_bytes(GROUP_ID), [ours])
    group.save()

    respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "welcomes": [
                        {
                            "id": WELCOME_ID,
                            "group_id": GROUP_ID,
                            "blob": _b64(group.last_commit().welcomes[0]),
                            "created_at": "2024-01-01T00:00:00Z",
                        }
                    ]
                },
            ),
            *[httpx.Response(200, json={"welcomes": []}) for _ in range(4)],
        ]
    )
    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
    return group


def _peer_advances(group, tmp_path) -> tuple[int, str, str]:
    """The peer commits one real Add; we are never told about it."""
    third = _peer_client(tmp_path, THIRD_ID).generate_key_package()
    bundle = group.add_member(third)
    group.save()
    return bundle.epoch, _b64(bundle.commit), _b64(bundle.group_info)


def _mock_group_info(blob: str | None, epoch: int | None) -> None:
    respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
        return_value=httpx.Response(200, json={"group_info": blob, "epoch": epoch})
    )


def _mock_commit() -> respx.Route:
    def _accept(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json={"epoch": body["epoch"], "delivered_to": 1})

    return respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(side_effect=_accept)


def _mock_handshakes(*, commit: str | None = None, epoch: int = 0) -> None:
    if commit is None:
        respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
            return_value=httpx.Response(200, json={"handshakes": []})
        )
        return
    respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
        return_value=httpx.Response(
            200,
            json={
                "handshakes": [
                    {
                        "id": "h1",
                        "epoch": epoch,
                        "blob": commit,
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )
    respx.post(f"{API}/groups/{GROUP_ID}/mls/ack").mock(
        return_value=httpx.Response(200, json={"confirmed": True, "acks": 1, "needed": 1})
    )


def _refuse_replay() -> None:
    respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": "mls_resync_required",
                "detail": "replay cannot bridge that gap",
            },
        )
    )


def _local(tmp_config_dir, agent_id):
    return load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID)


class TestTheCheapRung:
    @respx.mock
    def test_recover_when_the_backlog_is_still_there_then_it_replays_without_committing(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        stale_epoch = _local(tmp_config_dir, agent_id).epoch()
        epoch, commit, group_info = _peer_advances(group, tmp_path)
        _mock_group_info(group_info, epoch)
        _mock_handshakes(commit=commit, epoch=epoch)
        posted = _mock_commit()

        result = recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.rung == "replay"
        assert result.processed == 1
        assert result.from_epoch == stale_epoch
        assert result.behind == epoch - stale_epoch
        assert result.epoch == epoch
        assert posted.call_count == 0

    @respx.mock
    def test_recover_when_the_group_moves_during_the_replay_then_it_does_not_escalate(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        epoch, commit, group_info = _peer_advances(group, tmp_path)
        # The distance is measured first, against the epoch the replay can reach;
        # every later read reports a group that has already moved on.
        respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
            side_effect=[
                httpx.Response(200, json={"group_info": group_info, "epoch": epoch}),
                *[
                    httpx.Response(200, json={"group_info": group_info, "epoch": epoch + 5})
                    for _ in range(4)
                ],
            ]
        )
        _mock_handshakes(commit=commit, epoch=epoch)
        posted = _mock_commit()

        result = recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.rung == "replay"
        assert posted.call_count == 0


class TestTheExpensiveRung:
    @respx.mock
    def test_recover_when_the_server_refuses_the_replay_then_it_resyncs_admitting_nobody(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        stale_epoch = _local(tmp_config_dir, agent_id).epoch()
        stale_leaf = _local(tmp_config_dir, agent_id).current_member_index()
        seated_before = len(group.member_identities())
        epoch, _commit, group_info = _peer_advances(group, tmp_path)
        _mock_group_info(group_info, epoch)
        _refuse_replay()
        posted = _mock_commit()

        result = recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.rung == "resync"
        assert result.from_epoch == stale_epoch
        assert result.behind == epoch - stale_epoch
        assert result.epoch == epoch + 1
        assert posted.call_count == 1
        # An external commit adds nobody, so it carries no Welcome.
        body = json.loads(posted.calls[0].request.content)
        assert body["welcomes"] == []
        assert body["group_info"]
        assert body["cipher_suite"] == DEFAULT_CIPHER_SUITE
        # The same leaf, still seated exactly once, and the tree the same size.
        assert _local(tmp_config_dir, agent_id).current_member_index() == stale_leaf
        group.apply_commit(base64.b64decode(body["commit"], validate=True))
        seats = group.member_identities()
        assert len(seats) == seated_before + 1  # the peer's own Add landed too
        assert len([s for s in seats if s.index == stale_leaf]) == 1

    @respx.mock
    def test_recover_when_the_replay_leaves_a_gap_then_it_escalates(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        stale_epoch = _local(tmp_config_dir, agent_id).epoch()
        epoch, _commit, group_info = _peer_advances(group, tmp_path)
        _mock_group_info(group_info, epoch)
        # A 200 with nothing in it: the server answered, and the gap is still there.
        _mock_handshakes()
        posted = _mock_commit()

        result = recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.rung == "resync"
        assert result.processed == 0
        assert result.behind == epoch - stale_epoch
        assert posted.call_count == 1

    @respx.mock
    def test_recover_when_the_group_published_no_group_info_then_it_refuses(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_group_info(None, None)
        _refuse_replay()
        posted = _mock_commit()

        with pytest.raises(Exception, match="published no GroupInfo"):
            recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)
        assert posted.call_count == 0

    @respx.mock
    def test_recover_when_the_resync_is_refused_then_the_message_names_the_remedy(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        """The operator gets the group, the rung and the remedy.

        An mls-rs sentence about a protocol state names none of the three, and
        handing one over is the failure this verb exists to replace.
        """
        _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _mock_group_info(None, None)
        _refuse_replay()
        _mock_commit()

        with pytest.raises(Exception) as caught:
            recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        message = str(caught.value)
        assert GROUP_ID in message
        assert "resync rung" in message
        assert "invite it again" in message
        # The core's own text is kept, last, so a bug report still carries it.
        assert "published no GroupInfo" in message


class TestWhatItRefuses:
    @respx.mock
    def test_recover_when_local_state_will_not_load_then_it_refuses_by_name(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        posted = _mock_commit()

        with pytest.raises(MlsResyncUnavailableError) as caught:
            recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        # Never a fallback to the plain external join: MLS refuses that for an
        # agent its tree already holds, so it would answer with a protocol error.
        assert posted.call_count == 0
        assert "remove this agent" in str(caught.value)
        assert caught.value.code == "mls_resync_unavailable"

    @respx.mock
    def test_recover_when_the_failure_is_not_the_escalation_signal_then_it_surfaces(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _, _commit, group_info = _peer_advances(group, tmp_path)
        _mock_group_info(group_info, 99)
        respx.get(f"{API}/groups/{GROUP_ID}/mls/handshakes").mock(
            return_value=httpx.Response(
                503, json={"error": "upstream_down", "detail": "upstream down"}
            )
        )
        posted = _mock_commit()

        with pytest.raises(Exception, match="upstream down"):
            recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)
        assert posted.call_count == 0

    @respx.mock
    def test_recover_when_the_replay_hits_a_protocol_refusal_then_it_escalates(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, monkeypatch
    ):
        """The shape ``sync_mls_group``'s own orphan reconciliation produces.

        It re-bootstraps with a plain external join, and MLS refuses that for an
        agent the tree already holds — measured, not assumed. Rethrown, the operator
        saw a protocol error naming a leaf they never asked about; the rung that
        actually fixes it is the resync.
        """
        from rine._mls import resync as resync_mod
        from rine._mls.binding import MlsCoreError

        group = _found_and_seat(sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path)
        _, _commit, group_info = _peer_advances(group, tmp_path)
        _mock_group_info(group_info, 99)
        posted = _mock_commit()

        def _refuse(*_args, **_kwargs):
            raise MlsCoreError("duplicate signature key, hpke key or identity found at index 1")

        monkeypatch.setattr(resync_mod, "sync_mls_group", _refuse)

        result = recover_mls_group(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.rung == "resync"
        assert posted.call_count == 1
