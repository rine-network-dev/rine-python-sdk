"""Recovery step 6: a restored agent retakes its seat in each closed group.

These drive the real ``rine-mls`` core. The restored agent is a fresh device: its
config dir holds keys and no MLS state, so the only way back in is the published
GroupInfo. Only the server is mocked.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._mls import load_mls_group, mls_group_id_bytes, open_mls_client
from rine._mls.binding import DEFAULT_CIPHER_SUITE
from rine._mls.escrow_drain import DrainOutcome
from rine._mls.escrow_report import EscrowDeferral, EscrowReport
from rine._mls.escrow_store import PendingEscrow, write_pending
from rine._recover_reseat import GroupReseat, ReseatStatus, reseat_closed_groups
from rine.errors import CryptoError, RineApiError
from rine.testing import WORLD

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
THIRD_ID = "12121212-3434-5656-7878-909090909090"


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _group_row(agent_id: str, *, mls_group_id: str | None = "latched") -> dict:
    return {
        "id": GROUP_ID,
        "name": "ops",
        "handle": "#ops@acme",
        "created_at": "2024-01-01T00:00:00Z",
        "mls_group_id": mls_group_id,
        "member_agent_ids": [agent_id],
    }


def _mock_groups(*rows: dict) -> None:
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": list(rows)}))


def _mock_group_info(blob: bytes | None, epoch: int = 1) -> None:
    body = {
        "group_info": None if blob is None else base64.b64encode(blob).decode(),
        "epoch": epoch,
    }
    respx.get(f"{API}/groups/{GROUP_ID}/mls/group-info").mock(
        return_value=httpx.Response(200, json=body)
    )


def _mock_commit() -> respx.Route:
    def _accept(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"epoch": json.loads(request.content)["epoch"]})

    return respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(side_effect=_accept)


def _published_group_info(tmp_path, agent_id: str, other_agent_id: str) -> bytes:
    """The GroupInfo a peer publishes for a group that seats the restored agent."""
    donor_dir = str(tmp_path / "donor")
    save_agent_keys(donor_dir, agent_id, WORLD.keys(agent_id))
    key_package = open_mls_client(donor_dir, agent_id).generate_key_package()
    peer_dir = str(tmp_path / "peer")
    save_agent_keys(peer_dir, other_agent_id, WORLD.keys(other_agent_id))
    save_agent_keys(peer_dir, agent_id, WORLD.keys(agent_id))
    group = open_mls_client(peer_dir, other_agent_id).create_group_with_members(
        mls_group_id_bytes(GROUP_ID), [key_package]
    )
    return group.last_commit().group_info


def _fresh_device(tmp_config_dir: str, other_agent_id: str) -> None:
    """The restored device knows the peer's leaf key and holds no MLS state."""
    save_agent_keys(tmp_config_dir, other_agent_id, WORLD.keys(other_agent_id))


class TestReseat:
    @respx.mock
    def test_reseat_when_the_agent_is_seated_then_it_retakes_the_seat_and_escrows_the_epoch(
        self,
        sync_client,
        tmp_config_dir,
        agent_id,
        other_agent_id,
        tmp_path,
        mls_escrow_stub,
        escrow_calls,
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        posted = _mock_commit()

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert result == [GroupReseat(agent_id, GROUP_ID, ReseatStatus.RESEATED)]
        assert posted.call_count == 1
        local = load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID)
        assert local is not None
        assert mls_escrow_stub == [(GROUP_ID, local.epoch())]
        assert escrow_calls == [("settle", GROUP_ID), ("drain", GROUP_ID)]
        assert (
            json.loads(posted.calls.last.request.content)["cipher_suite"] == DEFAULT_CIPHER_SUITE
        )

    @respx.mock
    def test_reseat_when_the_group_published_no_group_info_then_it_says_so(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        _mock_groups(_group_row(agent_id))
        _mock_group_info(None)
        posted = _mock_commit()

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [r.status for r in result] == [ReseatStatus.NO_GROUP_INFO]
        assert posted.call_count == 0

    @respx.mock
    def test_reseat_when_the_roster_holds_no_leaf_of_the_agent_then_it_is_not_seated(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, THIRD_ID, other_agent_id))
        posted = _mock_commit()

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [r.status for r in result] == [ReseatStatus.NOT_SEATED]
        assert posted.call_count == 0
        assert load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID) is None

    @respx.mock
    def test_reseat_when_the_server_refuses_the_commit_then_nothing_is_adopted_or_escrowed(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, mls_escrow_stub
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(403, json={"detail": "not a member"})
        )

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [r.status for r in result] == [ReseatStatus.FAILED]
        assert mls_escrow_stub == []
        assert list(tmp_path.glob("**/escrow-pending/**/*.bin")) == []

    @respx.mock
    def test_reseat_when_the_group_advanced_during_the_post_then_it_retakes_the_seat_once(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        accepted = _mock_commit().side_effect
        conflict = httpx.Response(409, json={"error": "epoch_conflict", "detail": "moved"})
        posted = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            side_effect=[conflict, accepted]
        )

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [r.status for r in result] == [ReseatStatus.RESEATED]
        assert posted.call_count == 2

    @respx.mock
    def test_reseat_when_the_group_keeps_advancing_then_the_second_loss_is_reported(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        posted = respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(
            return_value=httpx.Response(409, json={"error": "epoch_conflict", "detail": "moved"})
        )

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [r.status for r in result] == [ReseatStatus.FAILED]
        assert posted.call_count == 2

    @respx.mock
    def test_reseat_when_the_escrow_was_deferred_then_the_outcome_says_it_is_pending(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path, monkeypatch
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        _mock_commit()
        monkeypatch.setattr(
            "rine._recover_reseat.drain_escrow",
            lambda *_a, **_k: DrainOutcome(0, 0, (), CryptoError("no escrow key")),
        )

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert result == [
            GroupReseat(
                agent_id,
                GROUP_ID,
                ReseatStatus.RESEATED,
                None,
                True,
                EscrowReport(deferral=EscrowDeferral.KEY_UNAVAILABLE),
            )
        ]

    @respx.mock
    def test_reseat_when_only_an_older_epoch_fails_to_upload_then_the_new_epoch_is_not_pending(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        _mock_commit()
        write_pending(tmp_config_dir, agent_id, PendingEscrow(GROUP_ID, 0, b"\x01" * 16, b"old"))
        uploaded: list[int] = []

        def upload(client, agent, group_id, epoch, body):
            if epoch == 0:
                raise RineApiError(422, "stale", json.dumps({"error": "stale_key_gen"}))
            uploaded.append(epoch)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("rine._mls.escrow_upload.upload_escrow", upload)
            result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert result == [GroupReseat(agent_id, GROUP_ID, ReseatStatus.RESEATED)]
        assert uploaded

    @respx.mock
    def test_reseat_when_the_new_epoch_cannot_be_uploaded_then_it_is_pending(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id, tmp_path
    ):
        _mock_token()
        _fresh_device(tmp_config_dir, other_agent_id)
        _mock_groups(_group_row(agent_id))
        _mock_group_info(_published_group_info(tmp_path, agent_id, other_agent_id))
        _mock_commit()

        def upload(*_args):
            raise ConnectionError("network down")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr("rine._mls.escrow_upload.upload_escrow", upload)
            result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [(r.status, r.escrow_pending) for r in result] == [(ReseatStatus.RESEATED, True)]

    @respx.mock
    def test_reseat_when_a_group_is_open_or_lists_other_agents_then_it_is_skipped(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_groups(
            {**_group_row(agent_id, mls_group_id=None)},
            {**_group_row(other_agent_id)},
        )

        assert reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id]) == []

    @respx.mock
    def test_reseat_when_the_group_list_cannot_be_read_then_the_agent_is_reported_failed(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_token()
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(500, json={"detail": "x"}))

        result = reseat_closed_groups(sync_client._http, tmp_config_dir, [agent_id])

        assert [(r.agent_id, r.group_id, r.status) for r in result] == [
            (agent_id, None, ReseatStatus.FAILED)
        ]
