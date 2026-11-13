"""A group our org may not post in is refused before anything is sealed or sent.

The sentences are the server's, pinned to ``rine-core/test/fixtures/group-rules.json`` so the
three clients cannot drift from it. The send-path tests count ``POST /messages`` on the same
mocked route the seated control arm makes fire, so a count of zero means "refused" and not "the
mock could not answer".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._group_send import encrypt_for_group_sync
from rine._http import SyncHttpClient
from rine.errors import RineError
from rine.format import group_posting_line
from rine.group_postable import (
    GROUP_POSTING_REFUSED_CODE,
    GroupPostingRefusedError,
    assert_group_postable,
    unreadable_by_orgs_sentence,
)
from rine.testing import WORLD, write_agent_identity
from rine.types import GroupRead, MessageRead, PostingRefusal

FIXTURE = Path(__file__).resolve().parents[2] / "rine-core/test/fixtures/group-rules.json"
if not FIXTURE.is_file():
    pytest.skip(
        "rine-core is not checked out - SDK tested outside the monorepo", allow_module_level=True
    )
RULES = json.loads(FIXTURE.read_text())

API = "https://rine.network"
SENDER = "00000000-1111-2222-3333-444444444444"
MEMBER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#billboard@acme.rine.network"
PAYLOAD = {"announcement": "open enrolment, all welcome"}


def _group_row(**overrides: Any) -> dict[str, Any]:
    return {
        "id": GROUP_ID,
        "name": "billboard",
        "handle": GROUP_HANDLE,
        "created_at": "2024-01-01T00:00:00Z",
        "mls_enabled": False,
        "mls_group_id": None,
        "mls_pending": False,
        "member_agent_ids": [SENDER],
        **overrides,
    }


def _group(**overrides: Any) -> GroupRead:
    return GroupRead.model_validate(_group_row(**overrides))


class TestTheSentencesAreTheServers:
    @pytest.mark.parametrize("reason", PostingRefusal)
    def test_assert_group_postable_when_refused_then_says_the_pinned_sentence(
        self, reason: PostingRefusal
    ) -> None:
        with pytest.raises(GroupPostingRefusedError) as caught:
            assert_group_postable(_group(posting_refused=reason.value))

        assert str(caught.value) == RULES["sentences"]["posting_refused"][reason.value]
        assert caught.value.code == GROUP_POSTING_REFUSED_CODE
        assert caught.value.group_id == GROUP_ID
        assert caught.value.reason is reason

    def test_the_refusal_values_when_compared_to_the_shared_fixture_then_the_list_matches(
        self,
    ) -> None:
        assert [r.value for r in PostingRefusal] == RULES["posting_refusals"]
        assert GROUP_POSTING_REFUSED_CODE in RULES["codes"]

    def test_group_posting_refused_error_is_a_rine_error_a_caller_can_catch(self) -> None:
        assert issubclass(GroupPostingRefusedError, RineError)

    def test_unreadable_by_orgs_sentence_when_one_then_the_singular(self) -> None:
        assert unreadable_by_orgs_sentence(1) == RULES["sentences"]["unreadable"]["one"]

    @pytest.mark.parametrize("count", [2, 7])
    def test_unreadable_by_orgs_sentence_when_many_then_the_plural_with_the_count(
        self, count: int
    ) -> None:
        assert unreadable_by_orgs_sentence(count) == RULES["sentences"]["unreadable"][
            "many"
        ].replace("{n}", str(count))

    @pytest.mark.parametrize("count", [None, 0])
    def test_unreadable_by_orgs_sentence_when_none_or_zero_then_says_nothing(
        self, count: int | None
    ) -> None:
        assert unreadable_by_orgs_sentence(count) is None

    def test_group_posting_line_when_foreign_open_group_then_the_pinned_line(self) -> None:
        line = group_posting_line(_group(posting_refused="foreign_open_group"))

        assert line == RULES["sentences"]["posting_line"]["foreign_open_group"]

    def test_group_posting_line_when_refused_members_then_the_pinned_line_with_the_count(
        self,
    ) -> None:
        refused = [MEMBER, "cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee"]

        line = group_posting_line(
            _group(posting_refused="refused_members", refused_members=refused)
        )

        assert line == RULES["sentences"]["posting_line"]["refused_members"].replace("{k}", "2")

    @pytest.mark.parametrize("value", [None, "a_refusal_from_a_newer_server"])
    def test_group_posting_line_when_nothing_known_is_refused_then_prints_nothing(
        self, value: str | None
    ) -> None:
        assert group_posting_line(_group(posting_refused=value)) is None


class TestTheGuardOnlyRefusesWhatItCanWord:
    @pytest.mark.parametrize("value", [None, "a_refusal_from_a_newer_server"])
    def test_assert_group_postable_when_unset_or_unknown_then_leaves_it_to_the_server(
        self, value: str | None
    ) -> None:
        assert_group_postable(_group(posting_refused=value))

    def test_posting_refusal_known_when_unknown_then_none(self) -> None:
        assert PostingRefusal.known("a_refusal_from_a_newer_server") is None


class TestTheNewFieldsParse:
    def test_group_read_when_the_server_names_a_refusal_then_carries_it(self) -> None:
        group = _group(posting_refused="refused_members", refused_members=[MEMBER])

        assert group.posting_refused == "refused_members"
        assert [str(m) for m in group.refused_members or []] == [MEMBER]

    def test_group_read_when_an_older_server_omits_them_then_they_are_unset(self) -> None:
        group = _group()

        assert group.posting_refused is None
        assert group.refused_members is None

    def test_message_read_when_the_server_counts_unreadable_orgs_then_carries_it(self) -> None:
        msg = MessageRead.model_validate(_message_row(unreadable_by_orgs=3))

        assert msg.unreadable_by_orgs == 3

    def test_message_read_when_an_older_server_omits_the_count_then_it_is_unset(self) -> None:
        assert MessageRead.model_validate(_message_row()).unreadable_by_orgs is None


def _message_row(**extra: Any) -> dict[str, Any]:
    return {
        "id": "cccccccc-dddd-eeee-ffff-000000000101",
        "conversation_id": "cccccccc-dddd-eeee-ffff-000000000103",
        "type": "rine.v1.task_request",
        "encrypted_payload": "opaque",
        "encryption_version": "sender-key-v1",
        "created_at": "2024-01-01T00:00:00Z",
        "direction": "sent",
        **extra,
    }


@pytest.fixture
def config_dir(tmp_config_dir):
    write_agent_identity(tmp_config_dir, SENDER)
    return tmp_config_dir


@pytest.fixture
def http(config_dir):
    client = SyncHttpClient(config_dir=config_dir, api_url=API)
    yield client
    client.close()


def _serve(config_dir: str, group: dict[str, Any]) -> respx.Route:
    """A server that completes a real fan-out; returns the ``POST /messages`` route."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [group]}))
    respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(200, json={"items": [{"agent_id": MEMBER, "role": "member"}]})
    )
    save_agent_keys(config_dir, MEMBER, WORLD.keys(MEMBER))
    respx.get(f"{API}/agents/{MEMBER}/keys").mock(
        return_value=httpx.Response(200, json=WORLD.keys_response(MEMBER))
    )
    return respx.post(f"{API}/messages").mock(
        return_value=httpx.Response(200, json={"id": "sent", "created_at": "2024-01-01T00:00:00Z"})
    )


class _MlsResult:
    encrypted_payload = "AAAA"
    encryption_version = "mls-v1"
    sender_signing_kid = "kid"


class TestARefusedPostCostsNothing:
    @pytest.mark.parametrize("reason", PostingRefusal)
    @respx.mock
    def test_encrypt_for_group_sync_when_posting_is_refused_then_no_key_leaves_the_machine(
        self, config_dir, http, reason: PostingRefusal
    ) -> None:
        """The fan-out is the cost: one 1:1 message per member before the server could say no."""
        wire = _serve(config_dir, _group_row(posting_refused=reason.value))

        with pytest.raises(GroupPostingRefusedError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert wire.call_count == 0

    @respx.mock
    def test_encrypt_for_group_sync_when_posting_is_not_refused_then_the_control_arm_fans_out(
        self, config_dir, http
    ) -> None:
        wire = _serve(config_dir, _group_row())

        result, _group_row_read = encrypt_for_group_sync(
            http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD
        )

        assert result.encryption_version == "sender-key-v1"
        assert wire.call_count == 1

    @respx.mock
    def test_encrypt_for_group_sync_when_the_group_is_mls_and_refused_then_nothing_is_sealed(
        self, config_dir, http, monkeypatch
    ) -> None:
        sealed: list[object] = []
        monkeypatch.setattr(
            "rine._mls.messages.encrypt_mls_group_message",
            lambda *args, **kwargs: sealed.append(args) or _MlsResult(),
        )
        wire = _serve(
            config_dir,
            _group_row(mls_group_id="latched", posting_refused="refused_members"),
        )

        with pytest.raises(GroupPostingRefusedError):
            encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert sealed == []
        assert wire.call_count == 0

    @respx.mock
    def test_encrypt_for_group_sync_when_the_server_value_is_unknown_then_the_post_goes_out(
        self, config_dir, http
    ) -> None:
        wire = _serve(config_dir, _group_row(posting_refused="a_refusal_from_a_newer_server"))

        result, _ = encrypt_for_group_sync(http, config_dir, SENDER, GROUP_HANDLE, PAYLOAD)

        assert result.encryption_version == "sender-key-v1"
        assert wire.call_count == 1
