"""What the ingest still takes from a distribution's plaintext, and what it must not.

The envelope's signature binds ``from_agent_id`` and the stored row's identity now
comes from the verified kid — but ``group_id``, ``sender_key_id``, ``chain_key`` and
``message_index`` are all still the sender's own plaintext, and the ingest acted on
each of them unchecked. Three consequences, all reachable by any agent that can DM
this one:

* **The key-id squat.** The duplicate check was global on ``sender_key_id``, so the
  FIRST distribution to claim an id owned that slot and every later one — including
  the genuine owner's — was silently skipped. The attacker learns the id from its own
  copy of the peer's distribution, and the inbox lists newest-first, so a shadow sent
  afterwards is processed first. The peer's group traffic is then permanently
  unreadable, surfacing as the sealed-message refusal.
* **The split path namespace.** The state file was named for the id as spelled in the
  payload while every honest reader passes the server's lower-case spelling, so an
  upper-cased ``group_id`` wrote a file no reader and no leave-time cleanup would ever
  look at.
* **Unbounded fields.** A ``chain_key`` of any length and a negative, enormous or
  non-integer ``message_index`` were all stored verbatim, though the wire format
  admits exactly 32 bytes and a uint32.

🔴 The load-bearing assertion for the squat is a real DECRYPT of the honest member's
group post, never the shape of the state file: a fix that files the shadow row
correctly and still leaves the slot taken would satisfy a shape assertion and leave
the group unreadable. Every probe here drives the real
``_scan_pending_sk_distributions`` on the client under test with only the network
mocked, and the other agents' private keys live in a config dir the reader does not
own — so nothing passes on material a real attacker would not hold.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest
import respx

from rine import _client as async_client_module
from rine import _sync_client as sync_client_module
from rine._constants import MessageType
from rine._crypto._agent_keys import recipient_keys_from_response
from rine._crypto.keys import (
    generate_agent_keys,
    load_agent_keys,
    public_keys_body,
    save_agent_keys,
)
from rine._crypto.message import (
    decrypt_group_message_sync,
    encrypt_group_message,
    encrypt_message,
)
from rine._crypto.sender_keys import generate_sender_key
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._http import SyncHttpClient
from rine._utils import to_base64url
from tests.conftest import sender_key_region_is_held_here

API = "https://rine.network"
#: Any agent that can DM the reader — it never has to be a member to send the DM.
ATTACKER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
#: The honest peer whose group traffic the squat denies.
MEMBER_A_ID = "11111111-2222-4333-8444-555555555555"
GROUP_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
GROUP_POST = {"text": "the group secret"}
HONEST_DM_ID = "99999999-8888-4777-8666-555555555555"
SECOND_DM_ID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
UNRELATED_KEY_ID = "12345678-1234-4234-8234-123456789abc"
#: Material the reader must never mistake for the honest peer's.
SHADOW_CHAIN_KEY = bytes(range(32))


@pytest.fixture
def foreign_config_dir(tmp_path):
    """A config dir that is NOT the reader's, where the other agents hold their keys.

    Sealing and signing need the SENDER's private keys, and putting them in the
    reader's own dir would let a probe pass on material no attacker has.
    """
    path = tmp_path / "foreign"
    path.mkdir()
    return str(path)


@dataclass(frozen=True)
class HonestKey:
    """Member A's genuine key: the DM that distributes it and one post sealed under it."""

    key_id: str
    row: dict
    post: str


def _publish(config_dir: str, agent_id: str) -> dict:
    """Mint one agent's keys into *config_dir* and return their published form."""
    keys = generate_agent_keys()
    save_agent_keys(config_dir, agent_id, keys)
    return public_keys_body(keys)


def _distribution(
    foreign_dir: str,
    signer_id: str,
    reader_dir: str,
    reader_id: str,
    message_id: str,
    payload: dict,
) -> dict:
    """A real ``rine.v1.sender_key_distribution`` DM, sealed and SIGNED by *signer_id*.

    The HPKE seal, the Ed25519 signature and the ``from_agent_id`` the server would
    stamp are all genuine; *payload* is the part under the sender's sole control.
    """
    sealed = encrypt_message(
        foreign_dir,
        signer_id,
        recipient_keys_from_response(public_keys_body(load_agent_keys(reader_dir, reader_id))),
        payload,
    )
    return {
        "id": message_id,
        "conversation_id": "cccccccc-dddd-eeee-ffff-000000000103",
        "from_agent_id": signer_id,
        "to_agent_id": reader_id,
        "type": MessageType.SENDER_KEY_DISTRIBUTION,
        "encrypted_payload": sealed.encrypted_payload,
        "encryption_version": sealed.encryption_version,
        "sender_signing_kid": sealed.sender_signing_kid,
        "created_at": "2024-01-01T00:00:00Z",
    }


def _register(reader_id: str, rows: list[dict], published: dict[str, dict]) -> None:
    """Every route the ingest and the follow-up group decrypt read.

    *rows* is listed in the order given — the server lists the distribution inbox
    newest-first (``src/rine/api/messages.py`` orders by ``created_at DESC``) and the
    scan imposes no ordering of its own, which is what makes the squat winnable with
    no race at all.
    """
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(
        f"{API}/agents/{reader_id}/messages",
        params={"type": MessageType.SENDER_KEY_DISTRIBUTION},
    ).mock(
        return_value=httpx.Response(
            200, json={"items": [{"id": row["id"]} for row in rows], "total": len(rows)}
        )
    )
    for row in rows:
        respx.get(f"{API}/messages/{row['id']}").mock(return_value=httpx.Response(200, json=row))
    for agent, body in published.items():
        respx.get(f"{API}/agents/{agent}/keys").mock(
            return_value=httpx.Response(200, json={"agent_id": agent, **body})
        )


def _stand_up(foreign_dir: str, reader_dir: str, reader_id: str) -> tuple[dict, HonestKey]:
    """Both peers' published keys, plus Member A's key, its DM and one post under it."""
    published = {a: _publish(foreign_dir, a) for a in (ATTACKER_ID, MEMBER_A_ID)}
    state = generate_sender_key(GROUP_ID, MEMBER_A_ID)
    payload = {
        "group_id": GROUP_ID,
        "sender_key_id": state.sender_key_id,
        "chain_key": to_base64url(state.chain_key),
        "message_index": state.message_index,
        "sender_agent_id": MEMBER_A_ID,
    }
    # The send path refuses to seal under state nothing persisted, so Member A holds
    # its own key exactly as a real sender does.
    save_sender_key_state(foreign_dir, MEMBER_A_ID, GROUP_ID, [state])
    sealed, _ = encrypt_group_message(foreign_dir, MEMBER_A_ID, GROUP_ID, state, GROUP_POST)
    row = _distribution(foreign_dir, MEMBER_A_ID, reader_dir, reader_id, HONEST_DM_ID, payload)
    return published, HonestKey(state.sender_key_id, row, sealed.encrypted_payload)


def _forged(
    foreign_dir: str, reader_dir: str, reader_id: str, signer_id: str, **payload_overrides
) -> dict:
    """A second distribution DM, genuinely signed by *signer_id*, contents chosen freely."""
    payload = {
        "group_id": GROUP_ID,
        "sender_key_id": UNRELATED_KEY_ID,
        "chain_key": to_base64url(SHADOW_CHAIN_KEY),
        "message_index": 0,
        "sender_agent_id": signer_id,
        **payload_overrides,
    }
    return _distribution(foreign_dir, signer_id, reader_dir, reader_id, SECOND_DM_ID, payload)


def _read_group_post(reader_dir: str, reader_id: str, encrypted_payload: str) -> str:
    """What the reader gets when it opens Member A's post — the whole point."""
    http = SyncHttpClient(config_dir=reader_dir, api_url=API)
    try:
        return decrypt_group_message_sync(
            reader_dir, reader_id, GROUP_ID, encrypted_payload, http, MEMBER_A_ID
        ).plaintext
    finally:
        http.close()


def _rows(reader_dir: str, reader_id: str) -> list:
    """The group's state file as it stands, in file order, under the canonical id."""
    return load_sender_key_states(reader_dir, reader_id, GROUP_ID)


class TestTheKeyIdSquat:
    """One sender must not be able to occupy the slot another sender needs."""

    @respx.mock
    def test_control_when_no_shadow_is_sent_then_the_peers_post_opens(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The load-bearing control: this harness CAN decrypt, so a refusal is the attack."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        _register(agent_id, [honest.row], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1

        assert "the group secret" in _read_group_post(tmp_config_dir, agent_id, honest.post)

    @respx.mock
    def test_sync_ingest_when_a_shadow_squats_the_peers_key_id_then_the_post_still_opens(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """🔴 The assertion that matters: the honest member is still readable.

        The shadow is listed first because it was sent later, so under a dedup that is
        global on ``sender_key_id`` it takes the slot and Member A's genuine
        distribution is skipped — permanently, since every re-scan re-skips it.
        """
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        shadow = _forged(
            foreign_config_dir,
            tmp_config_dir,
            agent_id,
            ATTACKER_ID,
            sender_key_id=honest.key_id,
        )
        _register(agent_id, [shadow, honest.row], published)

        scan = sync_client._scan_pending_sk_distributions(agent_id)

        # Both are genuinely signed DMs, so both are ingested — the defence is that
        # neither sender can displace the other, not a refusal.
        assert scan.ingested == 2
        assert {(s.sender_agent_id, s.sender_key_id) for s in _rows(tmp_config_dir, agent_id)} == {
            (ATTACKER_ID, honest.key_id),
            (MEMBER_A_ID, honest.key_id),
        }
        assert "the group secret" in _read_group_post(tmp_config_dir, agent_id, honest.post)

    @respx.mock
    async def test_async_ingest_when_a_shadow_squats_the_peers_key_id_then_the_post_still_opens(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The async client carries its own copy of the loop, so it needs its own gate."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        shadow = _forged(
            foreign_config_dir,
            tmp_config_dir,
            agent_id,
            ATTACKER_ID,
            sender_key_id=honest.key_id,
        )
        _register(agent_id, [shadow, honest.row], published)

        scan = await async_client._scan_pending_sk_distributions(agent_id)

        assert scan.ingested == 2
        assert "the group secret" in _read_group_post(tmp_config_dir, agent_id, honest.post)

    @respx.mock
    def test_ingest_when_one_sender_repeats_its_own_key_id_then_it_is_still_deduped(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """Scoping the check per sender must not turn a re-send into a second row."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        again = dict(honest.row, id=SECOND_DM_ID)
        _register(agent_id, [honest.row, again], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1
        assert len(_rows(tmp_config_dir, agent_id)) == 1


class TestTheIngestTakesItsRegion:
    """Both clients append inside the state file's lock, not merely atomically.

    The ingest is a load, an append and a save of the WHOLE array — an assert,
    not a merge — so anything that landed between its load and its save is
    discarded. What lands there is the worst possible thing to lose: a rotation
    fanning a fresh key out to the group runs its own whole-array write from a
    worker thread, and an unlocked append erases it. The peers then hold a key
    the sender has retired and every later post reads as sealed, with nothing in
    the file to say which write won.

    Neither client could be serialised by the loop tier alone, which is why this
    pins the region rather than the atomic save: the async client's group send
    runs on a worker thread that no :class:`asyncio.Lock` reaches, and a host
    driving a sync client and an async one on two threads used to race here
    outright.
    """

    @respx.mock
    def test_sync_ingest_when_it_writes_then_the_region_is_held(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir, monkeypatch
    ):
        """Asked from inside the write, because the bytes cannot tell the difference."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        _register(agent_id, [honest.row], published)
        held: list[bool] = []
        real = sync_client_module.save_sender_key_state

        def watched(config_dir, writer_id, gid, states):
            held.append(sender_key_region_is_held_here(config_dir, writer_id, gid))
            return real(config_dir, writer_id, gid, states)

        monkeypatch.setattr(sync_client_module, "save_sender_key_state", watched)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1

        assert held == [True]
        # And the ingest is still correct with the writer wrapped, so a passing
        # region assertion is never a passing assertion over a dead code path.
        assert "the group secret" in _read_group_post(tmp_config_dir, agent_id, honest.post)

    @respx.mock
    async def test_async_ingest_when_it_writes_then_the_region_is_held(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir, monkeypatch
    ):
        """The async client's own copy, which is the one the send races."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        _register(agent_id, [honest.row], published)
        held: list[bool] = []
        real = async_client_module.save_sender_key_state

        def watched(config_dir, writer_id, gid, states):
            held.append(sender_key_region_is_held_here(config_dir, writer_id, gid))
            return real(config_dir, writer_id, gid, states)

        monkeypatch.setattr(async_client_module, "save_sender_key_state", watched)

        assert (await async_client._scan_pending_sk_distributions(agent_id)).ingested == 1

        assert held == [True]
        assert "the group secret" in _read_group_post(tmp_config_dir, agent_id, honest.post)


class TestTheGroupIdNamespace:
    """One logical group is one state file, however the payload spells its id."""

    @respx.mock
    def test_ingest_when_the_payload_upper_cases_the_group_id_then_the_row_is_still_found(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """A reader passes the SERVER's spelling; the payload's must reach the same file."""
        published = {a: _publish(foreign_config_dir, a) for a in (ATTACKER_ID, MEMBER_A_ID)}
        row = _forged(
            foreign_config_dir,
            tmp_config_dir,
            agent_id,
            MEMBER_A_ID,
            group_id=GROUP_ID.upper(),
        )
        _register(agent_id, [row], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1

        # Read back under the canonical spelling — what every honest reader, and the
        # leave-time cleanup, actually passes.
        assert [s.sender_key_id for s in _rows(tmp_config_dir, agent_id)] == [UNRELATED_KEY_ID]

    @respx.mock
    def test_ingest_when_a_second_spelling_repeats_a_key_id_then_it_does_not_re_open_the_slot(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """A per-spelling namespace makes "we already hold that key" a local statement."""
        published, honest = _stand_up(foreign_config_dir, tmp_config_dir, agent_id)
        upper = _forged(
            foreign_config_dir,
            tmp_config_dir,
            agent_id,
            MEMBER_A_ID,
            group_id=GROUP_ID.upper(),
            sender_key_id=honest.key_id,
        )
        _register(agent_id, [honest.row, upper], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1
        assert len(_rows(tmp_config_dir, agent_id)) == 1


class TestTheUnboundedFields:
    """``chain_key`` and ``message_index`` are wire-format constrained, so check them."""

    @pytest.mark.parametrize(
        ("label", "overrides"),
        [
            ("empty chain key", {"chain_key": to_base64url(b"")}),
            ("short chain key", {"chain_key": to_base64url(b"\x01")}),
            ("1 MiB chain key", {"chain_key": to_base64url(b"\x00" * 1024 * 1024)}),
            ("negative index", {"message_index": -5}),
            ("index past uint32", {"message_index": 2**62}),
            ("non-integer index", {"message_index": "0"}),
            # ``True`` is an ``int`` in Python and would ratchet silently to 1.
            ("boolean index", {"message_index": True}),
            # Absent means "starts at zero"; an explicit null is a value the sender
            # chose, and the TypeScript twin refuses it for the same reason.
            ("null index", {"message_index": None}),
            ("key id that is a path", {"sender_key_id": "../../../etc/passwd"}),
            ("key id that is not an id", {"sender_key_id": 17}),
        ],
    )
    @respx.mock
    def test_ingest_when_a_field_is_out_of_range_then_nothing_is_written(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir, label, overrides
    ):
        """Storing these costs the reader disk and buys the sender a cheaper denial."""
        published = {a: _publish(foreign_config_dir, a) for a in (ATTACKER_ID, MEMBER_A_ID)}
        row = _forged(foreign_config_dir, tmp_config_dir, agent_id, ATTACKER_ID, **overrides)
        _register(agent_id, [row], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 0, label
        assert _rows(tmp_config_dir, agent_id) == []

    @respx.mock
    def test_ingest_when_the_index_is_a_real_mid_stream_position_then_it_is_kept(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """A peer distributing mid-stream sends a non-zero index; refusing it would break."""
        published = {a: _publish(foreign_config_dir, a) for a in (ATTACKER_ID, MEMBER_A_ID)}
        row = _forged(foreign_config_dir, tmp_config_dir, agent_id, MEMBER_A_ID, message_index=7)
        _register(agent_id, [row], published)

        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1
        assert _rows(tmp_config_dir, agent_id)[0].message_index == 7
