"""A sender-key distribution DM cannot name its own sender.

The envelope's signature is verified against ``from_agent_id`` — the id the
SERVER stamped on the row the DM was listed as — while the payload inside it is
the sender's own plaintext. The Python ingest used to take the stored row's
``sender_agent_id`` from that plaintext and never compare the two, so any agent
that could DM this one and knew the group's UUID — every current and every
FORMER member of the group — could plant a row claiming to be the reader's OWN
sender key. Being the last own row in the file, it is then exactly what the next
group send selects: this agent fans the planter's chain key out to the whole
group as its own and seals under it, and ``needs_rotation`` can never retire it
because an ingested row carries no ``created_at``.

The row's identity now comes from ``agent_id_from_kid(result.sender_kid)``, the
signer the verify actually established — which is what
``rine-core/src/crypto/ingest.ts`` has always done, and this stack's divergence
from it WAS the hole. Both clients carried it, so both are driven here: the real
``_scan_pending_sk_distributions``, a genuinely sealed and signed DM, and only
the network standing in.

🔴 The load-bearing assertion is not where the row lands, it is what the next
send SELECTS. A fix that bound the row correctly and left the selector reaching
the planted key would satisfy a file-shape assertion and still hand the group
away, so every planting test here ends at
:func:`rine._sender_key_ops.get_or_create_sender_key_sync` — the selector BOTH
clients use, since the async send runs that same sync function on a worker
thread (``rine._client.RineClient.send`` → ``rine._group_send.encrypt_for_group_sync``).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._constants import MessageType
from rine._crypto._agent_keys import recipient_keys_from_response
from rine._crypto.keys import (
    generate_agent_keys,
    load_agent_keys,
    public_keys_body,
    save_agent_keys,
)
from rine._crypto.message import encrypt_message
from rine._crypto.sender_keys import generate_sender_key
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._http import SyncHttpClient
from rine._sender_key_ops import get_or_create_sender_key_sync
from rine._utils import to_base64url

API = "https://rine.network"
#: Any agent that can DM the reader. It never has to be a member to send the DM.
ATTACKER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
#: A seated peer, and the honest half's sender.
MEMBER_A_ID = "11111111-2222-4333-8444-555555555555"
MEMBER_B_ID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
GROUP_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
GROUP_HANDLE = "#ops@myorg.rine.network"
DISTRIBUTION_ID = "99999999-8888-4777-8666-555555555555"
#: The key id the DM carries — distinct from the reader's own, so the ingest's
#: "already have it" short-circuit does not decide the test.
ARRIVING_KEY_ID = "12345678-1234-4234-8234-123456789abc"
#: Recognisable material: a chain key the reader must never seal under.
ARRIVING_CHAIN_KEY = bytes(range(32))


@pytest.fixture
def foreign_config_dir(tmp_path):
    """A config dir that is NOT the reader's, where another agent holds its keys.

    Sealing needs the SENDER's private signing key, and putting it in the
    reader's own dir would let a test pass on material no attacker has.
    """
    path = tmp_path / "foreign"
    path.mkdir()
    return str(path)


def _agent(config_dir: str, agent_id: str) -> dict:
    """Mint one agent's keys into *config_dir* and return their published form."""
    keys = generate_agent_keys()
    save_agent_keys(config_dir, agent_id, keys)
    return public_keys_body(keys)


def _distribution_row(
    foreign_dir: str,
    signer_id: str,
    reader_dir: str,
    reader_id: str,
    claimed_sender_agent_id: str,
) -> dict:
    """A real ``rine.v1.sender_key_distribution`` DM, sealed and SIGNED by *signer_id*.

    Everything here is genuine — the HPKE seal, the Ed25519 signature and the
    ``from_agent_id`` the server would stamp. The single field under the
    sender's sole control is ``sender_agent_id``, which lives inside the
    plaintext and is what this file is about.
    """
    sealed = encrypt_message(
        foreign_dir,
        signer_id,
        recipient_keys_from_response(public_keys_body(load_agent_keys(reader_dir, reader_id))),
        {
            "group_id": GROUP_ID,
            "sender_key_id": ARRIVING_KEY_ID,
            "chain_key": to_base64url(ARRIVING_CHAIN_KEY),
            "message_index": 0,
            "sender_agent_id": claimed_sender_agent_id,
        },
    )
    return {
        "id": DISTRIBUTION_ID,
        "conversation_id": "cccccccc-dddd-eeee-ffff-000000000103",
        "from_agent_id": signer_id,
        "to_agent_id": reader_id,
        "type": MessageType.SENDER_KEY_DISTRIBUTION,
        "encrypted_payload": sealed.encrypted_payload,
        "encryption_version": sealed.encryption_version,
        "sender_signing_kid": sealed.sender_signing_kid,
        "created_at": "2024-01-01T00:00:00Z",
    }


def _stand_up(reader_dir: str, reader_id: str, foreign_dir: str, signer_id: str, claims: str):
    """One group, one arriving DM, and every route the ingest and next send read.

    The reader already holds its own genuine, fully distributed sender key, so
    the next send has no honest reason to fan anything out — which is what makes
    ``POST /messages`` a usable assertion.

    Returns the reader's genuine key and the ``POST /messages`` route.
    """
    genuine = generate_sender_key(GROUP_ID, reader_id)
    genuine.distributed_to = [MEMBER_A_ID, MEMBER_B_ID]
    save_sender_key_state(reader_dir, reader_id, GROUP_ID, [genuine])

    published = {
        agent: _agent(foreign_dir, agent)
        for agent in dict.fromkeys([signer_id, MEMBER_A_ID, MEMBER_B_ID])
    }
    row = _distribution_row(foreign_dir, signer_id, reader_dir, reader_id, claims)

    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(
        f"{API}/agents/{reader_id}/messages",
        params={"type": MessageType.SENDER_KEY_DISTRIBUTION},
    ).mock(return_value=httpx.Response(200, json={"items": [{"id": row["id"]}], "total": 1}))
    respx.get(f"{API}/messages/{row['id']}").mock(return_value=httpx.Response(200, json=row))
    for agent, body in published.items():
        respx.get(f"{API}/agents/{agent}/keys").mock(
            return_value=httpx.Response(200, json={"agent_id": agent, **body})
        )
    respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {"agent_id": agent, "role": "member"}
                    for agent in (reader_id, MEMBER_A_ID, MEMBER_B_ID)
                ]
            },
        )
    )
    posts = respx.post(f"{API}/messages").mock(
        return_value=httpx.Response(200, json={"id": "dddddddd-eeee-4fff-8000-111111111111"})
    )
    return genuine, posts


def _rows(reader_dir: str, reader_id: str) -> dict:
    """The group's state file as it stands, keyed by sender key id."""
    return {s.sender_key_id: s for s in load_sender_key_states(reader_dir, reader_id, GROUP_ID)}


def _next_send_key(reader_dir: str, reader_id: str):
    """What this agent's NEXT group send would seal under.

    Through the selector itself rather than by reading the file: "the last own
    row" is the selector's rule, not the file's, and asserting the file's shape
    would leave the consequence — which key the group is handed — unasserted.
    """
    http = SyncHttpClient(config_dir=reader_dir, api_url=API)
    try:
        return get_or_create_sender_key_sync(
            http, reader_dir, reader_id, {"id": GROUP_ID, "handle": GROUP_HANDLE}
        )
    finally:
        http.close()


class TestAPlantedSenderKey:
    """A DM whose payload claims to be the READER's own key, from an agent that is not."""

    @respx.mock
    def test_sync_ingest_when_the_payload_claims_the_readers_id_then_the_row_is_the_signers(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The row is bound to whoever signed the envelope, and to nobody else."""
        _stand_up(tmp_config_dir, agent_id, foreign_config_dir, ATTACKER_ID, claims=agent_id)

        scan = sync_client._scan_pending_sk_distributions(agent_id)

        # The DM is well-formed and genuinely signed, so it IS ingested — the
        # defence is the identity it is filed under, not a refusal.
        assert scan.ingested == 1
        assert _rows(tmp_config_dir, agent_id)[ARRIVING_KEY_ID].sender_agent_id == ATTACKER_ID

    @respx.mock
    async def test_async_ingest_when_the_payload_claims_the_readers_id_then_the_row_is_the_signers(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The async client had its own copy of the line, so it needs its own gate."""
        _stand_up(tmp_config_dir, agent_id, foreign_config_dir, ATTACKER_ID, claims=agent_id)

        scan = await async_client._scan_pending_sk_distributions(agent_id)

        assert scan.ingested == 1
        assert _rows(tmp_config_dir, agent_id)[ARRIVING_KEY_ID].sender_agent_id == ATTACKER_ID

    @respx.mock
    def test_sync_send_when_a_key_was_planted_as_the_readers_own_then_it_is_not_selected(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """🔴 The assertion that matters: the group is still sealed under this agent's key.

        A planted row bound to the reader is the LAST own row in the file, which
        is precisely what the selector returns — so the next send seals under the
        planter's chain key and DMs it to every member as this agent's own. Both
        halves are asserted: the key chosen, and the fan-out that would carry it.
        """
        genuine, posts = _stand_up(
            tmp_config_dir, agent_id, foreign_config_dir, ATTACKER_ID, claims=agent_id
        )
        assert sync_client._scan_pending_sk_distributions(agent_id).ingested == 1

        picked = _next_send_key(tmp_config_dir, agent_id)

        assert picked.sender_key_id == genuine.sender_key_id
        assert picked.chain_key != ARRIVING_CHAIN_KEY
        # The reader's own key already reached both members, so an honest send
        # distributes nothing. Anything here is the planted key going out.
        assert posts.call_count == 0

    @respx.mock
    async def test_async_send_when_a_key_was_planted_as_the_readers_own_then_it_is_not_selected(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The same consequence, reached through the async client's own ingest.

        The selector is deliberately the sync one on both: an async group send
        runs ``encrypt_for_group_sync`` on a worker thread, so this IS the async
        send path's key choice and not a stand-in for it.
        """
        genuine, posts = _stand_up(
            tmp_config_dir, agent_id, foreign_config_dir, ATTACKER_ID, claims=agent_id
        )
        assert (await async_client._scan_pending_sk_distributions(agent_id)).ingested == 1

        picked = _next_send_key(tmp_config_dir, agent_id)

        assert picked.sender_key_id == genuine.sender_key_id
        assert picked.chain_key != ARRIVING_CHAIN_KEY
        assert posts.call_count == 0


class TestAnHonestDistribution:
    """The other half: a peer distributing its own key is still ingested, under its own id."""

    @respx.mock
    def test_sync_ingest_when_the_peer_names_itself_then_the_key_lands_under_that_peer(
        self, sync_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """Deriving the id from the kid must not cost the reader its peers' keys."""
        _stand_up(tmp_config_dir, agent_id, foreign_config_dir, MEMBER_A_ID, claims=MEMBER_A_ID)

        scan = sync_client._scan_pending_sk_distributions(agent_id)

        assert scan.ingested == 1
        arrived = _rows(tmp_config_dir, agent_id)[ARRIVING_KEY_ID]
        assert arrived.sender_agent_id == MEMBER_A_ID
        # The material itself, not just the label: this row is what opens that
        # peer's group posts.
        assert arrived.chain_key == ARRIVING_CHAIN_KEY

    @respx.mock
    async def test_async_ingest_when_the_peer_names_itself_then_the_key_lands_under_that_peer(
        self, async_client, tmp_config_dir, agent_id, foreign_config_dir
    ):
        """The async twin of the honest path."""
        _stand_up(tmp_config_dir, agent_id, foreign_config_dir, MEMBER_A_ID, claims=MEMBER_A_ID)

        scan = await async_client._scan_pending_sk_distributions(agent_id)

        assert scan.ingested == 1
        arrived = _rows(tmp_config_dir, agent_id)[ARRIVING_KEY_ID]
        assert arrived.sender_agent_id == MEMBER_A_ID
        assert arrived.chain_key == ARRIVING_CHAIN_KEY
