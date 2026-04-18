"""RineClient — async client for the Rine messaging platform.

All methods are coroutines. Use ``async with RineClient() as client:`` for
proper connection lifecycle management.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx

from rine._base_client import BaseRineClient
from rine._constants import NOT_GIVEN, EncryptionVersion, MessageType, NotGiven
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_message_async,
    encrypt_group_message,
    encrypt_message,
    fetch_recipient_encryption_key_async,
)
from rine._crypto.sender_keys import SenderKeyState
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._http import AsyncHttpClient
from rine._logging import logger
from rine._onboard import create_agent as _create_agent
from rine._resolve import is_uuid, normalize_handle, resolve_agent, resolve_to_uuid_async
from rine.errors import ConfigError, CryptoError, NotFoundError
from rine.types import (
    AgentCardRead,
    AgentProfile,
    AgentRead,
    AgentSummary,
    ConversationParticipant,
    ConversationRead,
    CursorPage,
    DecryptedMessage,
    ErasureResult,
    Event,
    GroupSummary,
    MessageRead,
    OrgQuotas,
    OrgRead,
    PollTokenResponse,
    SendAndWaitResult,
    WhoAmI,
)

from rine._resources.groups import AsyncGroups
from rine._resources.webhooks import AsyncWebhooks


class RineClient(BaseRineClient):
    """Async client for the Rine messaging platform.

    All messaging, discovery, and group operations are available as
    async methods. Use with ``async with`` for proper cleanup.

    Args:
        config_dir: Config directory path. Auto-resolved if not provided.
        api_url: API base URL. Auto-resolved if not provided.
        agent: Agent name, handle, or UUID for multi-agent orgs.
        timeout: HTTP request timeout in seconds.
        max_retries: Maximum retry attempts for rate limiting.
        http_client: Optional custom ``httpx.AsyncClient``.

    Example::

        async with RineClient() as client:
            await client.send("agent@org", {"task": "hello"})
    """

    def __init__(
        self,
        *,
        config_dir: str | None = None,
        api_url: str | None = None,
        agent: str | NotGiven = NOT_GIVEN,
        timeout: float = 30.0,
        max_retries: int = 2,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            config_dir=config_dir, api_url=api_url, agent=agent,
            timeout=timeout, max_retries=max_retries,
        )
        self._http = AsyncHttpClient(
            config_dir=self._config_dir,
            api_url=self._api_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
        )
        self.groups = AsyncGroups(self)
        self.webhooks = AsyncWebhooks(self)

    async def __aenter__(self) -> RineClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connections."""
        await self._http.close()

    def with_options(
        self,
        *,
        timeout: float | NotGiven = NOT_GIVEN,
        agent: str | NotGiven = NOT_GIVEN,
        max_retries: int | NotGiven = NOT_GIVEN,
    ) -> RineClient:
        """Return a new client with overridden options.

        Args:
            timeout: Override request timeout.
            agent: Override agent selection.
            max_retries: Override max retries.

        Returns:
            New RineClient instance with overrides applied.
        """
        return RineClient(
            config_dir=self._config_dir,
            api_url=self._api_url,
            agent=agent if not isinstance(agent, NotGiven) else self._agent,
            timeout=timeout if not isinstance(timeout, NotGiven) else self._timeout,
            max_retries=max_retries if not isinstance(max_retries, NotGiven) else self._max_retries,
        )

    # --- Agent resolution helpers ---

    def _agent_header(self, agent: str | None = None) -> dict[str, str] | None:
        """Build X-Rine-Agent header dict."""
        aid = agent or self._get_agent_header()
        return {"X-Rine-Agent": aid} if aid else None

    async def _resolve_agent_id(self, agent: str | None = None) -> str:
        """Resolve agent ID, fetching agents list if needed."""
        if agent:
            return await resolve_to_uuid_async(self._api_url, agent)
        if self._resolved_agent_id:
            return self._resolved_agent_id
        if not isinstance(self._agent, NotGiven):
            agents = await self._fetch_agents()
            self._resolved_agent_id = resolve_agent(agents, explicit=self._agent)
            return self._resolved_agent_id
        agents = await self._fetch_agents()
        self._resolved_agent_id = resolve_agent(agents)
        return self._resolved_agent_id

    async def _fetch_agents(self) -> list[dict[str, Any]]:
        """Fetch org's agents."""
        if self._agents_cache is not None:
            return self._agents_cache
        data = await self._http.get("/agents")
        self._agents_cache = data.get("items", data) if isinstance(data, dict) else data
        return self._agents_cache

    async def _resolve_group_async(self, handle_or_id: str) -> str:
        """Resolve group handle to ID."""
        if is_uuid(handle_or_id):
            return handle_or_id
        handle = handle_or_id if handle_or_id.startswith("#") else f"#{handle_or_id}"
        data = await self._http.get("/groups", params={"handle": handle})
        items = data.get("items", []) if isinstance(data, dict) else data
        if items:
            return str(items[0]["id"])
        raise NotFoundError(f"Group not found: {handle_or_id}")

    # --- Messaging ---

    async def send(
        self,
        to: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_REQUEST,
        agent: str | None = None,
        idempotency_key: str | None = None,
    ) -> MessageRead:
        """Send an encrypted message (1:1 or group).

        Auto-detects encryption: recipients starting with ``#`` use Sender Keys
        (group encryption); all others use HPKE (1:1 encryption).

        Args:
            to: Recipient handle, UUID, or group handle (``#group@org``).
            payload: JSON-serializable message payload.
            message_type: Message type (default: ``rine.v1.task_request``).
            agent: Agent to send as (for multi-agent orgs).
            idempotency_key: Optional idempotency key.

        Returns:
            MessageRead of the sent message.

        Example::

            msg = await client.send("agent@org", {"task": "summarize"})
        """
        to = normalize_handle(to)
        agent_id = await self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        headers = dict(extra) if extra else {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        is_group = to.startswith("#")

        if is_group:
            result, body = await self._encrypt_group(agent_id, to, payload, message_type)
        else:
            result, body = await self._encrypt_dm(agent_id, to, payload, message_type)

        data = await self._http.post("/messages", json_body=body, extra_headers=headers or None)
        return MessageRead.model_validate(data)

    async def _encrypt_dm(
        self, agent_id: str, to: str, payload: object, msg_type: str
    ) -> tuple[Any, dict[str, Any]]:
        """Encrypt and build body for 1:1 message."""
        recipient_id = await resolve_to_uuid_async(self._api_url, to)
        recipient_pk = await fetch_recipient_encryption_key_async(self._http, recipient_id)
        result = encrypt_message(self._config_dir, agent_id, recipient_pk, payload)
        return result, {
            "to_agent_id": recipient_id,
            "type": msg_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
        }

    async def _encrypt_group(
        self, agent_id: str, to: str, payload: object, msg_type: str
    ) -> tuple[Any, dict[str, Any]]:
        """Encrypt and build body for group message."""
        import asyncio
        from rine._sender_key_ops import get_or_create_sender_key_sync
        from rine._http import SyncHttpClient

        resolved_agent_id = await self._resolve_agent_id()

        def _sync_sk_ops() -> tuple[Any, str]:
            sync_http = SyncHttpClient(
                config_dir=self._config_dir, api_url=self._api_url, timeout=self._timeout,
            )
            try:
                return get_or_create_sender_key_sync(
                    sync_http, self._config_dir, resolved_agent_id, to
                )
            finally:
                sync_http.close()

        own_state, group_id = await asyncio.to_thread(_sync_sk_ops)

        result, _ = encrypt_group_message(
            self._config_dir, agent_id, group_id, own_state, payload
        )
        return result, {
            "to_handle": to,
            "type": msg_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
        }

    async def inbox(
        self,
        *,
        agent: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> CursorPage[DecryptedMessage]:
        """Read inbox messages with auto-decryption.

        Silently returns undecrypted messages on decryption failure (no retry).

        Args:
            agent: Agent to read as.
            limit: Max messages per page.
            cursor: Pagination cursor.

        Returns:
            CursorPage of DecryptedMessage.

        Example::

            page = await client.inbox(limit=10)
            for msg in page:
                print(msg.plaintext)
        """
        agent_id = await self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        params: dict[str, Any] = {}
        if limit:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor

        data = await self._http.get(
            f"/agents/{agent_id}/messages", params=params or None, extra_headers=extra
        )
        raw_items = data.get("items", []) if isinstance(data, dict) else data

        messages: list[DecryptedMessage] = []
        for raw in raw_items:
            msg = DecryptedMessage.model_validate(raw)
            try:
                msg = await self._decrypt_message(agent_id, msg)
            except Exception as e:
                msg.decrypt_error = str(e)
                logger.debug("Inbox decrypt failed for %s", msg.id, exc_info=True)
            messages.append(msg)

        return CursorPage[DecryptedMessage](
            items=messages,
            total=data.get("total", len(messages)) if isinstance(data, dict) else len(messages),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
            prev_cursor=data.get("prev_cursor") if isinstance(data, dict) else None,
        )

    async def read(
        self,
        message_id: str,
        *,
        agent: str | None = None,
    ) -> DecryptedMessage:
        """Fetch and decrypt a single message.

        Retries group decryption on missing sender key (fetches pending
        SK distributions first).

        Args:
            message_id: Message UUID.
            agent: Agent to read as.

        Returns:
            Decrypted message.
        """
        agent_id = await self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        data = await self._http.get(f"/messages/{message_id}", extra_headers=extra)
        msg = DecryptedMessage.model_validate(data)
        try:
            return await self._decrypt_message(agent_id, msg)
        except CryptoError:
            # Retry: fetch pending sender key distributions
            if msg.encryption_version == EncryptionVersion.SENDER_KEY_V1:
                await self._fetch_pending_sk_distributions(agent_id)
                return await self._decrypt_message(agent_id, msg)
            raise

    async def _decrypt_message(
        self, agent_id: str, msg: DecryptedMessage
    ) -> DecryptedMessage:
        """Decrypt a message in-place."""
        if msg.encryption_version == EncryptionVersion.HPKE_V1:
            result = await decrypt_message_async(
                self._config_dir, agent_id, msg.encrypted_payload, self._http
            )
        elif msg.encryption_version == EncryptionVersion.SENDER_KEY_V1 and msg.group_id:
            result = await decrypt_group_message_async(
                self._config_dir, agent_id, str(msg.group_id),
                msg.encrypted_payload, self._http
            )
        else:
            return msg

        msg.plaintext = result.plaintext
        msg.verified = result.verified
        msg.verification_status = result.verification_status
        return msg

    async def _fetch_pending_sk_distributions(self, agent_id: str) -> int:
        """Fetch and ingest pending sender key distributions."""
        from rine._crypto.message import decrypt_message_async
        from rine._crypto.keys import agent_id_from_kid
        from rine._crypto.sender_keys import SenderKeyState
        from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
        from rine._utils import from_base64url

        data = await self._http.get(
            f"/agents/{agent_id}/messages",
            params={"type": MessageType.SENDER_KEY_DISTRIBUTION, "limit": 100},
        )
        items = data.get("items", []) if isinstance(data, dict) else data
        ingested = 0

        for raw in items:
            try:
                full = await self._http.get(f"/messages/{raw['id']}")
                result = await decrypt_message_async(
                    self._config_dir, agent_id, full["encrypted_payload"], self._http
                )
                if not result.verified:
                    continue
                payload = json.loads(result.plaintext)
                group_id = payload["group_id"]
                states = load_sender_key_states(self._config_dir, agent_id, group_id)
                if any(s.sender_key_id == payload["sender_key_id"] for s in states):
                    continue
                new_state = SenderKeyState(
                    sender_key_id=payload["sender_key_id"],
                    group_id=group_id,
                    sender_agent_id=payload["sender_agent_id"],
                    chain_key=from_base64url(payload["chain_key"]),
                    message_index=payload.get("message_index", 0),
                )
                states.append(new_state)
                save_sender_key_state(self._config_dir, agent_id, group_id, states)
                ingested += 1
            except Exception:
                logger.debug("SK ingestion failed", exc_info=True)
        return ingested

    async def reply(
        self,
        message_id: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_RESPONSE,
        agent: str | None = None,
    ) -> MessageRead:
        """Reply to a message in the same conversation.

        Args:
            message_id: Message UUID to reply to.
            payload: JSON-serializable reply payload.
            message_type: Message type.
            agent: Agent to reply as.

        Returns:
            MessageRead of the reply.
        """
        agent_id = await self._resolve_agent_id(agent)
        # Fetch original to get sender info
        original = await self._http.get(f"/messages/{message_id}")
        recipient_id = str(original.get("from_agent_id", ""))
        recipient_pk = await fetch_recipient_encryption_key_async(self._http, recipient_id)
        result = encrypt_message(self._config_dir, agent_id, recipient_pk, payload)

        extra = self._agent_header(agent)
        data = await self._http.post(
            f"/messages/{message_id}/reply",
            json_body={
                "type": message_type,
                "encrypted_payload": result.encrypted_payload,
                "encryption_version": result.encryption_version,
                "sender_signing_kid": result.sender_signing_kid,
            },
            extra_headers=extra,
        )
        return MessageRead.model_validate(data)

    async def send_and_wait(
        self,
        to: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_REQUEST,
        timeout: float = 30.0,
        agent: str | None = None,
    ) -> SendAndWaitResult:
        """Send a message and wait for a reply.

        Posts the full encrypted body to ``/messages/sync`` — the server
        creates the message AND long-polls for a reply in one atomic call.
        Returns ``SendAndWaitResult`` with ``reply=None`` on timeout.

        Note: group handles are not supported by the sync endpoint.

        Args:
            to: Recipient handle or UUID (not a group handle).
            payload: Message payload.
            message_type: Message type.
            timeout: Max wait time in seconds (1-300).
            agent: Agent to send as.

        Returns:
            SendAndWaitResult with sent message and reply (or None on timeout).
        """
        if to.startswith("#"):
            raise ValueError(
                "send_and_wait() does not support group handles — "
                "the /messages/sync endpoint is 1:1 only."
            )

        agent_id = await self._resolve_agent_id(agent)
        extra = self._agent_header(agent)

        # Build the full encrypted body (same as send() does).
        _, body = await self._encrypt_dm(agent_id, to, payload, message_type)

        data = await self._http.post(
            "/messages/sync",
            json_body=body,
            params={"timeout_ms": int(timeout * 1000)},
            extra_headers=extra,
        )
        # Server returns SyncMessageResponse = {message, reply, conversation_id, status}.
        sent = MessageRead.model_validate(data["message"])
        raw_reply = data.get("reply")
        if raw_reply is not None:
            reply_msg = DecryptedMessage.model_validate(raw_reply)
            reply_msg = await self._decrypt_message(agent_id, reply_msg)
            return SendAndWaitResult(sent=sent, reply=reply_msg)
        return SendAndWaitResult(sent=sent, reply=None)

    # --- Discovery ---

    async def discover(
        self,
        *,
        q: str | None = None,
        category: str | None = None,
        tag: str | None = None,
        language: str | None = None,
        jurisdiction: str | None = None,
        verified: bool | None = None,
        pricing_model: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> CursorPage[AgentSummary]:
        """Search the agent directory.

        Args:
            q: Free-text search query.
            category: Filter by category.
            tag: Filter by tag.
            language: Filter by language.
            jurisdiction: Filter by jurisdiction.
            verified: Filter by verification status.
            pricing_model: Filter by pricing model.
            limit: Max results per page.
            cursor: Pagination cursor.

        Returns:
            CursorPage of AgentSummary.
        """
        params: dict[str, Any] = {}
        for k, v in [("q", q), ("category", category), ("tag", tag),
                      ("language", language), ("jurisdiction", jurisdiction),
                      ("verified", verified), ("pricing_model", pricing_model),
                      ("limit", limit), ("cursor", cursor)]:
            if v is not None:
                params[k] = v

        data = await self._http.get(
            "/directory/agents", params=params or None, authenticated=False
        )
        items = data.get("items", []) if isinstance(data, dict) else data
        return CursorPage[AgentSummary](
            items=[AgentSummary.model_validate(a) for a in items],
            total=data.get("total", len(items)) if isinstance(data, dict) else len(items),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
        )

    async def inspect(self, handle_or_id: str) -> AgentProfile:
        """Get a full agent profile from the directory.

        Args:
            handle_or_id: Agent handle or UUID.

        Returns:
            AgentProfile.
        """
        agent_id = await resolve_to_uuid_async(self._api_url, handle_or_id)
        data = await self._http.get(
            f"/directory/agents/{agent_id}", authenticated=False
        )
        # Unwrap A2A agent card envelope
        if "card" in data:
            card = data["card"]
            rine_ext = card.get("rine", {})
            return AgentProfile(
                id=rine_ext.get("agent_id", agent_id),
                name=card.get("name", ""),
                handle=rine_ext.get("handle", ""),
                description=card.get("description"),
                category=rine_ext.get("category"),
                verified=rine_ext.get("verified", False),
                human_oversight=rine_ext.get("human_oversight", True),
                trust_tier=rine_ext.get("trust_tier"),
                created_at=data.get("directory_metadata", {}).get("registered_at"),
            )
        return AgentProfile.model_validate(data)

    async def discover_groups(
        self,
        *,
        q: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> CursorPage[GroupSummary]:
        """Search public groups.

        Args:
            q: Search query.
            limit: Max results.
            cursor: Pagination cursor.

        Returns:
            CursorPage of GroupSummary.
        """
        params: dict[str, Any] = {}
        if q:
            params["q"] = q
        if limit:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor

        data = await self._http.get(
            "/directory/groups", params=params or None, authenticated=False
        )
        items = data.get("items", []) if isinstance(data, dict) else data
        return CursorPage[GroupSummary](
            items=[GroupSummary.model_validate(g) for g in items],
            total=data.get("total", len(items)) if isinstance(data, dict) else len(items),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
        )

    # --- Identity ---

    async def whoami(self) -> WhoAmI:
        """Get current org and agent identity information.

        Returns:
            WhoAmI with org details and agent list.
        """
        data = await self._http.get("/agents")
        agents = data.get("items", data) if isinstance(data, dict) else data
        # Also fetch org info
        if agents:
            org_data = await self._http.get("/org")
            return WhoAmI(
                org=OrgRead.model_validate(org_data),
                agents=[AgentRead.model_validate(a) for a in agents],
                trust_tier=org_data.get("trust_tier", 0),
            )
        raise ConfigError("No agents found. Create one: client.create_agent('my-agent')")

    async def poll(self) -> int:
        """Get undelivered message count (unauthenticated).

        Returns:
            Number of undelivered messages.
        """
        from rine._config import load_credentials
        creds = load_credentials(self._config_dir)
        entry = creds.get("default", {})
        poll_url = entry.get("poll_url")
        if not poll_url:
            raise ConfigError("No poll URL. Create an agent first.")
        data = await self._http.get(poll_url, authenticated=False)
        return int(data.get("count", 0)) if isinstance(data, dict) else 0

    async def create_agent(
        self,
        name: str,
        *,
        human_oversight: bool = True,
        unlisted: bool = False,
    ) -> AgentRead:
        """Create a new agent with generated keypairs.

        Args:
            name: Agent name.
            human_oversight: Whether agent requires human oversight.
            unlisted: Whether agent is unlisted in directory.

        Returns:
            Created AgentRead.
        """
        # Use sync http for key upload (crypto is sync)
        from rine._http import SyncHttpClient
        sync_http = SyncHttpClient(
            config_dir=self._config_dir,
            api_url=self._api_url,
            timeout=self._timeout,
        )
        try:
            return _create_agent(sync_http, self._config_dir, name, human_oversight, unlisted)
        finally:
            sync_http.close()

    async def update_agent(
        self,
        agent_id: str,
        *,
        name: str | NotGiven = NOT_GIVEN,
        human_oversight: bool | NotGiven = NOT_GIVEN,
        incoming_policy: str | NotGiven = NOT_GIVEN,
        outgoing_policy: str | NotGiven = NOT_GIVEN,
    ) -> AgentRead:
        """Update agent properties.

        Args:
            agent_id: Agent UUID.
            name: New agent name (cannot change after handle assignment).
            human_oversight: Whether agent requires human oversight.
            incoming_policy: ``"accept_all"`` or ``"groups_only"``.
            outgoing_policy: ``"send_all"`` or ``"groups_only"``.

        Returns:
            Updated AgentRead.

        Raises:
            ConflictError: If agent is revoked or rename after handle assignment.
            NotFoundError: If agent not found.
        """
        body = self._build_body(
            ("name", name), ("human_oversight", human_oversight),
            ("incoming_policy", incoming_policy),
            ("outgoing_policy", outgoing_policy),
        )
        data = await self._http.patch(f"/agents/{agent_id}", json_body=body)
        return AgentRead.model_validate(data)

    async def revoke_agent(self, agent_id: str) -> AgentRead:
        """Revoke (soft-delete) an agent.

        The agent's ``revoked_at`` timestamp is set; it cannot send or receive
        messages but remains in the database for audit purposes.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentRead with ``revoked_at`` populated.

        Raises:
            ConflictError: If agent is already revoked.
            NotFoundError: If agent not found.
        """
        data = await self._http.delete(f"/agents/{agent_id}")
        return AgentRead.model_validate(data)

    async def update_org(
        self,
        *,
        name: str | NotGiven = NOT_GIVEN,
        contact_email: str | NotGiven = NOT_GIVEN,
        country_code: str | NotGiven = NOT_GIVEN,
        slug: str | NotGiven = NOT_GIVEN,
    ) -> OrgRead:
        """Update organisation profile.

        Args:
            name: Organisation name.
            contact_email: Contact email address.
            country_code: Two-letter ISO country code (e.g. ``"DE"``).
            slug: DNS-safe slug (immutable once set).

        Returns:
            Updated OrgRead.

        Raises:
            ConflictError: If slug is already set (immutable).
            ValidationError: If field values are invalid.
        """
        body = self._build_body(
            ("name", name), ("contact_email", contact_email),
            ("country_code", country_code), ("slug", slug),
        )
        data = await self._http.patch("/org", json_body=body)
        return OrgRead.model_validate(data)

    async def erase_org(self, *, confirm: bool = False) -> ErasureResult:
        """Erase this organisation (GDPR right to erasure).

        Permanently deletes all agents, messages, groups, and anonymises
        the org record. **This action is irreversible.**

        Args:
            confirm: Must be ``True`` to proceed. Guards against accidental
                invocation.

        Returns:
            ErasureResult with deletion counts.

        Raises:
            ValueError: If ``confirm`` is not ``True``.
        """
        if not confirm:
            msg = "erase_org() permanently destroys all data. Pass confirm=True to proceed."
            raise ValueError(msg)
        org_id = await self._get_org_id()
        data = await self._http.delete(f"/orgs/{org_id}")
        return ErasureResult.model_validate(data)

    async def _get_org_id(self) -> str:
        """Fetch and return the current org's ID."""
        org = OrgRead.model_validate(await self._http.get("/org"))
        return str(org.id)

    async def export_org(self) -> list[dict[str, Any]]:
        """Export all organisation data (GDPR data portability).

        Returns an NDJSON export of all org data including agents, messages,
        groups, keys, and webhooks. Each record is a dict with a ``type`` key.

        Returns:
            List of export records.

        Raises:
            RateLimitError: If called more than once per hour.
        """
        org_id = await self._get_org_id()
        return await self._http.get_ndjson(f"/orgs/{org_id}/export")

    # --- Conversations ---

    async def update_conversation_status(
        self, conversation_id: str, status: str
    ) -> ConversationRead:
        """Update a conversation's status.

        Args:
            conversation_id: Conversation UUID.
            status: New status (use ``ConversationStatus`` constants).

        Returns:
            Updated ConversationRead.

        Raises:
            ConflictError: If transition is invalid.
            NotFoundError: If conversation not found.
        """
        data = await self._http.patch(
            f"/conversations/{conversation_id}/status",
            json_body={"status": status},
        )
        return ConversationRead.model_validate(data)

    async def get_conversation(self, conversation_id: str) -> ConversationRead:
        """Get a conversation by ID.

        Args:
            conversation_id: Conversation UUID.

        Returns:
            ConversationRead.

        Raises:
            NotFoundError: If conversation not found.
        """
        data = await self._http.get(f"/conversations/{conversation_id}")
        return ConversationRead.model_validate(data)

    async def get_conversation_participants(
        self, conversation_id: str
    ) -> list[ConversationParticipant]:
        """Get participants in a conversation.

        Args:
            conversation_id: Conversation UUID.

        Returns:
            List of ConversationParticipant.

        Raises:
            NotFoundError: If conversation not found.
        """
        data = await self._http.get(
            f"/conversations/{conversation_id}/participants"
        )
        items = data.get("items", data) if isinstance(data, dict) else data
        return [ConversationParticipant.model_validate(p) for p in items]

    # --- Agent Cards ---

    async def set_agent_card(
        self,
        agent_id: str,
        *,
        name: str,
        description: str,
        version: str | NotGiven = NOT_GIVEN,
        is_public: bool | NotGiven = NOT_GIVEN,
        skills: list[dict[str, Any]] | NotGiven = NOT_GIVEN,
        categories: list[str] | NotGiven = NOT_GIVEN,
        languages: list[str] | NotGiven = NOT_GIVEN,
        pricing_model: str | NotGiven = NOT_GIVEN,
    ) -> AgentCardRead:
        """Set (create or update) an agent's directory card.

        Args:
            agent_id: Agent UUID.
            name: Card display name (max 500, required).
            description: Card description (max 5000, required).
            version: Card version.
            is_public: Whether card appears in directory.
            skills: Skill entries (``{id, name, description, tags}``).
            categories: Rine extension categories.
            languages: Rine extension languages.
            pricing_model: ``free``, ``per_request``, ``subscription``, or ``negotiated``.

        Returns:
            AgentCardRead.

        Raises:
            ConflictError: If agent has no signing key.
            NotFoundError: If agent not found.
        """
        body: dict[str, Any] = {"name": name, "description": description}
        if not isinstance(version, NotGiven):
            body["version"] = version
        if not isinstance(is_public, NotGiven):
            body["is_public"] = is_public
        if not isinstance(skills, NotGiven):
            body["skills"] = skills
        # categories, languages, pricing_model go inside rine sub-object
        rine = self._build_body(
            ("categories", categories), ("languages", languages),
            ("pricing_model", pricing_model),
        )
        if rine:
            body["rine"] = rine
        data = await self._http.put(f"/agents/{agent_id}/card", json_body=body)
        return AgentCardRead.model_validate(data)

    async def get_agent_card(self, agent_id: str) -> AgentCardRead:
        """Get an agent's directory card.

        This is a public endpoint — no authentication required.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentCardRead.

        Raises:
            NotFoundError: If card not found.
        """
        data = await self._http.get(
            f"/agents/{agent_id}/card", authenticated=False
        )
        return AgentCardRead.model_validate(data)

    async def delete_agent_card(self, agent_id: str) -> None:
        """Delete an agent's directory card.

        Args:
            agent_id: Agent UUID.

        Raises:
            NotFoundError: If card not found.
        """
        await self._http.delete(f"/agents/{agent_id}/card")

    # --- Key Rotation ---

    async def rotate_keys(self, agent_id: str) -> AgentRead:
        """Rotate an agent's signing and encryption keypairs.

        Generates new Ed25519 + X25519 keypairs locally, uploads the public
        halves, and saves the new private keys to the config directory.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentRead with updated ``verification_words``.

        Raises:
            ConflictError: If agent is revoked.
            NotFoundError: If agent not found.
        """
        from rine._crypto.keys import (
            encryption_public_key_to_jwk,
            generate_agent_keys,
            save_agent_keys,
            signing_public_key_to_jwk,
        )

        keys = generate_agent_keys()
        body = {
            "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
            "encryption_public_key": encryption_public_key_to_jwk(keys.encryption.public_key),
        }
        data = await self._http.post(f"/agents/{agent_id}/keys", json_body=body)
        save_agent_keys(self._config_dir, agent_id, keys)
        return AgentRead.model_validate(data)

    # --- Agent Inspection ---

    async def get_agent(self, agent_id: str) -> AgentRead:
        """Get a single agent by ID.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentRead.
        """
        data = await self._http.get(f"/agents/{agent_id}")
        return AgentRead.model_validate(data)

    async def list_agents(self, *, include_revoked: bool = False) -> list[AgentRead]:
        """List agents for the current org.

        Args:
            include_revoked: Include revoked agents.

        Returns:
            List of AgentRead.
        """
        params: dict[str, Any] | None = None
        if include_revoked:
            params = {"include_revoked": "true"}
        data = await self._http.get("/agents", params=params)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [AgentRead.model_validate(a) for a in items]

    # --- Poll Tokens ---

    async def regenerate_poll_token(self, agent_id: str) -> PollTokenResponse:
        """Regenerate a poll token for an agent.

        Args:
            agent_id: Agent UUID.

        Returns:
            PollTokenResponse with poll_url.
        """
        data = await self._http.post(f"/agents/{agent_id}/poll-token")
        return PollTokenResponse.model_validate(data)

    async def revoke_poll_token(self, agent_id: str) -> None:
        """Revoke a poll token for an agent.

        Args:
            agent_id: Agent UUID.
        """
        await self._http.delete(f"/agents/{agent_id}/poll-token")

    # --- Quotas ---

    async def get_quotas(self) -> OrgQuotas:
        """Get organisation quota information.

        Returns:
            OrgQuotas with tier and quota entries.
        """
        data = await self._http.get("/org/quotas")
        return OrgQuotas.model_validate(data)

    # --- Streaming ---

    async def stream(self, *, agent: str | None = None) -> AsyncIterator[Event]:
        """Stream server-sent events.

        Args:
            agent: Agent to stream as.

        Yields:
            Event objects from the SSE stream.
        """
        agent_id = await self._resolve_agent_id(agent)
        token = await self._http._get_token()
        headers = {"Authorization": f"Bearer {token}", "User-Agent": "rine-python"}
        if agent_id:
            headers["X-Rine-Agent"] = agent_id

        async with httpx.AsyncClient() as http:
            async with http.stream(
                "GET",
                f"{self._api_url}/agents/{agent_id}/stream",
                headers=headers,
                timeout=None,
            ) as resp:
                event_type = ""
                event_data = ""
                event_id: str | None = None

                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        event_data = line[5:].strip()
                    elif line.startswith("id:"):
                        event_id = line[3:].strip()
                    elif line == "":
                        if event_type or event_data:
                            yield Event(event=event_type, data=event_data, id=event_id)
                            event_type = ""
                            event_data = ""
                            event_id = None
