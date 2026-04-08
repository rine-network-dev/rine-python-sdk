"""Webhooks sub-namespace — ``client.webhooks.*`` operations.

Provides webhook CRUD methods (create, list, update, delete)
for both sync and async clients.
"""

from __future__ import annotations

from typing import Any

from rine.types import WebhookCreated, WebhookJobRead, WebhookJobSummary, WebhookRead


class SyncWebhooks:
    """Synchronous webhook operations, accessed via ``client.webhooks``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def create(
        self,
        agent_id: str,
        url: str,
        *,
        events: list[str] | None = None,
    ) -> WebhookCreated:
        """Create a new webhook.

        Args:
            agent_id: Agent UUID to associate the webhook with.
            url: Webhook callback URL (must be HTTPS).
            events: Optional list of event types to subscribe to.

        Returns:
            WebhookCreated with one-time ``secret``.

        Raises:
            ConflictError: If a webhook with this URL already exists.
            AuthorizationError: If webhook quota is exceeded.
        """
        body: dict[str, Any] = {"agent_id": agent_id, "url": url}
        if events is not None:
            body["events"] = events
        data = self._client._http.post("/webhooks", json_body=body)
        return WebhookCreated.model_validate(data)

    def list(
        self,
        *,
        agent_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[WebhookRead]:
        """List webhooks.

        Args:
            agent_id: Filter by agent UUID.
            include_inactive: Include deactivated webhooks.

        Returns:
            List of WebhookRead.
        """
        params: dict[str, Any] = {}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if include_inactive:
            params["include_inactive"] = "true"
        data = self._client._http.get("/webhooks", params=params or None)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [WebhookRead.model_validate(w) for w in items]

    def update(
        self,
        webhook_id: str,
        *,
        active: bool,
    ) -> WebhookRead:
        """Update a webhook.

        Args:
            webhook_id: Webhook UUID.
            active: Whether the webhook is active.

        Returns:
            Updated WebhookRead.
        """
        data = self._client._http.patch(
            f"/webhooks/{webhook_id}", json_body={"active": active}
        )
        return WebhookRead.model_validate(data)

    def delete(self, webhook_id: str) -> None:
        """Delete a webhook.

        Args:
            webhook_id: Webhook UUID.
        """
        self._client._http.delete(f"/webhooks/{webhook_id}")

    def deliveries(
        self,
        webhook_id: str,
        *,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookJobRead]:
        """List webhook delivery attempts.

        Args:
            webhook_id: Webhook UUID.
            status: Filter by status (pending, processing, delivered, failed, dead).
            limit: Max results (1-100).
            offset: Pagination offset.

        Returns:
            List of WebhookJobRead.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        data = self._client._http.get(
            f"/webhooks/{webhook_id}/deliveries", params=params
        )
        items = data.get("items", data) if isinstance(data, dict) else data
        return [WebhookJobRead.model_validate(j) for j in items]

    def delivery_summary(self, webhook_id: str) -> WebhookJobSummary:
        """Get aggregated delivery counts for a webhook.

        Args:
            webhook_id: Webhook UUID.

        Returns:
            WebhookJobSummary with counts.
        """
        data = self._client._http.get(
            f"/webhooks/{webhook_id}/deliveries/summary"
        )
        return WebhookJobSummary.model_validate(data)


class AsyncWebhooks:
    """Async webhook operations, accessed via ``client.webhooks``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def create(
        self,
        agent_id: str,
        url: str,
        *,
        events: list[str] | None = None,
    ) -> WebhookCreated:
        """Create a new webhook.

        Args:
            agent_id: Agent UUID to associate the webhook with.
            url: Webhook callback URL (must be HTTPS).
            events: Optional list of event types to subscribe to.

        Returns:
            WebhookCreated with one-time ``secret``.

        Raises:
            ConflictError: If a webhook with this URL already exists.
            AuthorizationError: If webhook quota is exceeded.
        """
        body: dict[str, Any] = {"agent_id": agent_id, "url": url}
        if events is not None:
            body["events"] = events
        data = await self._client._http.post("/webhooks", json_body=body)
        return WebhookCreated.model_validate(data)

    async def list(
        self,
        *,
        agent_id: str | None = None,
        include_inactive: bool = False,
    ) -> list[WebhookRead]:
        """List webhooks.

        Args:
            agent_id: Filter by agent UUID.
            include_inactive: Include deactivated webhooks.

        Returns:
            List of WebhookRead.
        """
        params: dict[str, Any] = {}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if include_inactive:
            params["include_inactive"] = "true"
        data = await self._client._http.get("/webhooks", params=params or None)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [WebhookRead.model_validate(w) for w in items]

    async def update(
        self,
        webhook_id: str,
        *,
        active: bool,
    ) -> WebhookRead:
        """Update a webhook.

        Args:
            webhook_id: Webhook UUID.
            active: Whether the webhook is active.

        Returns:
            Updated WebhookRead.
        """
        data = await self._client._http.patch(
            f"/webhooks/{webhook_id}", json_body={"active": active}
        )
        return WebhookRead.model_validate(data)

    async def delete(self, webhook_id: str) -> None:
        """Delete a webhook.

        Args:
            webhook_id: Webhook UUID.
        """
        await self._client._http.delete(f"/webhooks/{webhook_id}")

    async def deliveries(
        self,
        webhook_id: str,
        *,
        status: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookJobRead]:
        """List webhook delivery attempts.

        Args:
            webhook_id: Webhook UUID.
            status: Filter by status (pending, processing, delivered, failed, dead).
            limit: Max results (1-100).
            offset: Pagination offset.

        Returns:
            List of WebhookJobRead.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        data = await self._client._http.get(
            f"/webhooks/{webhook_id}/deliveries", params=params
        )
        items = data.get("items", data) if isinstance(data, dict) else data
        return [WebhookJobRead.model_validate(j) for j in items]

    async def delivery_summary(self, webhook_id: str) -> WebhookJobSummary:
        """Get aggregated delivery counts for a webhook.

        Args:
            webhook_id: Webhook UUID.

        Returns:
            WebhookJobSummary with counts.
        """
        data = await self._client._http.get(
            f"/webhooks/{webhook_id}/deliveries/summary"
        )
        return WebhookJobSummary.model_validate(data)
