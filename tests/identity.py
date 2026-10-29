"""The ``POST /agents`` answer the onboarding tests serve."""

from __future__ import annotations

import json

import httpx


def echo_created_agent(request: httpx.Request) -> httpx.Response:
    """A ``POST /agents`` answer naming the id and name the client chose, as the server does."""
    body = json.loads(request.content)
    return httpx.Response(
        201,
        json={
            "id": body["id"],
            "name": body["name"],
            "handle": f"{body['name']}@myorg.rine.network",
            "human_oversight": body["human_oversight"],
            "incoming_policy": "accept_all",
            "outgoing_policy": "send_all",
            "created_at": "2024-01-01T00:00:00Z",
        },
    )
