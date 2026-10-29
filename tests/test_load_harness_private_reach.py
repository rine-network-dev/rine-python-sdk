"""The private SDK names the load harness reaches, listed so a rename fails here.

``scripts/load/org_session.py`` reads the org's current bearer through
``SyncRineClient._http._get_token()``. The harness runs in its own container, so nothing else
would notice the SDK moving either name: the failure would arrive mid-run, as an
``AttributeError`` on the first token refresh.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import httpx
import pytest

from rine import SyncRineClient

HARNESS = Path(__file__).resolve().parents[2] / "scripts" / "load" / "org_session.py"


def test_load_harness_private_reach_when_the_sdk_moves_it_still_resolves(tmp_path: Path) -> None:
    """The client the harness builds carries the token method the harness calls."""
    client = SyncRineClient(
        config_dir=str(tmp_path),
        api_url="http://localhost:1",
        owner_dir=str(tmp_path / "owner"),
        http_client=httpx.Client(),
    )
    try:
        assert callable(client._http._get_token)
        assert "force" in inspect.signature(client._http._get_token).parameters
    finally:
        client.close()


def test_load_harness_private_reach_when_the_harness_changes_it_is_listed_here() -> None:
    """The harness reaches exactly the names above; a new reach has to be listed first."""
    if not HARNESS.exists():
        pytest.skip("the load harness is not in this tree")
    source = HARNESS.read_text()
    reaches = {line.strip() for line in source.splitlines() if "._client._" in line}
    assert reaches == {"return self._client._http._get_token()"}
