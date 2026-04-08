"""Shared fixtures for rine SDK tests."""

from __future__ import annotations

import os
import tempfile

import pytest

from rine._crypto.keys import AgentKeys, KeyPair, generate_agent_keys, save_agent_keys


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Provide a temporary config directory."""
    return str(tmp_path)


@pytest.fixture
def agent_keys():
    """Generate fresh agent keys."""
    return generate_agent_keys()


@pytest.fixture
def agent_id():
    """Provide a fixed agent UUID."""
    return "00000000-1111-2222-3333-444444444444"


@pytest.fixture
def other_agent_id():
    """Provide a second fixed agent UUID."""
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def saved_agent_keys(tmp_config_dir, agent_id, agent_keys):
    """Save agent keys to disk and return them."""
    save_agent_keys(tmp_config_dir, agent_id, agent_keys)
    return agent_keys


@pytest.fixture
def sync_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured SyncRineClient with saved credentials and keys."""
    from rine._config import save_credentials
    save_credentials(tmp_config_dir, {
        "default": {"client_id": "test-cid", "client_secret": "test-csecret"}
    })
    from rine import SyncRineClient
    client = SyncRineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    yield client
    client.close()


@pytest.fixture
def async_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured RineClient with saved credentials and keys."""
    from rine._config import save_credentials
    save_credentials(tmp_config_dir, {
        "default": {"client_id": "test-cid", "client_secret": "test-csecret"}
    })
    from rine import RineClient
    client = RineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    return client
