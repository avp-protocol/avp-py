"""Tests for the AVP client."""

import pytest
from datetime import datetime, timedelta

from avp import (
    AVPClient,
    MemoryBackend,
    AuthMethod,
    SecretNotFoundError,
    InvalidNameError,
    SessionExpiredError,
    SessionNotFoundError,
)
from avp.types import ConformanceLevel


@pytest.fixture
def backend():
    """Create a memory backend for testing."""
    return MemoryBackend()


@pytest.fixture
def client(backend):
    """Create an AVP client with memory backend."""
    return AVPClient(backend)


class TestDiscover:
    """Tests for DISCOVER operation."""

    def test_discover_returns_version(self, client):
        response = client.discover()
        assert response.version == "0.1.0"

    def test_discover_returns_conformance(self, client):
        response = client.discover()
        assert response.conformance == ConformanceLevel.FULL

    def test_discover_returns_backends(self, client):
        response = client.discover()
        assert len(response.backends) == 1
        assert response.backends[0].id == "memory-0"

    def test_discover_returns_capabilities(self, client):
        response = client.discover()
        assert response.capabilities.rotation is True
        assert response.capabilities.expiration is True


class TestAuthenticate:
    """Tests for AUTHENTICATE operation."""

    def test_authenticate_creates_session(self, client):
        session = client.authenticate(workspace="test")
        assert session.session_id.startswith("avp_sess_")
        assert session.workspace == "test"

    def test_authenticate_with_agent_id(self, client):
        session = client.authenticate(agent_id="my-agent/1.0")
        assert session.agent_id == "my-agent/1.0"

    def test_authenticate_with_ttl(self, client):
        session = client.authenticate(requested_ttl=300)
        assert session.ttl_seconds == 300

    def test_authenticate_respects_max_ttl(self, client):
        session = client.authenticate(requested_ttl=999999)
        assert session.ttl_seconds <= 86400  # Max TTL

    def test_authenticate_terminate(self, client):
        session = client.authenticate()
        client.authenticate(
            auth_method=AuthMethod.TERMINATE,
            auth_data={"session_id": session.session_id},
        )
        # Session should be terminated
        with pytest.raises(SessionNotFoundError):
            client.store(session.session_id, "test", b"value")


class TestStore:
    """Tests for STORE operation."""

    def test_store_new_secret(self, client):
        session = client.authenticate()
        response = client.store(session.session_id, "api_key", b"secret123")
        assert response.name == "api_key"
        assert response.created is True
        assert response.version == 1

    def test_store_update_secret(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"secret123")
        response = client.store(session.session_id, "api_key", b"secret456")
        assert response.created is False
        assert response.version == 2

    def test_store_with_labels(self, client):
        session = client.authenticate()
        labels = {"env": "prod", "service": "api"}
        response = client.store(session.session_id, "api_key", b"secret", labels=labels)
        assert response.created is True

    def test_store_invalid_name(self, client):
        session = client.authenticate()
        with pytest.raises(InvalidNameError):
            client.store(session.session_id, "123invalid", b"value")

    def test_store_invalid_session(self, client):
        with pytest.raises(SessionNotFoundError):
            client.store("invalid_session", "test", b"value")


class TestRetrieve:
    """Tests for RETRIEVE operation."""

    def test_retrieve_secret(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"secret123")
        response = client.retrieve(session.session_id, "api_key")
        assert response.name == "api_key"
        assert response.value == b"secret123"
        assert response.version == 1

    def test_retrieve_nonexistent_secret(self, client):
        session = client.authenticate()
        with pytest.raises(SecretNotFoundError):
            client.retrieve(session.session_id, "nonexistent")

    def test_retrieve_specific_version(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"v1")
        client.store(session.session_id, "api_key", b"v2")
        # Memory backend doesn't keep history, so version 1 should fail
        with pytest.raises(SecretNotFoundError):
            client.retrieve(session.session_id, "api_key", version=1)


class TestDelete:
    """Tests for DELETE operation."""

    def test_delete_existing_secret(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"secret")
        response = client.delete(session.session_id, "api_key")
        assert response.name == "api_key"
        assert response.deleted is True

    def test_delete_nonexistent_secret(self, client):
        session = client.authenticate()
        response = client.delete(session.session_id, "nonexistent")
        assert response.deleted is False

    def test_delete_removes_secret(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"secret")
        client.delete(session.session_id, "api_key")
        with pytest.raises(SecretNotFoundError):
            client.retrieve(session.session_id, "api_key")


class TestList:
    """Tests for LIST operation."""

    def test_list_empty_workspace(self, client):
        session = client.authenticate()
        response = client.list_secrets(session.session_id)
        assert len(response.secrets) == 0

    def test_list_secrets(self, client):
        session = client.authenticate()
        client.store(session.session_id, "key1", b"v1")
        client.store(session.session_id, "key2", b"v2")
        client.store(session.session_id, "key3", b"v3")
        response = client.list_secrets(session.session_id)
        assert len(response.secrets) == 3
        names = [s.name for s in response.secrets]
        assert "key1" in names
        assert "key2" in names
        assert "key3" in names

    def test_list_does_not_include_values(self, client):
        session = client.authenticate()
        client.store(session.session_id, "key1", b"secret")
        response = client.list_secrets(session.session_id)
        assert response.secrets[0].value is None

    def test_list_with_label_filter(self, client):
        session = client.authenticate()
        client.store(session.session_id, "key1", b"v1", labels={"env": "prod"})
        client.store(session.session_id, "key2", b"v2", labels={"env": "dev"})
        response = client.list_secrets(
            session.session_id, filter_labels={"env": "prod"}
        )
        assert len(response.secrets) == 1
        assert response.secrets[0].name == "key1"

    def test_list_pagination(self, client):
        session = client.authenticate()
        for i in range(10):
            client.store(session.session_id, f"key{i:02d}", b"value")

        response = client.list_secrets(session.session_id, limit=3)
        assert len(response.secrets) == 3
        assert response.has_more is True
        assert response.cursor is not None

        response2 = client.list_secrets(
            session.session_id, limit=3, cursor=response.cursor
        )
        assert len(response2.secrets) == 3


class TestRotate:
    """Tests for ROTATE operation."""

    def test_rotate_secret(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"old_value")
        response = client.rotate(session.session_id, "api_key", b"new_value")
        assert response.name == "api_key"
        assert response.version == 2

    def test_rotate_updates_value(self, client):
        session = client.authenticate()
        client.store(session.session_id, "api_key", b"old_value")
        client.rotate(session.session_id, "api_key", b"new_value")
        response = client.retrieve(session.session_id, "api_key")
        assert response.value == b"new_value"

    def test_rotate_nonexistent_secret(self, client):
        session = client.authenticate()
        with pytest.raises(SecretNotFoundError):
            client.rotate(session.session_id, "nonexistent", b"value")


class TestExpiration:
    """Tests for secret expiration."""

    def test_expired_secret_not_retrieved(self, client):
        session = client.authenticate()
        # Store with expiration in the past
        client.store(
            session.session_id,
            "api_key",
            b"secret",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        with pytest.raises(SecretNotFoundError):
            client.retrieve(session.session_id, "api_key")

    def test_expired_secret_not_listed(self, client):
        session = client.authenticate()
        client.store(
            session.session_id,
            "expired_key",
            b"secret",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        client.store(session.session_id, "valid_key", b"secret")
        response = client.list_secrets(session.session_id)
        names = [s.name for s in response.secrets]
        assert "valid_key" in names
        assert "expired_key" not in names


class TestSessionExpiration:
    """Tests for session expiration."""

    def test_expired_session_rejected(self, client):
        from dataclasses import replace
        session = client.authenticate(requested_ttl=1)
        # Manually expire the session
        client._sessions[session.session_id] = replace(
            session, expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        with pytest.raises(SessionExpiredError):
            client.store(session.session_id, "test", b"value")


class TestWorkspaceIsolation:
    """Tests for workspace isolation."""

    def test_secrets_isolated_by_workspace(self, client):
        session1 = client.authenticate(workspace="workspace1")
        session2 = client.authenticate(workspace="workspace2")

        client.store(session1.session_id, "shared_name", b"value1")
        client.store(session2.session_id, "shared_name", b"value2")

        response1 = client.retrieve(session1.session_id, "shared_name")
        response2 = client.retrieve(session2.session_id, "shared_name")

        assert response1.value == b"value1"
        assert response2.value == b"value2"


class TestContextManager:
    """Tests for context manager support."""

    def test_client_as_context_manager(self, backend):
        with AVPClient(backend) as client:
            session = client.authenticate()
            client.store(session.session_id, "key", b"value")
            response = client.retrieve(session.session_id, "key")
            assert response.value == b"value"
