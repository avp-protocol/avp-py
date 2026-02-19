"""Tests for the Keychain backend."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Mock keyring before importing KeychainBackend
mock_keyring = MagicMock()
mock_storage: dict = {}


def mock_set_password(service, key, value):
    if service not in mock_storage:
        mock_storage[service] = {}
    mock_storage[service][key] = value


def mock_get_password(service, key):
    return mock_storage.get(service, {}).get(key)


def mock_delete_password(service, key):
    if service in mock_storage and key in mock_storage[service]:
        del mock_storage[service][key]
    else:
        raise Exception("Not found")


mock_keyring.set_password = mock_set_password
mock_keyring.get_password = mock_get_password
mock_keyring.delete_password = mock_delete_password

with patch.dict("sys.modules", {"keyring": mock_keyring}):
    from avp.backends.keychain import KeychainBackend
    from avp.errors import SecretNotFoundError
    from avp.types import BackendType


@pytest.fixture
def backend():
    """Create a keychain backend for testing."""
    mock_storage.clear()
    return KeychainBackend(backend_id="test-keychain")


class TestKeychainBackend:
    """Test suite for KeychainBackend."""

    def test_backend_properties(self, backend):
        """Test backend type and ID."""
        assert backend.backend_type == BackendType.KEYCHAIN
        assert backend.backend_id == "test-keychain"

    def test_capabilities(self, backend):
        """Test backend capabilities."""
        caps = backend.capabilities
        assert caps.rotation is True
        assert caps.migration is True
        assert caps.versioning is True

    def test_limits(self, backend):
        """Test backend limits."""
        limits = backend.limits
        assert limits.max_secret_name_length == 255
        assert limits.max_secret_value_length == 16384

    def test_info(self, backend):
        """Test backend info."""
        info = backend.get_info()
        assert "platform" in info
        assert "backend" in info

    def test_store_new_secret(self, backend):
        """Test storing a new secret."""
        created, version = backend.store(
            workspace="test",
            name="api_key",
            value=b"secret123",
        )
        assert created is True
        assert version == 1

    def test_store_update_secret(self, backend):
        """Test updating an existing secret."""
        backend.store("test", "api_key", b"v1")
        created, version = backend.store("test", "api_key", b"v2")
        assert created is False
        assert version == 2

    def test_retrieve_secret(self, backend):
        """Test retrieving a secret."""
        backend.store("test", "api_key", b"secret123")
        value, version = backend.retrieve("test", "api_key")
        assert value == b"secret123"
        assert version == 1

    def test_retrieve_nonexistent(self, backend):
        """Test retrieving a non-existent secret."""
        with pytest.raises(SecretNotFoundError):
            backend.retrieve("test", "nonexistent")

    def test_delete_secret(self, backend):
        """Test deleting a secret."""
        backend.store("test", "api_key", b"secret123")
        deleted = backend.delete("test", "api_key")
        assert deleted is True

        # Should not exist anymore
        with pytest.raises(SecretNotFoundError):
            backend.retrieve("test", "api_key")

    def test_delete_nonexistent(self, backend):
        """Test deleting a non-existent secret."""
        deleted = backend.delete("test", "nonexistent")
        assert deleted is False

    def test_list_secrets(self, backend):
        """Test listing secrets."""
        backend.store("test", "key1", b"value1")
        backend.store("test", "key2", b"value2")

        secrets, cursor = backend.list_secrets("test")
        names = [s.name for s in secrets]
        assert "key1" in names
        assert "key2" in names
        assert cursor is None

    def test_list_empty_workspace(self, backend):
        """Test listing secrets in empty workspace."""
        secrets, cursor = backend.list_secrets("empty")
        assert secrets == []
        assert cursor is None

    def test_list_with_labels(self, backend):
        """Test listing secrets with label filter."""
        backend.store("test", "prod_key", b"value1", labels={"env": "prod"})
        backend.store("test", "dev_key", b"value2", labels={"env": "dev"})

        secrets, _ = backend.list_secrets("test", filter_labels={"env": "prod"})
        assert len(secrets) == 1
        assert secrets[0].name == "prod_key"

    def test_get_metadata(self, backend):
        """Test getting secret metadata."""
        backend.store("test", "api_key", b"secret", labels={"env": "test"})
        metadata = backend.get_metadata("test", "api_key")

        assert metadata.version == 1
        assert metadata.backend == BackendType.KEYCHAIN
        assert metadata.labels == {"env": "test"}
        assert metadata.created_at is not None

    def test_rotate_secret(self, backend):
        """Test rotating a secret."""
        backend.store("test", "api_key", b"v1")
        version = backend.rotate("test", "api_key", b"v2")
        assert version == 2

        value, _ = backend.retrieve("test", "api_key")
        assert value == b"v2"

    def test_workspace_isolation(self, backend):
        """Test that workspaces are isolated."""
        backend.store("workspace1", "key", b"value1")
        backend.store("workspace2", "key", b"value2")

        value1, _ = backend.retrieve("workspace1", "key")
        value2, _ = backend.retrieve("workspace2", "key")

        assert value1 == b"value1"
        assert value2 == b"value2"

    def test_pagination(self, backend):
        """Test listing with pagination."""
        for i in range(5):
            backend.store("test", f"key{i}", f"value{i}".encode())

        # First page
        secrets, cursor = backend.list_secrets("test", limit=2)
        assert len(secrets) == 2
        assert cursor is not None

        # Second page
        secrets2, cursor2 = backend.list_secrets("test", cursor=cursor, limit=2)
        assert len(secrets2) == 2

    def test_close(self, backend):
        """Test closing the backend."""
        # Should not raise
        backend.close()
