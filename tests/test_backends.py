"""Tests for AVP backends."""

import os
import tempfile
import pytest
from datetime import datetime, timedelta

from avp import FileBackend, MemoryBackend, SecretNotFoundError
from avp.types import BackendType


class TestMemoryBackend:
    """Tests for MemoryBackend."""

    @pytest.fixture
    def backend(self):
        return MemoryBackend()

    def test_backend_type(self, backend):
        assert backend.backend_type == BackendType.MEMORY

    def test_backend_id(self, backend):
        assert backend.backend_id == "memory-0"

    def test_custom_backend_id(self):
        backend = MemoryBackend(backend_id="custom-memory")
        assert backend.backend_id == "custom-memory"

    def test_store_and_retrieve(self, backend):
        created, version = backend.store("default", "key1", b"value1")
        assert created is True
        assert version == 1

        value, ver = backend.retrieve("default", "key1")
        assert value == b"value1"
        assert ver == 1

    def test_update_increments_version(self, backend):
        backend.store("default", "key1", b"v1")
        _, version = backend.store("default", "key1", b"v2")
        assert version == 2

    def test_delete(self, backend):
        backend.store("default", "key1", b"value")
        deleted = backend.delete("default", "key1")
        assert deleted is True

        with pytest.raises(SecretNotFoundError):
            backend.retrieve("default", "key1")

    def test_delete_nonexistent(self, backend):
        deleted = backend.delete("default", "nonexistent")
        assert deleted is False

    def test_list_secrets(self, backend):
        backend.store("default", "key1", b"v1")
        backend.store("default", "key2", b"v2")

        secrets, cursor = backend.list_secrets("default")
        assert len(secrets) == 2
        assert cursor is None

    def test_list_with_labels(self, backend):
        backend.store("default", "key1", b"v1", labels={"env": "prod"})
        backend.store("default", "key2", b"v2", labels={"env": "dev"})

        secrets, _ = backend.list_secrets("default", filter_labels={"env": "prod"})
        assert len(secrets) == 1
        assert secrets[0].name == "key1"

    def test_get_metadata(self, backend):
        backend.store("default", "key1", b"value", labels={"key": "val"})
        metadata = backend.get_metadata("default", "key1")

        assert metadata.version == 1
        assert metadata.backend == BackendType.MEMORY
        assert metadata.labels == {"key": "val"}

    def test_clear(self, backend):
        backend.store("default", "key1", b"value")
        backend.clear()

        secrets, _ = backend.list_secrets("default")
        assert len(secrets) == 0

    def test_workspace_isolation(self, backend):
        backend.store("ws1", "key", b"value1")
        backend.store("ws2", "key", b"value2")

        value1, _ = backend.retrieve("ws1", "key")
        value2, _ = backend.retrieve("ws2", "key")

        assert value1 == b"value1"
        assert value2 == b"value2"

    def test_expiration(self, backend):
        past = datetime.utcnow() - timedelta(hours=1)
        backend.store("default", "expired", b"value", expires_at=past)

        with pytest.raises(SecretNotFoundError):
            backend.retrieve("default", "expired")


class TestFileBackend:
    """Tests for FileBackend."""

    @pytest.fixture
    def backend(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f:
            path = f.name
        backend = FileBackend(path, password="test_password")
        yield backend
        backend.close()
        if os.path.exists(path):
            os.unlink(path)

    def test_backend_type(self, backend):
        assert backend.backend_type == BackendType.FILE

    def test_store_and_retrieve(self, backend):
        created, version = backend.store("default", "key1", b"value1")
        assert created is True
        assert version == 1

        value, ver = backend.retrieve("default", "key1")
        assert value == b"value1"
        assert ver == 1

    def test_persistence(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f:
            path = f.name

        try:
            # Store with one instance
            backend1 = FileBackend(path, password="test")
            backend1.store("default", "key1", b"persistent_value")
            backend1.close()

            # Retrieve with another instance
            backend2 = FileBackend(path, password="test")
            value, _ = backend2.retrieve("default", "key1")
            assert value == b"persistent_value"
            backend2.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_wrong_password(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f:
            path = f.name

        try:
            # Create with one password
            backend1 = FileBackend(path, password="correct")
            backend1.store("default", "key", b"value")
            backend1.close()

            # Try to open with wrong password
            with pytest.raises(Exception):  # EncryptionError
                FileBackend(path, password="wrong")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_delete(self, backend):
        backend.store("default", "key1", b"value")
        deleted = backend.delete("default", "key1")
        assert deleted is True

        with pytest.raises(SecretNotFoundError):
            backend.retrieve("default", "key1")

    def test_list_secrets(self, backend):
        backend.store("default", "key1", b"v1")
        backend.store("default", "key2", b"v2")

        secrets, _ = backend.list_secrets("default")
        assert len(secrets) == 2

    def test_get_metadata(self, backend):
        backend.store("default", "key1", b"value", labels={"env": "prod"})
        metadata = backend.get_metadata("default", "key1")

        assert metadata.version == 1
        assert metadata.backend == BackendType.FILE
        assert metadata.labels == {"env": "prod"}

    def test_file_permissions(self, backend):
        backend.store("default", "key", b"value")
        # File should have restricted permissions (0600)
        mode = os.stat(backend._path).st_mode & 0o777
        assert mode == 0o600
