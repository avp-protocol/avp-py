"""Tests for AVP types."""

import pytest
from datetime import datetime, timedelta

from avp.types import Secret, Workspace, Session


class TestSecretName:
    """Tests for secret name validation."""

    def test_valid_names(self):
        valid_names = [
            "api_key",
            "API_KEY",
            "myKey123",
            "key.name",
            "key-name",
            "a",
            "A",
            "key_with_underscores",
            "key-with-dashes",
            "key.with.dots",
        ]
        for name in valid_names:
            assert Secret.validate_name(name), f"{name} should be valid"

    def test_invalid_names(self):
        invalid_names = [
            "",  # Empty
            "123key",  # Starts with number
            "_key",  # Starts with underscore
            ".key",  # Starts with dot
            "-key",  # Starts with dash
            "key with spaces",  # Contains spaces
            "key/path",  # Contains slash
            "key\\path",  # Contains backslash
            "a" * 256,  # Too long
        ]
        for name in invalid_names:
            assert not Secret.validate_name(name), f"{name} should be invalid"

    def test_max_length(self):
        # 255 characters should be valid
        name_255 = "a" * 255
        assert Secret.validate_name(name_255)

        # 256 characters should be invalid
        name_256 = "a" * 256
        assert not Secret.validate_name(name_256)


class TestWorkspaceId:
    """Tests for workspace ID validation."""

    def test_valid_workspace_ids(self):
        valid_ids = [
            "default",
            "my-project",
            "my_project",
            "my.project",
            "project/subproject",
            "production/us-east/api",
            "123",
            "a",
        ]
        for ws_id in valid_ids:
            assert Workspace.validate_id(ws_id), f"{ws_id} should be valid"

    def test_invalid_workspace_ids(self):
        invalid_ids = [
            "",  # Empty
            "/leading_slash",  # Leading slash
            "a" * 256,  # Too long
        ]
        for ws_id in invalid_ids:
            assert not Workspace.validate_id(ws_id), f"{ws_id} should be invalid"


class TestSession:
    """Tests for Session type."""

    def test_is_expired_false(self):
        session = Session(
            session_id="avp_sess_test",
            workspace="default",
            backend="memory-0",
            agent_id="test",
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            ttl_seconds=3600,
        )
        assert session.is_expired() is False
        assert session.is_valid() is True

    def test_is_expired_true(self):
        session = Session(
            session_id="avp_sess_test",
            workspace="default",
            backend="memory-0",
            agent_id="test",
            created_at=datetime.utcnow() - timedelta(hours=2),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            ttl_seconds=3600,
        )
        assert session.is_expired() is True
        assert session.is_valid() is False
