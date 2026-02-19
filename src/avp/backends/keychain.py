"""OS Keychain backend for AVP.

Provides secure credential storage using the platform's native keychain:
- macOS: Keychain
- Linux: SecretService (gnome-keyring, KWallet)
- Windows: Windows Credential Manager
"""

import base64
import json
import platform
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

from avp.types import (
    BackendType,
    Capabilities,
    Limits,
    Secret,
    SecretMetadata,
)
from avp.backends.base import BackendBase
from avp.errors import (
    SecretNotFoundError,
    BackendUnavailableError,
)


def _check_keyring():
    """Check if keyring is available."""
    if not KEYRING_AVAILABLE:
        raise BackendUnavailableError(
            "Keychain backend requires the 'keyring' package. "
            "Install with: pip install avp-sdk[keychain]"
        )


class KeychainBackend(BackendBase):
    """
    OS Keychain-backed storage for AVP.

    Uses the operating system's native credential storage:
    - macOS: Keychain Access
    - Linux: SecretService API (gnome-keyring, KWallet, etc.)
    - Windows: Windows Credential Manager

    Secrets are stored with service name "avp-{workspace}" and username as the key.
    Metadata is stored alongside the secret value as JSON.
    """

    SERVICE_PREFIX = "avp"
    METADATA_SERVICE_PREFIX = "avp-meta"
    INDEX_KEY = "__avp_secret_index__"

    def __init__(
        self,
        backend_id: str = "keychain-0",
        service_prefix: str = "avp",
    ):
        """
        Initialize the keychain backend.

        Args:
            backend_id: Unique backend identifier
            service_prefix: Prefix for keyring service names
        """
        _check_keyring()
        self._backend_id = backend_id
        self.SERVICE_PREFIX = service_prefix
        self.METADATA_SERVICE_PREFIX = f"{service_prefix}-meta"
        self._lock = threading.RLock()
        self._verify_keyring()

    def _verify_keyring(self) -> None:
        """Verify keyring is properly configured."""
        try:
            # Try a test operation
            test_service = f"{self.SERVICE_PREFIX}-test"
            keyring.set_password(test_service, "__avp_test__", "test")
            result = keyring.get_password(test_service, "__avp_test__")
            keyring.delete_password(test_service, "__avp_test__")
            if result != "test":
                raise BackendUnavailableError("Keyring test failed")
        except Exception as e:
            if "NoKeyringError" in str(type(e).__name__):
                raise BackendUnavailableError(
                    "No keyring backend found. On Linux, install gnome-keyring or KWallet. "
                    f"Error: {e}"
                )
            # Ignore delete errors if key doesn't exist
            if "delete" not in str(e).lower():
                pass  # Key was already deleted, that's fine

    def _service_name(self, workspace: str) -> str:
        """Get keyring service name for workspace."""
        return f"{self.SERVICE_PREFIX}-{workspace}"

    def _meta_service_name(self, workspace: str) -> str:
        """Get keyring service name for workspace metadata."""
        return f"{self.METADATA_SERVICE_PREFIX}-{workspace}"

    def _get_index(self, workspace: str) -> List[str]:
        """Get list of secret names in workspace."""
        service = self._meta_service_name(workspace)
        try:
            index_json = keyring.get_password(service, self.INDEX_KEY)
            if index_json:
                return json.loads(index_json)
        except Exception:
            pass
        return []

    def _save_index(self, workspace: str, names: List[str]) -> None:
        """Save list of secret names."""
        service = self._meta_service_name(workspace)
        keyring.set_password(service, self.INDEX_KEY, json.dumps(names))

    def _get_metadata(self, workspace: str, name: str) -> Optional[Dict]:
        """Get metadata for a secret."""
        service = self._meta_service_name(workspace)
        try:
            meta_json = keyring.get_password(service, name)
            if meta_json:
                return json.loads(meta_json)
        except Exception:
            pass
        return None

    def _save_metadata(self, workspace: str, name: str, metadata: Dict) -> None:
        """Save metadata for a secret."""
        service = self._meta_service_name(workspace)
        keyring.set_password(service, name, json.dumps(metadata))

    def _delete_metadata(self, workspace: str, name: str) -> None:
        """Delete metadata for a secret."""
        service = self._meta_service_name(workspace)
        try:
            keyring.delete_password(service, name)
        except Exception:
            pass  # Ignore if doesn't exist

    @property
    def backend_type(self) -> BackendType:
        return BackendType.KEYCHAIN

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            attestation=False,
            rotation=True,
            injection=False,
            audit=False,  # Keychain doesn't provide audit logs
            migration=True,
            implicit_sessions=True,
            expiration=True,
            versioning=True,
        )

    @property
    def limits(self) -> Limits:
        # Keychain has per-item size limits that vary by platform
        return Limits(
            max_secret_name_length=255,
            max_secret_value_length=16384,  # Conservative limit
            max_labels_per_secret=32,
            max_secrets_per_workspace=1000,
            max_session_ttl_seconds=86400,
        )

    def get_info(self) -> Dict[str, str]:
        system = platform.system()
        backend_info = {
            "Darwin": "macOS Keychain",
            "Linux": "SecretService (gnome-keyring/KWallet)",
            "Windows": "Windows Credential Manager",
        }.get(system, f"keyring ({system})")

        return {
            "platform": system,
            "backend": backend_info,
            "service_prefix": self.SERVICE_PREFIX,
        }

    def store(
        self,
        workspace: str,
        name: str,
        value: bytes,
        labels: Optional[Dict[str, str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, int]:
        with self._lock:
            service = self._service_name(workspace)
            now = datetime.utcnow()

            # Check if exists
            existing_meta = self._get_metadata(workspace, name)
            created = existing_meta is None

            if created:
                version = 1
                created_at = now.isoformat()
            else:
                version = existing_meta.get("version", 0) + 1
                created_at = existing_meta.get("created_at", now.isoformat())

            # Store value as base64 string (keychain stores strings)
            value_b64 = base64.b64encode(value).decode("ascii")
            keyring.set_password(service, name, value_b64)

            # Store metadata
            metadata = {
                "created_at": created_at,
                "updated_at": now.isoformat(),
                "backend": "keychain",
                "version": version,
                "labels": labels or {},
                "expires_at": expires_at.isoformat() if expires_at else None,
            }
            self._save_metadata(workspace, name, metadata)

            # Update index
            index = self._get_index(workspace)
            if name not in index:
                index.append(name)
                self._save_index(workspace, index)

            return created, version

    def retrieve(
        self,
        workspace: str,
        name: str,
        version: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        with self._lock:
            service = self._service_name(workspace)

            # Get value
            value_b64 = keyring.get_password(service, name)
            if value_b64 is None:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            # Get metadata
            metadata = self._get_metadata(workspace, name)
            if metadata is None:
                # Value exists but no metadata - create minimal metadata
                metadata = {"version": 1}

            # Check expiration
            if metadata.get("expires_at"):
                expires_at = datetime.fromisoformat(metadata["expires_at"])
                if datetime.utcnow() > expires_at:
                    self.delete(workspace, name)
                    raise SecretNotFoundError(f"Secret '{name}' not found")

            # Version check
            current_version = metadata.get("version", 1)
            if version is not None and version != current_version:
                raise SecretNotFoundError(
                    f"Secret '{name}' version {version} not found"
                )

            value = base64.b64decode(value_b64)
            return value, current_version

    def delete(self, workspace: str, name: str) -> bool:
        with self._lock:
            service = self._service_name(workspace)

            # Check if exists
            if keyring.get_password(service, name) is None:
                return False

            # Delete value
            try:
                keyring.delete_password(service, name)
            except Exception:
                return False

            # Delete metadata
            self._delete_metadata(workspace, name)

            # Update index
            index = self._get_index(workspace)
            if name in index:
                index.remove(name)
                self._save_index(workspace, index)

            return True

    def list_secrets(
        self,
        workspace: str,
        filter_labels: Optional[Dict[str, str]] = None,
        cursor: Optional[str] = None,
        limit: int = 100,
    ) -> Tuple[List[Secret], Optional[str]]:
        with self._lock:
            index = self._get_index(workspace)
            secrets = []
            now = datetime.utcnow()

            for name in sorted(index):
                metadata_dict = self._get_metadata(workspace, name)
                if metadata_dict is None:
                    continue

                # Check expiration
                if metadata_dict.get("expires_at"):
                    expires_at = datetime.fromisoformat(metadata_dict["expires_at"])
                    if now > expires_at:
                        # Clean up expired secret
                        self.delete(workspace, name)
                        continue

                # Apply label filter
                if filter_labels:
                    labels = metadata_dict.get("labels", {})
                    match = all(
                        labels.get(k) == v for k, v in filter_labels.items()
                    )
                    if not match:
                        continue

                metadata = SecretMetadata(
                    created_at=datetime.fromisoformat(metadata_dict["created_at"]),
                    updated_at=datetime.fromisoformat(metadata_dict["updated_at"]),
                    backend=BackendType.KEYCHAIN,
                    version=metadata_dict.get("version", 1),
                    labels=metadata_dict.get("labels", {}),
                    expires_at=(
                        datetime.fromisoformat(metadata_dict["expires_at"])
                        if metadata_dict.get("expires_at")
                        else None
                    ),
                )

                secrets.append(Secret(
                    name=name,
                    workspace=workspace,
                    metadata=metadata,
                    value=None,
                ))

            # Pagination
            start = 0
            if cursor:
                try:
                    start = int(cursor)
                except ValueError:
                    start = 0

            end = start + limit
            page = secrets[start:end]
            next_cursor = str(end) if end < len(secrets) else None

            return page, next_cursor

    def get_metadata(self, workspace: str, name: str) -> SecretMetadata:
        with self._lock:
            metadata_dict = self._get_metadata(workspace, name)
            if metadata_dict is None:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            # Check expiration
            if metadata_dict.get("expires_at"):
                expires_at = datetime.fromisoformat(metadata_dict["expires_at"])
                if datetime.utcnow() > expires_at:
                    self.delete(workspace, name)
                    raise SecretNotFoundError(f"Secret '{name}' not found")

            return SecretMetadata(
                created_at=datetime.fromisoformat(metadata_dict["created_at"]),
                updated_at=datetime.fromisoformat(metadata_dict["updated_at"]),
                backend=BackendType.KEYCHAIN,
                version=metadata_dict.get("version", 1),
                labels=metadata_dict.get("labels", {}),
                expires_at=(
                    datetime.fromisoformat(metadata_dict["expires_at"])
                    if metadata_dict.get("expires_at")
                    else None
                ),
            )

    def close(self) -> None:
        """No cleanup needed for keychain backend."""
        pass
