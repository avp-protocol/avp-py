"""In-memory backend for AVP (useful for testing)."""

from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading

from avp.types import (
    BackendType,
    Capabilities,
    Limits,
    Secret,
    SecretMetadata,
)
from avp.backends.base import BackendBase
from avp.errors import SecretNotFoundError


class MemoryBackend(BackendBase):
    """
    In-memory backend for testing and development.

    WARNING: Secrets are stored in plaintext in memory.
    Do not use in production.
    """

    def __init__(self, backend_id: str = "memory-0"):
        self._backend_id = backend_id
        self._secrets: Dict[str, Dict[str, Tuple[bytes, SecretMetadata]]] = {}
        self._lock = threading.RLock()

    @property
    def backend_type(self) -> BackendType:
        return BackendType.MEMORY

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            attestation=False,
            rotation=True,
            injection=False,
            audit=True,
            migration=False,
            implicit_sessions=True,
            expiration=True,
            versioning=True,
        )

    @property
    def limits(self) -> Limits:
        return Limits(
            max_secret_name_length=255,
            max_secret_value_length=65536,
            max_labels_per_secret=64,
            max_secrets_per_workspace=10000,
            max_session_ttl_seconds=86400,
        )

    def get_info(self) -> Dict[str, str]:
        return {
            "type": "memory",
            "warning": "In-memory storage - data lost on restart",
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
            if workspace not in self._secrets:
                self._secrets[workspace] = {}

            now = datetime.utcnow()
            created = name not in self._secrets[workspace]

            if created:
                version = 1
                created_at = now
            else:
                _, existing_meta = self._secrets[workspace][name]
                version = existing_meta.version + 1
                created_at = existing_meta.created_at

            metadata = SecretMetadata(
                created_at=created_at,
                updated_at=now,
                backend=BackendType.MEMORY,
                version=version,
                labels=labels or {},
                expires_at=expires_at,
            )

            self._secrets[workspace][name] = (value, metadata)
            return created, version

    def retrieve(
        self,
        workspace: str,
        name: str,
        version: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        with self._lock:
            if workspace not in self._secrets:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            if name not in self._secrets[workspace]:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            value, metadata = self._secrets[workspace][name]

            # Check expiration
            if metadata.expires_at and datetime.utcnow() > metadata.expires_at:
                del self._secrets[workspace][name]
                raise SecretNotFoundError(f"Secret '{name}' not found")

            # Version check (simplified - we don't keep version history)
            if version is not None and version != metadata.version:
                raise SecretNotFoundError(
                    f"Secret '{name}' version {version} not found"
                )

            return value, metadata.version

    def delete(self, workspace: str, name: str) -> bool:
        with self._lock:
            if workspace not in self._secrets:
                return False

            if name not in self._secrets[workspace]:
                return False

            # Zero out the value before deleting
            value, metadata = self._secrets[workspace][name]
            zeroed = b"\x00" * len(value)
            self._secrets[workspace][name] = (zeroed, metadata)

            del self._secrets[workspace][name]
            return True

    def list_secrets(
        self,
        workspace: str,
        filter_labels: Optional[Dict[str, str]] = None,
        cursor: Optional[str] = None,
        limit: int = 100,
    ) -> Tuple[List[Secret], Optional[str]]:
        with self._lock:
            if workspace not in self._secrets:
                return [], None

            secrets = []
            now = datetime.utcnow()

            for name, (_, metadata) in self._secrets[workspace].items():
                # Skip expired secrets
                if metadata.expires_at and now > metadata.expires_at:
                    continue

                # Apply label filter
                if filter_labels:
                    match = all(
                        metadata.labels.get(k) == v
                        for k, v in filter_labels.items()
                    )
                    if not match:
                        continue

                secrets.append(Secret(
                    name=name,
                    workspace=workspace,
                    metadata=metadata,
                    value=None,  # Never include value in LIST
                ))

            # Sort by name for consistent ordering
            secrets.sort(key=lambda s: s.name)

            # Handle pagination
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
            if workspace not in self._secrets:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            if name not in self._secrets[workspace]:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            _, metadata = self._secrets[workspace][name]

            # Check expiration
            if metadata.expires_at and datetime.utcnow() > metadata.expires_at:
                del self._secrets[workspace][name]
                raise SecretNotFoundError(f"Secret '{name}' not found")

            return metadata

    def clear(self) -> None:
        """Clear all secrets (for testing)."""
        with self._lock:
            self._secrets.clear()
