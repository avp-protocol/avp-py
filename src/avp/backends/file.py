"""Encrypted file backend for AVP."""

import base64
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import threading

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    EncryptionError,
    IntegrityError,
)


class FileBackend(BackendBase):
    """
    Encrypted file-based backend.

    Secrets are encrypted using Fernet (AES-128-CBC with HMAC).
    The encryption key is derived from a password using PBKDF2.
    """

    def __init__(
        self,
        path: str,
        password: str,
        backend_id: str = "file-0",
    ):
        """
        Initialize the file backend.

        Args:
            path: Path to the secrets file
            password: Encryption password
            backend_id: Unique backend identifier
        """
        self._path = Path(path)
        self._backend_id = backend_id
        self._lock = threading.RLock()

        # Derive encryption key from password
        self._fernet = self._create_fernet(password)

        # Load or create the secrets file
        self._data: Dict[str, Any] = self._load()

    def _create_fernet(self, password: str) -> Fernet:
        """Create a Fernet instance from password."""
        # Use a fixed salt for simplicity (in production, store salt with data)
        salt = b"avp_file_backend_v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def _load(self) -> Dict[str, Any]:
        """Load secrets from file."""
        if not self._path.exists():
            return {"version": 1, "workspaces": {}}

        # Check if file is empty
        if self._path.stat().st_size == 0:
            return {"version": 1, "workspaces": {}}

        try:
            encrypted_data = self._path.read_bytes()
            decrypted = self._fernet.decrypt(encrypted_data)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt secrets file: {e}")

    def _save(self) -> None:
        """Save secrets to file."""
        try:
            json_data = json.dumps(self._data, default=self._json_serializer)
            encrypted = self._fernet.encrypt(json_data.encode("utf-8"))

            # Write atomically
            temp_path = self._path.with_suffix(".tmp")
            temp_path.write_bytes(encrypted)
            temp_path.replace(self._path)

            # Set restrictive permissions
            os.chmod(self._path, 0o600)
        except Exception as e:
            raise EncryptionError(f"Failed to save secrets file: {e}")

    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """JSON serializer for datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, BackendType):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    @property
    def backend_type(self) -> BackendType:
        return BackendType.FILE

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
            migration=True,
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
            "path": str(self._path),
            "encryption": "Fernet (AES-128-CBC + HMAC)",
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
            if "workspaces" not in self._data:
                self._data["workspaces"] = {}

            if workspace not in self._data["workspaces"]:
                self._data["workspaces"][workspace] = {}

            now = datetime.utcnow()
            ws = self._data["workspaces"][workspace]
            created = name not in ws

            if created:
                version = 1
                created_at = now.isoformat()
            else:
                version = ws[name]["metadata"]["version"] + 1
                created_at = ws[name]["metadata"]["created_at"]

            # Store value as base64
            ws[name] = {
                "value": base64.b64encode(value).decode("ascii"),
                "metadata": {
                    "created_at": created_at,
                    "updated_at": now.isoformat(),
                    "backend": "file",
                    "version": version,
                    "labels": labels or {},
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            }

            self._save()
            return created, version

    def retrieve(
        self,
        workspace: str,
        name: str,
        version: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        with self._lock:
            ws = self._data.get("workspaces", {}).get(workspace, {})

            if name not in ws:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            secret = ws[name]
            metadata = secret["metadata"]

            # Check expiration
            if metadata.get("expires_at"):
                expires_at = datetime.fromisoformat(metadata["expires_at"])
                if datetime.utcnow() > expires_at:
                    del ws[name]
                    self._save()
                    raise SecretNotFoundError(f"Secret '{name}' not found")

            # Version check
            if version is not None and version != metadata["version"]:
                raise SecretNotFoundError(
                    f"Secret '{name}' version {version} not found"
                )

            value = base64.b64decode(secret["value"])
            return value, metadata["version"]

    def delete(self, workspace: str, name: str) -> bool:
        with self._lock:
            ws = self._data.get("workspaces", {}).get(workspace, {})

            if name not in ws:
                return False

            # Overwrite value before deleting
            ws[name]["value"] = base64.b64encode(b"\x00" * 32).decode("ascii")
            del ws[name]

            self._save()
            return True

    def list_secrets(
        self,
        workspace: str,
        filter_labels: Optional[Dict[str, str]] = None,
        cursor: Optional[str] = None,
        limit: int = 100,
    ) -> Tuple[List[Secret], Optional[str]]:
        with self._lock:
            ws = self._data.get("workspaces", {}).get(workspace, {})

            secrets = []
            now = datetime.utcnow()

            for name, data in ws.items():
                metadata_dict = data["metadata"]

                # Check expiration
                if metadata_dict.get("expires_at"):
                    expires_at = datetime.fromisoformat(metadata_dict["expires_at"])
                    if now > expires_at:
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
                    backend=BackendType.FILE,
                    version=metadata_dict["version"],
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

            # Sort by name
            secrets.sort(key=lambda s: s.name)

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
            ws = self._data.get("workspaces", {}).get(workspace, {})

            if name not in ws:
                raise SecretNotFoundError(f"Secret '{name}' not found")

            metadata_dict = ws[name]["metadata"]

            # Check expiration
            if metadata_dict.get("expires_at"):
                expires_at = datetime.fromisoformat(metadata_dict["expires_at"])
                if datetime.utcnow() > expires_at:
                    del ws[name]
                    self._save()
                    raise SecretNotFoundError(f"Secret '{name}' not found")

            return SecretMetadata(
                created_at=datetime.fromisoformat(metadata_dict["created_at"]),
                updated_at=datetime.fromisoformat(metadata_dict["updated_at"]),
                backend=BackendType.FILE,
                version=metadata_dict["version"],
                labels=metadata_dict.get("labels", {}),
                expires_at=(
                    datetime.fromisoformat(metadata_dict["expires_at"])
                    if metadata_dict.get("expires_at")
                    else None
                ),
            )

    def close(self) -> None:
        """Ensure data is saved before closing."""
        with self._lock:
            self._save()
