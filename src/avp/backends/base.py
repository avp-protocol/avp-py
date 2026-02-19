"""Base backend interface for AVP."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from avp.types import (
    Backend,
    BackendType,
    Capabilities,
    Limits,
    Secret,
    SecretMetadata,
)


class BackendBase(ABC):
    """Abstract base class for AVP backends."""

    @property
    @abstractmethod
    def backend_type(self) -> BackendType:
        """Return the backend type."""
        pass

    @property
    @abstractmethod
    def backend_id(self) -> str:
        """Return a unique backend identifier."""
        pass

    @property
    def capabilities(self) -> Capabilities:
        """Return backend capabilities."""
        return Capabilities()

    @property
    def limits(self) -> Limits:
        """Return backend limits."""
        return Limits()

    def get_descriptor(self) -> Backend:
        """Get the backend descriptor."""
        return Backend(
            type=self.backend_type,
            id=self.backend_id,
            status="available",
            info=self.get_info(),
        )

    def get_info(self) -> Dict[str, str]:
        """Get backend-specific information."""
        return {}

    @abstractmethod
    def store(
        self,
        workspace: str,
        name: str,
        value: bytes,
        labels: Optional[Dict[str, str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> Tuple[bool, int]:
        """
        Store a secret.

        Args:
            workspace: Workspace identifier
            name: Secret name
            value: Secret value (bytes)
            labels: Optional key-value labels
            expires_at: Optional expiration timestamp

        Returns:
            Tuple of (created, version) where created is True if new secret
        """
        pass

    @abstractmethod
    def retrieve(
        self,
        workspace: str,
        name: str,
        version: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        """
        Retrieve a secret value.

        Args:
            workspace: Workspace identifier
            name: Secret name
            version: Optional specific version

        Returns:
            Tuple of (value, version)

        Raises:
            SecretNotFoundError: If secret doesn't exist
        """
        pass

    @abstractmethod
    def delete(self, workspace: str, name: str) -> bool:
        """
        Delete a secret.

        Args:
            workspace: Workspace identifier
            name: Secret name

        Returns:
            True if secret existed and was deleted, False otherwise
        """
        pass

    @abstractmethod
    def list_secrets(
        self,
        workspace: str,
        filter_labels: Optional[Dict[str, str]] = None,
        cursor: Optional[str] = None,
        limit: int = 100,
    ) -> Tuple[List[Secret], Optional[str]]:
        """
        List secrets in a workspace.

        Args:
            workspace: Workspace identifier
            filter_labels: Optional label filter
            cursor: Pagination cursor
            limit: Maximum number of results

        Returns:
            Tuple of (secrets, next_cursor)
        """
        pass

    @abstractmethod
    def get_metadata(self, workspace: str, name: str) -> SecretMetadata:
        """
        Get secret metadata without the value.

        Args:
            workspace: Workspace identifier
            name: Secret name

        Returns:
            Secret metadata

        Raises:
            SecretNotFoundError: If secret doesn't exist
        """
        pass

    def rotate(
        self,
        workspace: str,
        name: str,
        new_value: bytes,
    ) -> int:
        """
        Rotate a secret value.

        Args:
            workspace: Workspace identifier
            name: Secret name
            new_value: New secret value

        Returns:
            New version number

        Raises:
            SecretNotFoundError: If secret doesn't exist
        """
        # Default implementation: verify exists, then store
        self.get_metadata(workspace, name)  # Raises if not found
        _, version = self.store(workspace, name, new_value)
        return version

    def close(self) -> None:
        """Close the backend and release resources."""
        pass
