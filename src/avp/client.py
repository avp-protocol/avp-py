"""AVP Client - Main entry point for the protocol."""

import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from avp.types import (
    AuthMethod,
    ConformanceLevel,
    DeleteResponse,
    DiscoverResponse,
    ListResponse,
    RetrieveResponse,
    RotateResponse,
    Secret,
    Session,
    StoreResponse,
)
from avp.backends.base import BackendBase
from avp.errors import (
    AuthenticationError,
    InvalidNameError,
    InvalidWorkspaceError,
    SessionExpiredError,
    SessionNotFoundError,
    ValueTooLargeError,
)


class AVPClient:
    """
    AVP Protocol Client.

    This is the main entry point for interacting with the AVP protocol.
    It manages sessions and delegates operations to the configured backend.
    """

    VERSION = "0.1.0"
    DEFAULT_TTL = 3600  # 1 hour

    def __init__(self, backend: BackendBase):
        """
        Initialize the AVP client.

        Args:
            backend: The backend to use for storing secrets
        """
        self._backend = backend
        self._sessions: Dict[str, Session] = {}

    def discover(self) -> DiscoverResponse:
        """
        Query vault capabilities (DISCOVER operation).

        Returns:
            DiscoverResponse with vault information
        """
        return DiscoverResponse(
            version=self.VERSION,
            conformance=ConformanceLevel.FULL,
            backends=[self._backend.get_descriptor()],
            active_backend=self._backend.backend_id,
            capabilities=self._backend.capabilities,
            auth_methods=[AuthMethod.NONE, AuthMethod.TOKEN],
            limits=self._backend.limits,
        )

    def authenticate(
        self,
        workspace: str = "default",
        agent_id: str = "avp-py",
        auth_method: AuthMethod = AuthMethod.NONE,
        auth_data: Optional[Dict[str, str]] = None,
        requested_ttl: Optional[int] = None,
    ) -> Session:
        """
        Establish a session (AUTHENTICATE operation).

        Args:
            workspace: Target workspace
            agent_id: Agent identifier
            auth_method: Authentication method
            auth_data: Authentication credentials
            requested_ttl: Desired session TTL in seconds

        Returns:
            Session object

        Raises:
            AuthenticationError: If authentication fails
            InvalidWorkspaceError: If workspace is invalid
        """
        # Validate workspace
        from avp.types import Workspace
        if not Workspace.validate_id(workspace):
            raise InvalidWorkspaceError(f"Invalid workspace: {workspace}")

        # Handle termination
        if auth_method == AuthMethod.TERMINATE:
            if auth_data and "session_id" in auth_data:
                session_id = auth_data["session_id"]
                if session_id in self._sessions:
                    del self._sessions[session_id]
                return Session(
                    session_id=session_id,
                    workspace=workspace,
                    backend=self._backend.backend_id,
                    agent_id=agent_id,
                    created_at=datetime.utcnow(),
                    expires_at=datetime.utcnow(),
                    ttl_seconds=0,
                )
            raise AuthenticationError("session_id required for termination")

        # For other methods, create a new session
        ttl = min(
            requested_ttl or self.DEFAULT_TTL,
            self._backend.limits.max_session_ttl_seconds,
        )

        now = datetime.utcnow()
        session_id = f"avp_sess_{secrets.token_urlsafe(24)}"

        session = Session(
            session_id=session_id,
            workspace=workspace,
            backend=self._backend.backend_id,
            agent_id=agent_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            ttl_seconds=ttl,
        )

        self._sessions[session_id] = session
        return session

    def _validate_session(self, session_id: str) -> Session:
        """Validate and return a session."""
        if session_id not in self._sessions:
            raise SessionNotFoundError(f"Session not found: {session_id}")

        session = self._sessions[session_id]
        if session.is_expired():
            del self._sessions[session_id]
            raise SessionExpiredError("Session has expired")

        return session

    def store(
        self,
        session_id: str,
        name: str,
        value: bytes,
        labels: Optional[Dict[str, str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> StoreResponse:
        """
        Store a secret (STORE operation).

        Args:
            session_id: Active session identifier
            name: Secret name
            value: Secret value (bytes)
            labels: Optional key-value labels
            expires_at: Optional expiration timestamp

        Returns:
            StoreResponse

        Raises:
            SessionError: If session is invalid
            InvalidNameError: If name is invalid
            ValueTooLargeError: If value exceeds limit
        """
        session = self._validate_session(session_id)

        # Validate name
        if not Secret.validate_name(name):
            raise InvalidNameError(f"Invalid secret name: {name}")

        # Validate value size
        if len(value) > self._backend.limits.max_secret_value_length:
            raise ValueTooLargeError(
                f"Value exceeds maximum size of "
                f"{self._backend.limits.max_secret_value_length} bytes"
            )

        created, version = self._backend.store(
            workspace=session.workspace,
            name=name,
            value=value,
            labels=labels,
            expires_at=expires_at,
        )

        return StoreResponse(
            name=name,
            backend=self._backend.backend_id,
            created=created,
            version=version,
        )

    def retrieve(
        self,
        session_id: str,
        name: str,
        version: Optional[int] = None,
    ) -> RetrieveResponse:
        """
        Retrieve a secret (RETRIEVE operation).

        Args:
            session_id: Active session identifier
            name: Secret name
            version: Optional specific version

        Returns:
            RetrieveResponse with the secret value

        Raises:
            SessionError: If session is invalid
            SecretNotFoundError: If secret doesn't exist
        """
        session = self._validate_session(session_id)

        value, ver = self._backend.retrieve(
            workspace=session.workspace,
            name=name,
            version=version,
        )

        return RetrieveResponse(
            name=name,
            value=value,
            encoding="utf8",
            backend=self._backend.backend_id,
            version=ver,
        )

    def delete(
        self,
        session_id: str,
        name: str,
    ) -> DeleteResponse:
        """
        Delete a secret (DELETE operation).

        Args:
            session_id: Active session identifier
            name: Secret name

        Returns:
            DeleteResponse

        Raises:
            SessionError: If session is invalid
        """
        session = self._validate_session(session_id)

        deleted = self._backend.delete(
            workspace=session.workspace,
            name=name,
        )

        return DeleteResponse(name=name, deleted=deleted)

    def list_secrets(
        self,
        session_id: str,
        filter_labels: Optional[Dict[str, str]] = None,
        cursor: Optional[str] = None,
        limit: int = 100,
    ) -> ListResponse:
        """
        List secrets (LIST operation).

        Args:
            session_id: Active session identifier
            filter_labels: Optional label filter
            cursor: Pagination cursor
            limit: Maximum results

        Returns:
            ListResponse with secrets (no values)

        Raises:
            SessionError: If session is invalid
        """
        session = self._validate_session(session_id)

        secrets_list, next_cursor = self._backend.list_secrets(
            workspace=session.workspace,
            filter_labels=filter_labels,
            cursor=cursor,
            limit=limit,
        )

        return ListResponse(
            secrets=secrets_list,
            cursor=next_cursor,
            has_more=next_cursor is not None,
        )

    def rotate(
        self,
        session_id: str,
        name: str,
        new_value: bytes,
    ) -> RotateResponse:
        """
        Rotate a secret (ROTATE operation).

        Args:
            session_id: Active session identifier
            name: Secret name
            new_value: New secret value

        Returns:
            RotateResponse

        Raises:
            SessionError: If session is invalid
            SecretNotFoundError: If secret doesn't exist
        """
        session = self._validate_session(session_id)

        version = self._backend.rotate(
            workspace=session.workspace,
            name=name,
            new_value=new_value,
        )

        return RotateResponse(
            name=name,
            backend=self._backend.backend_id,
            version=version,
            rotated_at=datetime.utcnow(),
        )

    def close(self) -> None:
        """Close the client and release resources."""
        self._backend.close()
        self._sessions.clear()

    def __enter__(self) -> "AVPClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
