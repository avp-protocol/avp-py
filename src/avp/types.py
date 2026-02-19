"""AVP Protocol Types"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
import re


class BackendType(Enum):
    """Backend storage types."""
    FILE = "file"
    KEYCHAIN = "keychain"
    HARDWARE = "hardware"
    REMOTE = "remote"
    MEMORY = "memory"


class AuthMethod(Enum):
    """Authentication methods."""
    NONE = "none"
    PIN = "pin"
    TOKEN = "token"
    MTLS = "mtls"
    OS = "os"
    TERMINATE = "terminate"


class ConformanceLevel(Enum):
    """Protocol conformance levels."""
    CORE = "core"
    FULL = "full"
    HARDWARE = "hardware"


@dataclass
class RotationPolicy:
    """Secret rotation configuration."""
    interval_seconds: int
    strategy: str  # "generate" or "notify"
    last_rotated_at: Optional[datetime] = None


@dataclass
class SecretMetadata:
    """Non-sensitive metadata about a secret."""
    created_at: datetime
    updated_at: datetime
    backend: BackendType
    version: int = 1
    labels: Dict[str, str] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    rotation_policy: Optional[RotationPolicy] = None


@dataclass
class Secret:
    """A credential stored in the vault."""
    name: str
    workspace: str
    metadata: SecretMetadata
    value: Optional[bytes] = None  # Only populated on RETRIEVE

    # Name validation pattern
    NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.\-]{0,254}$")

    @classmethod
    def validate_name(cls, name: str) -> bool:
        """Validate a secret name according to AVP spec."""
        if not name or len(name) > 255:
            return False
        return bool(cls.NAME_PATTERN.match(name))


@dataclass
class Workspace:
    """A logical isolation boundary for secrets."""
    id: str
    secrets_count: int = 0

    # Workspace ID validation pattern
    ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-/]{0,254}$")

    @classmethod
    def validate_id(cls, workspace_id: str) -> bool:
        """Validate a workspace ID according to AVP spec."""
        if not workspace_id or len(workspace_id) > 255:
            return False
        return bool(cls.ID_PATTERN.match(workspace_id))


@dataclass
class Session:
    """An authenticated context for AVP operations."""
    session_id: str
    workspace: str
    backend: str
    agent_id: str
    created_at: datetime
    expires_at: datetime
    ttl_seconds: int

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the session is still valid."""
        return not self.is_expired()


@dataclass
class Backend:
    """Backend descriptor."""
    type: BackendType
    id: str
    status: str  # "available", "unavailable", "locked"
    info: Dict[str, str] = field(default_factory=dict)


@dataclass
class Capabilities:
    """Vault capability flags."""
    attestation: bool = False
    rotation: bool = False
    injection: bool = False
    audit: bool = True
    migration: bool = False
    implicit_sessions: bool = False
    expiration: bool = True
    versioning: bool = False


@dataclass
class Limits:
    """Operational limits."""
    max_secret_name_length: int = 255
    max_secret_value_length: int = 65536
    max_labels_per_secret: int = 64
    max_secrets_per_workspace: int = 1000
    max_session_ttl_seconds: int = 86400


@dataclass
class DiscoverResponse:
    """Response from DISCOVER operation."""
    version: str
    conformance: ConformanceLevel
    backends: List[Backend]
    active_backend: str
    capabilities: Capabilities
    auth_methods: List[AuthMethod]
    limits: Limits


@dataclass
class StoreResponse:
    """Response from STORE operation."""
    name: str
    backend: str
    created: bool
    version: int


@dataclass
class RetrieveResponse:
    """Response from RETRIEVE operation."""
    name: str
    value: bytes
    encoding: str
    backend: str
    version: int


@dataclass
class DeleteResponse:
    """Response from DELETE operation."""
    name: str
    deleted: bool


@dataclass
class ListResponse:
    """Response from LIST operation."""
    secrets: List[Secret]
    cursor: Optional[str] = None
    has_more: bool = False


@dataclass
class RotateResponse:
    """Response from ROTATE operation."""
    name: str
    backend: str
    version: int
    rotated_at: datetime
