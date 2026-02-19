"""
Agent Vault Protocol (AVP) - Python SDK

A secure credential management protocol for AI agents.
"""

from avp.types import (
    Secret,
    SecretMetadata,
    Session,
    Workspace,
    Backend,
    BackendType,
    Capabilities,
    Limits,
    RotationPolicy,
    AuthMethod,
)
from avp.errors import (
    AVPError,
    AuthenticationError,
    SessionError,
    SessionExpiredError,
    SessionNotFoundError,
    SecretNotFoundError,
    InvalidNameError,
    CapacityExceededError,
    BackendError,
)
from avp.client import AVPClient
from avp.backends.file import FileBackend
from avp.backends.memory import MemoryBackend

__version__ = "0.1.0"
__all__ = [
    # Types
    "Secret",
    "SecretMetadata",
    "Session",
    "Workspace",
    "Backend",
    "BackendType",
    "Capabilities",
    "Limits",
    "RotationPolicy",
    "AuthMethod",
    # Errors
    "AVPError",
    "AuthenticationError",
    "SessionError",
    "SessionExpiredError",
    "SessionNotFoundError",
    "SecretNotFoundError",
    "InvalidNameError",
    "CapacityExceededError",
    "BackendError",
    # Client
    "AVPClient",
    # Backends
    "FileBackend",
    "MemoryBackend",
]
