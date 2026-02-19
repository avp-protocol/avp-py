"""AVP Backend implementations."""

from avp.backends.base import BackendBase
from avp.backends.file import FileBackend
from avp.backends.memory import MemoryBackend

# Keychain backend requires optional dependency
try:
    from avp.backends.keychain import KeychainBackend
    KEYCHAIN_AVAILABLE = True
except ImportError:
    KeychainBackend = None  # type: ignore
    KEYCHAIN_AVAILABLE = False

__all__ = ["BackendBase", "FileBackend", "MemoryBackend", "KeychainBackend", "KEYCHAIN_AVAILABLE"]
