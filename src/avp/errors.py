"""AVP Protocol Error Types"""

from typing import Optional, Dict, Any


class AVPError(Exception):
    """Base exception for all AVP errors."""

    code: str = "AVP_ERROR"

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.detail = detail or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary format."""
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
            }
        }


class AuthenticationError(AVPError):
    """Authentication failed."""
    code = "AUTHENTICATION_FAILED"


class SessionError(AVPError):
    """Session-related error."""
    code = "SESSION_ERROR"


class SessionExpiredError(SessionError):
    """Session has expired."""
    code = "SESSION_EXPIRED"


class SessionTerminatedError(SessionError):
    """Session was terminated."""
    code = "SESSION_TERMINATED"


class SessionNotFoundError(SessionError):
    """Session does not exist."""
    code = "SESSION_NOT_FOUND"


class SecretNotFoundError(AVPError):
    """Secret does not exist."""
    code = "SECRET_NOT_FOUND"


class InvalidNameError(AVPError):
    """Invalid secret or workspace name."""
    code = "INVALID_NAME"


class InvalidWorkspaceError(AVPError):
    """Invalid workspace identifier."""
    code = "INVALID_WORKSPACE"


class CapacityExceededError(AVPError):
    """Backend storage capacity exceeded."""
    code = "CAPACITY_EXCEEDED"


class BackendError(AVPError):
    """Backend operation failed."""
    code = "BACKEND_ERROR"


class BackendUnavailableError(BackendError):
    """Backend is not available."""
    code = "BACKEND_UNAVAILABLE"


class RateLimitError(AVPError):
    """Rate limit exceeded."""
    code = "RATE_LIMIT_EXCEEDED"


class ValueTooLargeError(AVPError):
    """Secret value exceeds maximum size."""
    code = "VALUE_TOO_LARGE"


class EncryptionError(AVPError):
    """Encryption or decryption failed."""
    code = "ENCRYPTION_ERROR"


class IntegrityError(AVPError):
    """Data integrity check failed."""
    code = "INTEGRITY_ERROR"


# Error code to exception class mapping
ERROR_MAP: Dict[str, type] = {
    "AUTHENTICATION_FAILED": AuthenticationError,
    "SESSION_ERROR": SessionError,
    "SESSION_EXPIRED": SessionExpiredError,
    "SESSION_TERMINATED": SessionTerminatedError,
    "SESSION_NOT_FOUND": SessionNotFoundError,
    "SECRET_NOT_FOUND": SecretNotFoundError,
    "INVALID_NAME": InvalidNameError,
    "INVALID_WORKSPACE": InvalidWorkspaceError,
    "CAPACITY_EXCEEDED": CapacityExceededError,
    "BACKEND_ERROR": BackendError,
    "BACKEND_UNAVAILABLE": BackendUnavailableError,
    "RATE_LIMIT_EXCEEDED": RateLimitError,
    "VALUE_TOO_LARGE": ValueTooLargeError,
    "ENCRYPTION_ERROR": EncryptionError,
    "INTEGRITY_ERROR": IntegrityError,
}


def from_error_response(response: Dict[str, Any]) -> AVPError:
    """Create an exception from an error response dict."""
    error_data = response.get("error", {})
    code = error_data.get("code", "AVP_ERROR")
    message = error_data.get("message", "Unknown error")
    detail = error_data.get("detail", {})

    error_class = ERROR_MAP.get(code, AVPError)
    return error_class(message=message, code=code, detail=detail)
