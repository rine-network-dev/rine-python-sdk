"""Structured error hierarchy with actionable messages for AI agent self-correction.

All errors include three components: what failed, why, and what to try.
"""

from __future__ import annotations


class RineError(Exception):
    """Base exception for all Rine SDK errors."""


class RineApiError(RineError):
    """HTTP API error with status code and detail.

    Args:
        status: HTTP status code.
        detail: Human-readable error description.
        raw: Optional raw response body.
    """

    def __init__(self, status: int, detail: str, raw: object = None) -> None:
        self.status = status
        self.detail = detail
        self.raw = raw
        super().__init__(f"{status}: {detail}")


class AuthenticationError(RineApiError):
    """401 — invalid or missing credentials.

    Check credentials: verify ``RINE_CLIENT_ID``/``RINE_CLIENT_SECRET`` env vars
    or ``credentials.json`` in your config directory.
    """

    def __init__(self, detail: str = "Authentication failed", raw: object = None) -> None:
        super().__init__(401, detail, raw)


class AuthorizationError(RineApiError):
    """403 — insufficient permissions for the requested operation."""

    def __init__(self, detail: str = "Permission denied", raw: object = None) -> None:
        super().__init__(403, detail, raw)


class NotFoundError(RineApiError):
    """404 — the requested resource was not found.

    Check the identifier format: ``name@org`` for handles,
    UUID for direct IDs. Search the directory: ``client.discover()``.
    """

    def __init__(self, detail: str = "Resource not found", raw: object = None) -> None:
        super().__init__(404, detail, raw)


class ConflictError(RineApiError):
    """409 — resource conflict (e.g., duplicate slug or agent name)."""

    def __init__(self, detail: str = "Conflict", raw: object = None) -> None:
        super().__init__(409, detail, raw)


class RateLimitError(RineApiError):
    """429 — rate limit exceeded.

    Attributes:
        retry_after: Seconds to wait before retrying, if provided by server.
    """

    def __init__(
        self, detail: str = "Rate limit exceeded", retry_after: float | None = None,
        raw: object = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(429, detail, raw)


class ValidationError(RineApiError):
    """422 — request validation failed."""

    def __init__(self, detail: str = "Validation error", raw: object = None) -> None:
        super().__init__(422, detail, raw)


class InternalServerError(RineApiError):
    """500 — unexpected server error."""

    def __init__(self, detail: str = "Internal server error", raw: object = None) -> None:
        super().__init__(500, detail, raw)


class ServiceUnavailableError(RineApiError):
    """503 — service temporarily unavailable."""

    def __init__(self, detail: str = "Service unavailable", raw: object = None) -> None:
        super().__init__(503, detail, raw)


class APITimeoutError(RineError):
    """Request timed out — the server did not respond in time."""


class APIConnectionError(RineError):
    """Network-level failure — could not reach the server."""


class CryptoError(RineError):
    """Encryption or decryption failure.

    Messages include recovery suggestions (e.g., fetch sender keys, regenerate keys).
    """


class ConfigError(RineError):
    """Missing or invalid SDK configuration.

    Messages include setup instructions (e.g., run ``rine onboard``).
    """


_STATUS_MAP: dict[int, type[RineApiError]] = {
    401: AuthenticationError,
    403: AuthorizationError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError,
    429: RateLimitError,
    500: InternalServerError,
    503: ServiceUnavailableError,
}


def raise_for_status(status: int, detail: str, raw: object = None) -> None:
    """Raise the appropriate error class for an HTTP status code.

    Args:
        status: HTTP status code.
        detail: Error detail string.
        raw: Optional raw response body.

    Raises:
        RineApiError: Subclass matching the status code.
    """
    cls = _STATUS_MAP.get(status)
    if cls:
        raise cls(detail=detail, raw=raw)
    raise RineApiError(status, detail, raw)


def format_error(err: BaseException) -> str:
    """Format an error for display.

    Args:
        err: Any exception.

    Returns:
        Human-readable error string.
    """
    if isinstance(err, RineApiError):
        return err.detail
    if isinstance(err, Exception):
        return str(err)
    return str(err)
