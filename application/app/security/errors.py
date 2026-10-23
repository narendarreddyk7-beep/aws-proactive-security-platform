"""Application-level security and validation errors.

These are raised by services/repositories and translated into HTTP responses by
handlers registered in ``app.main``. Keeping them framework-free means the
business rules can be unit-tested without an HTTP client.
"""

from __future__ import annotations


class AppError(Exception):
    """Base class for all errors this application raises deliberately."""

    http_status: int = 500
    error_code: str = "internal_error"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class NotAuthenticatedError(AppError):
    """No trusted authenticated identity was present on the request."""

    http_status = 401
    error_code = "not_authenticated"


class AuthorizationError(AppError):
    """An authenticated principal attempted an action it is not permitted."""

    http_status = 403
    error_code = "forbidden"


class ResourceNotFoundError(AppError):
    """The requested resource does not exist within the caller's tenant."""

    http_status = 404
    error_code = "not_found"


class ValidationFailedError(AppError):
    """Client input failed a business or format validation rule."""

    http_status = 400
    error_code = "invalid_request"


class ConflictError(AppError):
    """The request conflicts with the current state of the resource."""

    http_status = 409
    error_code = "conflict"
