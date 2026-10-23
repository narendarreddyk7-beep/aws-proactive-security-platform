"""Application entry point.

Exposes:

* ``app``     -- the ASGI application (uvicorn locally, and the test harness).
* ``handler`` -- the Mangum-wrapped AWS Lambda handler, referenced by
  ``infrastructure/terraform/lambda.tf`` as ``app.main.handler``.

ERROR RESPONSE CONTRACT
-----------------------
Every error returns the same envelope::

    {"error": "<machine_readable_code>",
     "message": "<safe human sentence>",
     "request_id": "<correlation id>"}

plus a ``fields`` list for schema-validation failures. Nothing else. No stack
trace, no exception text, no module path, no library name (finding F-008). The
detail an engineer needs goes to CloudWatch, correlated by ``request_id`` --
which is the right way round: the operator gets the diagnostics, the attacker
gets a sentence.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mangum import Mangum
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.config import Settings, get_settings
from app.observability.logging import configure_logging, get_logger
from app.observability.request_context import get_request_id
from app.routes import health, tickets
from app.security.errors import AppError
from app.security.http import (
    REQUEST_ID_HEADER,
    SecurityContextMiddleware,
    apply_security_headers,
)
from app.security.identity import build_identity_provider

logger = get_logger("app.main")

GENERIC_INTERNAL_MESSAGE = "An internal error occurred."

#: Status code -> machine-readable error code for framework-raised HTTP errors.
_HTTP_ERROR_CODES: dict[int, str] = {
    404: "not_found",
    405: "method_not_allowed",
    415: "unsupported_media_type",
}


def _error_response(
    status_code: int,
    error_code: str,
    message: str,
    *,
    path: str = "",
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build an error response with the standard envelope and headers.

    Security headers are applied here as well as in the middleware because the
    unhandled-exception handler runs *outside* the user middleware stack
    (Starlette's ``ServerErrorMiddleware`` is the outermost layer), so a 500
    would otherwise ship without them.
    """
    content: dict[str, Any] = {
        "error": error_code,
        "message": message,
        "request_id": get_request_id(),
    }
    if extra:
        content.update(extra)

    response = JSONResponse(status_code=status_code, content=content)
    apply_security_headers(response.headers, path=path)
    response.headers[REQUEST_ID_HEADER] = get_request_id()
    return response


def _sanitize_validation_errors(exc: RequestValidationError) -> list[dict[str, str]]:
    """Reduce Pydantic errors to location + reason, dropping submitted values.

    FastAPI's default 422 body includes ``input`` -- the offending value. For a
    support API that is a real exposure: validation errors are routinely
    captured by gateways, proxies and client-side error reporters, so echoing
    a submitted ticket description widens where that content can end up
    (finding F-008). The caller still learns which field was wrong and why.
    """
    sanitized: list[dict[str, str]] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()) if part != "body")
        sanitized.append(
            {
                "field": location or "body",
                "reason": str(error.get("msg", "invalid"))[:200],
                "type": str(error.get("type", "value_error")),
            }
        )
    return sanitized


def _register_exception_handlers(application: FastAPI) -> None:
    """Install the error-response contract."""

    @application.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        """Translate a deliberate application error into its HTTP response."""
        logger.info(
            "request rejected",
            extra={
                "event_type": "request_rejected",
                "outcome": "denied",
                "error_code": exc.error_code,
                "reason": exc.detail or exc.error_code,
                "http_status": exc.http_status,
                "http_method": request.method,
                "http_path": request.url.path,
            },
        )
        return _error_response(exc.http_status, exc.error_code, exc.message, path=request.url.path)

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return field-level reasons without echoing submitted values."""
        fields = _sanitize_validation_errors(exc)
        logger.info(
            "request failed validation",
            extra={
                "event_type": "request_validation_failed",
                "outcome": "denied",
                "error_code": "invalid_request",
                "http_status": 422,
                "http_method": request.method,
                "http_path": request.url.path,
                "changed_fields": [entry["field"] for entry in fields],
            },
        )
        return _error_response(
            422,
            "invalid_request",
            "The request did not match the expected schema.",
            path=request.url.path,
            extra={"fields": fields},
        )

    @application.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Normalise framework 404/405/415 responses into the envelope.

        The default body is ``{"detail": "Not Found"}``; replacing it keeps one
        parseable shape for clients and avoids leaking routing hints.
        """
        error_code = _HTTP_ERROR_CODES.get(exc.status_code, "request_failed")
        messages = {
            404: "The requested resource was not found.",
            405: "That method is not allowed for this resource.",
            415: "That media type is not supported.",
        }
        return _error_response(
            exc.status_code,
            error_code,
            messages.get(exc.status_code, "The request could not be completed."),
            path=request.url.path,
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        """Log the failure in full; return nothing diagnostic to the caller."""
        logger.exception(
            "unhandled application error",
            extra={
                "event_type": "unhandled_error",
                "outcome": "error",
                "error_code": "internal_error",
                "http_status": 500,
                "http_method": request.method,
                "http_path": request.url.path,
                # The exception *type* only. It makes 500s groupable in
                # CloudWatch ("are these all ClientError?") without putting the
                # message -- which may carry data -- into a structured field.
                # The full trace is attached by logger.exception, log-side only.
                "reason": type(exc).__name__,
            },
        )
        return _error_response(
            500, "internal_error", GENERIC_INTERNAL_MESSAGE, path=request.url.path
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    configure_logging()
    settings = settings or get_settings()

    application = FastAPI(
        title="Multi-Tenant Customer Support API",
        description=(
            "Support ticket management with organization-level data isolation. "
            "Authentication is performed by the API Gateway JWT authorizer; this "
            "service reads identity only from the verified authorizer context."
        ),
        version=__version__,
        # Published API surface is a local-development affordance (F-012).
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        # No implicit 307 to the trailing-slash variant: a redirect changes the
        # effective route and makes "which handler ran?" ambiguous in review.
        redirect_slashes=False,
    )

    # Added first, so it is the OUTERMOST middleware: the request id must be
    # bound before anything else runs, and the headers must be stamped on
    # whatever response comes back -- including CORS short-circuits.
    application.add_middleware(SecurityContextMiddleware)

    allowed_origins = settings.allowed_origins
    if allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            # Explicit, not "*": the API only has these verbs, and a wildcard
            # with credentials is what makes a CSRF-style read possible.
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
            max_age=600,
        )

    _register_exception_handlers(application)

    # Chosen once at cold start; see app.dependencies.get_identity_provider.
    application.state.identity_provider = build_identity_provider(settings)

    application.include_router(health.router)
    application.include_router(tickets.router)

    logger.info(
        "application initialised",
        extra={
            "event_type": "application_started",
            "outcome": "allowed",
            "reason": f"identity_source={settings.identity_source}",
        },
    )
    return application


app = create_app()

#: AWS Lambda handler. ``lifespan="off"`` because there is nothing to start or
#: stop per invocation and a lifespan cycle would add cold-start latency.
handler = Mangum(app, lifespan="off")


if __name__ == "__main__":  # pragma: no cover - local developer convenience
    import os

    import uvicorn

    # Loopback by default: a development server should not be reachable from
    # the network without the operator explicitly asking for it. Bandit flagged
    # the original hardcoded 0.0.0.0 as B104/CWE-605.
    uvicorn.run(
        app,
        host=os.environ.get("APP_BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("APP_BIND_PORT", "8000")),
        # Suppress the version banner so the server does not fingerprint itself.
        server_header=False,
        date_header=True,
    )
