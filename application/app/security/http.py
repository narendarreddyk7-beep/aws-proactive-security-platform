"""HTTP-layer security: response headers and request correlation.

Implemented as a **pure ASGI middleware** rather than Starlette's
``BaseHTTPMiddleware``. That is deliberate: ``BaseHTTPMiddleware`` runs the
downstream application in a separate task, which historically breaks
``ContextVar`` propagation. The request id lives in a ``ContextVar`` and must
be visible to every log call and to the error handlers, so this middleware has
to run in the same task.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.datastructures import MutableHeaders

from app.observability.request_context import sanitize_request_id, set_request_id

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

#: Applied to every response, including error responses (finding F-014).
#:
#: ``Cache-Control: no-store`` is the one that matters most for a multi-tenant
#: API: without it an intermediate cache or a browser can retain one tenant's
#: ticket data and serve it to the next request that looks similar.
#:
#: ``X-Content-Type-Options: nosniff`` stops a JSON body containing
#: customer-supplied text from being re-interpreted as HTML and executed.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Permitted-Cross-Domain-Policies": "none",
    # HSTS is harmless over the API Gateway TLS endpoint and protects any
    # browser-based client from a downgrade on a later request.
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

#: This API returns JSON only, so the strictest possible policy applies. It is
#: skipped for the interactive docs, which load their assets from a CDN and are
#: only ever enabled locally.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

_DOCS_PATHS = frozenset({"/docs", "/redoc", "/docs/oauth2-redirect"})

REQUEST_ID_HEADER = "X-Request-Id"


def apply_security_headers(headers: Any, *, path: str = "") -> None:
    """Add the standard security headers to a header container."""
    for name, value in SECURITY_HEADERS.items():
        headers[name] = value
    if path not in _DOCS_PATHS:
        headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY


class SecurityContextMiddleware:
    """Bind a request id to the context and stamp security headers.

    The request id is taken from the client's ``X-Request-Id`` when it matches
    a strict pattern, and generated otherwise. Accepting an arbitrary client
    value would let a caller inject newlines to forge log records or collide
    with another request's id (finding F-007); the sanitiser in
    ``app.observability.request_context`` is what makes honouring it safe.
    """

    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process one ASGI event stream."""
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        request_id = sanitize_request_id(_header_value(scope, b"x-request-id"))
        set_request_id(request_id)
        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                apply_security_headers(headers, path=path)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        await self._app(scope, receive, send_with_headers)


def _header_value(scope: Scope, name: bytes) -> str | None:
    """Return a single request header value from a raw ASGI scope."""
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            try:
                return value.decode("latin-1")
            except (UnicodeDecodeError, AttributeError):  # pragma: no cover
                return None
    return None
