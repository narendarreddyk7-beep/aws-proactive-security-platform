"""Simulated API Gateway JWT authorizer context.

WHY THIS LIVES IN THE TEST TREE
-------------------------------
In AWS, the HTTP API's JWT authorizer validates the Cognito token (signature,
issuer, audience, expiry) *before* Lambda is invoked, and places the verified
claims at::

    event["requestContext"]["authorizer"]["jwt"]["claims"]

The application reads identity from exactly that location and nowhere else, so
there is no production code path that can be tricked into trusting a header.

To exercise the application without AWS, something has to put a plausible event
into the ASGI scope. That "something" is this file -- a test double, not an
application component. It is never imported by ``app.*``.

The one supported local-development adapter (``IDENTITY_SOURCE=local_test``)
is separate, is refused unless ``ENVIRONMENT=local``, and is covered by its own
fail-closed tests in ``tests/security/test_authentication.py``.
"""

from __future__ import annotations

from typing import Any

CLAIM_SUB = "sub"
CLAIM_ORG = "custom:organization_id"
CLAIM_ROLE = "custom:role"


def gateway_claims(
    user_id: str,
    organization_id: str,
    role: str = "member",
    **extra: Any,
) -> dict[str, Any]:
    """Build a claim set shaped like Cognito access-token claims.

    HTTP API v2 flattens claims to strings, which is why every value here is a
    string even for numeric claims such as ``exp``.
    """
    claims: dict[str, Any] = {
        CLAIM_SUB: user_id,
        CLAIM_ORG: organization_id,
        CLAIM_ROLE: role,
        "token_use": "access",
        "client_id": "synthetic-app-client-id",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_SYNTHETIC",
        "exp": "4102444800",  # 2100-01-01, far future; synthetic
        "iat": "1772323200",
        "scope": "support/tickets.read support/tickets.write",
    }
    claims.update(extra)
    return claims


def build_event(
    claims: dict[str, Any] | None,
    *,
    method: str = "GET",
    path: str = "/v1/health",
    request_id: str = "synthetic-apigw-request-id",
) -> dict[str, Any]:
    """Build a minimal API Gateway HTTP API (payload format 2.0) event."""
    request_context: dict[str, Any] = {
        "accountId": "000000000000",  # synthetic placeholder, not a real account
        "apiId": "synthetic-api-id",
        "domainName": "synthetic.execute-api.us-east-1.amazonaws.com",
        "http": {
            "method": method,
            "path": path,
            "protocol": "HTTP/1.1",
            "sourceIp": "203.0.113.10",  # RFC 5737 documentation range
            "userAgent": "pytest",
        },
        "requestId": request_id,
        "routeKey": f"{method} {path}",
        "stage": "v1",
    }
    if claims is not None:
        request_context["authorizer"] = {"jwt": {"claims": claims, "scopes": None}}

    return {
        "version": "2.0",
        "routeKey": f"{method} {path}",
        "rawPath": path,
        "headers": {},
        "requestContext": request_context,
        "isBase64Encoded": False,
    }


class GatewayEventInjector:
    """ASGI wrapper that places a synthetic gateway event into the scope.

    Usage::

        injector = GatewayEventInjector(app)
        client = TestClient(injector)

        injector.authenticate_as(USER_A_MEMBER, ORG_A, "member")
        client.get("/v1/tickets")          # arrives with verified claims

        injector.anonymous()
        client.get("/v1/tickets")          # arrives with no authorizer context
    """

    def __init__(self, app: Any) -> None:
        self._app = app
        self._claims: dict[str, Any] | None = None
        self._event_override: dict[str, Any] | None = None
        self._inject = True

    # -- configuration -------------------------------------------------------

    def authenticate_as(
        self,
        user_id: str,
        organization_id: str,
        role: str = "member",
        **extra: Any,
    ) -> GatewayEventInjector:
        """Present verified claims for the given synthetic identity."""
        self._claims = gateway_claims(user_id, organization_id, role, **extra)
        self._event_override = None
        self._inject = True
        return self

    def with_claims(self, claims: dict[str, Any] | None) -> GatewayEventInjector:
        """Present an arbitrary (possibly malformed) claim set."""
        self._claims = claims
        self._event_override = None
        self._inject = True
        return self

    def with_event(self, event: dict[str, Any]) -> GatewayEventInjector:
        """Present a fully hand-built Lambda event."""
        self._event_override = event
        self._inject = True
        return self

    def anonymous(self) -> GatewayEventInjector:
        """Present a gateway event with no authorizer context at all.

        This is what API Gateway would produce for a route that is *not*
        protected by the authorizer. A protected route would never invoke
        Lambda at all without a valid token, so this is the strictest
        locally-reproducible "unauthenticated" case.
        """
        self._claims = None
        self._event_override = None
        self._inject = True
        return self

    def no_aws_event(self) -> GatewayEventInjector:
        """Simulate the application running outside Lambda entirely.

        Nothing is placed in the ASGI scope -- this is the shape of a direct
        request to the ASGI app, e.g. a developer running uvicorn, or an
        attacker who found a way to reach the app bypassing the gateway.
        """
        self._claims = None
        self._event_override = None
        self._inject = False
        return self

    # -- ASGI ----------------------------------------------------------------

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """Inject the event, then delegate to the wrapped application."""
        if scope.get("type") == "http" and self._inject:
            scope = dict(scope)
            if self._event_override is not None:
                scope["aws.event"] = self._event_override
            else:
                path = scope.get("path", "/")
                method = scope.get("method", "GET")
                scope["aws.event"] = build_event(self._claims, method=method, path=path)
            scope["aws.context"] = None
        await self._app(scope, receive, send)
