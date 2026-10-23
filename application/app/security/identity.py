"""Extract the caller's identity from the incoming request.

In AWS the API Gateway JWT authorizer validates the Cognito token and places
the verified claims in the Lambda event. Locally there is no gateway, so the
identity is read from request headers instead.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from app.config import get_settings
from app.models.membership import OrganizationRole
from app.security.errors import NotAuthenticatedError
from app.security.principal import Principal

_CLAIM_USER_ID = "sub"
_CLAIM_ORG_ID = "custom:organization_id"
_CLAIM_ROLE = "custom:role"


def _gateway_claims(request: Request) -> dict[str, Any] | None:
    """Return verified JWT claims from the API Gateway authorizer context."""
    event = request.scope.get("aws.event")
    if not isinstance(event, dict):
        return None
    authorizer = event.get("requestContext", {}).get("authorizer", {})
    claims = authorizer.get("jwt", {}).get("claims")
    if isinstance(claims, dict):
        return claims
    return None


def _header_claims(request: Request) -> dict[str, Any] | None:
    """Return claims supplied directly on the request headers.

    Used for local development and for smoke-testing the API without a
    Cognito user pool in front of it.
    """
    user_id = request.headers.get("X-User-Id")
    org_id = request.headers.get("X-Org-Id")
    if not user_id or not org_id:
        return None
    return {
        _CLAIM_USER_ID: user_id,
        _CLAIM_ORG_ID: org_id,
        _CLAIM_ROLE: request.headers.get("X-Role", "member"),
    }


def extract_principal(request: Request) -> Principal:
    """Build the caller's ``Principal`` for this request.

    Prefers the API Gateway authorizer context. When that is not present --
    for example when running locally -- falls back to the identity headers so
    the API stays usable outside AWS.
    """
    settings = get_settings()

    claims = _gateway_claims(request)
    if claims is None:
        claims = _header_claims(request)
    if claims is None:
        raise NotAuthenticatedError("No identity present on request")

    user_id = claims.get(_CLAIM_USER_ID)
    org_id = claims.get(_CLAIM_ORG_ID)
    if not user_id or not org_id:
        raise NotAuthenticatedError("Identity is missing required claims")

    role_value = claims.get(_CLAIM_ROLE, OrganizationRole.MEMBER.value)
    try:
        role = OrganizationRole(role_value)
    except ValueError:
        role = OrganizationRole.MEMBER

    if settings.debug:
        # Helpful while wiring up Cognito: shows exactly what the gateway sent.
        import logging

        logging.getLogger("app.identity").debug(
            "resolved principal user=%s org=%s role=%s auth_header=%s",
            user_id,
            org_id,
            role,
            request.headers.get("Authorization"),
        )

    return Principal(user_id=user_id, organization_id=org_id, role=role)
