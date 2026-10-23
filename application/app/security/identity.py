"""Establishing *who* is calling.

TRUST BOUNDARY
--------------
Everything an HTTP client can influence -- headers, query string, body, cookies
-- is attacker-controlled. The only trustworthy statement of identity available
to this application is the claim set that the **API Gateway JWT authorizer**
validated and placed into the Lambda event::

    event["requestContext"]["authorizer"]["jwt"]["claims"]

The gateway has already verified the token's signature against the Cognito
JWKS, its issuer, its audience/client id, and its expiry. A request that fails
any of those never reaches this code.

This module therefore has exactly one job: **read identity from that location
and from nowhere else.** The original implementation fell back to
``X-User-Id`` / ``X-Org-Id`` headers when the authorizer context was missing,
which made every tenant readable by anyone who could reach the function
(finding F-001). That fallback is gone.

AUTHENTICATION IS NOT AUTHORIZATION
-----------------------------------
A verified token says "Cognito believes this is user ``sub``". It does *not*
establish that the user belongs to the organization named in the token, nor
what role they hold there -- a token is a cached snapshot, and a user demoted
or removed five minutes ago still carries one asserting the old state.

So the claim set is only the first half. :func:`resolve_principal` then
consults the server-side membership record, which is authoritative for both
membership and role (finding F-002).
"""

from __future__ import annotations

from typing import Any, Protocol

from fastapi import Request
from pydantic import BaseModel, ConfigDict

from app.config import Settings
from app.models.membership import OrganizationRole
from app.observability.logging import get_logger
from app.repositories.membership_repository import MembershipStore
from app.security.errors import AuthorizationError, NotAuthenticatedError
from app.security.principal import Principal

logger = get_logger("app.security.identity")

CLAIM_USER_ID = "sub"
CLAIM_ORGANIZATION_ID = "custom:organization_id"
CLAIM_ROLE = "custom:role"

#: Headers the local-development adapter reads. Deliberately prefixed
#: ``X-Local-`` so they can never be confused with a real identity header, and
#: so a WAF rule can strip anything matching ``X-Local-*`` at the edge.
LOCAL_USER_HEADER = "X-Local-User-Id"
LOCAL_ORG_HEADER = "X-Local-Org-Id"
LOCAL_ROLE_HEADER = "X-Local-Role"


class VerifiedIdentity(BaseModel):
    """Identity as asserted by a trusted source, before authorization."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    organization_id: str
    #: The role the token *claims*. Advisory only -- never used for a decision.
    claimed_role: str | None = None


class IdentityProvider(Protocol):
    """Extracts a :class:`VerifiedIdentity` from an incoming request."""

    def extract(self, request: Request) -> VerifiedIdentity | None:
        """Return the identity, or ``None`` when the request carries none."""
        ...


def _clean(value: Any) -> str | None:
    """Return a non-empty, whitespace-stripped string, or ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


class ApiGatewayJwtIdentityProvider:
    """Reads identity from the API Gateway JWT authorizer context.

    This is the only provider used in any deployed environment.
    """

    def extract(self, request: Request) -> VerifiedIdentity | None:
        """Return the identity carried by the verified authorizer context."""
        event = request.scope.get("aws.event")
        if not isinstance(event, dict):
            # Not running behind API Gateway at all. There is no trusted
            # identity to be had, so the request is unauthenticated.
            return None

        request_context = event.get("requestContext")
        if not isinstance(request_context, dict):
            return None

        authorizer = request_context.get("authorizer")
        if not isinstance(authorizer, dict):
            return None

        # Specifically `authorizer.jwt`. A REQUEST (Lambda) authorizer puts its
        # context under `authorizer.lambda`; reading that would accept an
        # identity that never went through JWT validation, so it is ignored.
        jwt_context = authorizer.get("jwt")
        if not isinstance(jwt_context, dict):
            return None

        claims = jwt_context.get("claims")
        if not isinstance(claims, dict):
            return None

        user_id = _clean(claims.get(CLAIM_USER_ID))
        organization_id = _clean(claims.get(CLAIM_ORGANIZATION_ID))
        if not user_id or not organization_id:
            return None

        return VerifiedIdentity(
            user_id=user_id,
            organization_id=organization_id,
            claimed_role=_clean(claims.get(CLAIM_ROLE)),
        )


class LocalTestIdentityProvider:
    """Reads identity from ``X-Local-*`` request headers. **LOCAL ONLY.**

    This is a deliberate authentication bypass that exists so the API can be
    exercised with ``curl`` on a laptop without standing up a Cognito user
    pool (see ``docs/DEMO.md``).

    Three independent controls keep it out of a deployed environment:

    1. ``Settings`` refuses to load when ``identity_source='local_test'`` and
       ``environment != 'local'`` -- the Lambda fails to initialise.
    2. Terraform sets ``APP_IDENTITY_SOURCE=gateway`` explicitly on the
       function, so the value is never absent in AWS.
    3. ``gateway`` is the default, so even an unset variable is safe.

    Guarded by ``tests/security/test_authentication.py``.
    """

    def __init__(self, settings: Settings) -> None:
        if settings.environment != "local":
            # Belt and braces: even if the Settings guard were removed, this
            # provider refuses to exist outside a local environment.
            raise RuntimeError(
                "LocalTestIdentityProvider may only be constructed when "
                f"environment='local' (got '{settings.environment}')."
            )
        logger.warning(
            "insecure local identity adapter enabled",
            extra={"event_type": "insecure_identity_adapter_enabled", "outcome": "allowed"},
        )

    def extract(self, request: Request) -> VerifiedIdentity | None:
        """Return the identity asserted by the local development headers."""
        user_id = _clean(request.headers.get(LOCAL_USER_HEADER))
        organization_id = _clean(request.headers.get(LOCAL_ORG_HEADER))
        if not user_id or not organization_id:
            return None
        return VerifiedIdentity(
            user_id=user_id,
            organization_id=organization_id,
            claimed_role=_clean(request.headers.get(LOCAL_ROLE_HEADER)),
        )


def build_identity_provider(settings: Settings) -> IdentityProvider:
    """Return the identity provider for the current configuration."""
    if settings.identity_source == "local_test":
        return LocalTestIdentityProvider(settings)
    return ApiGatewayJwtIdentityProvider()


def resolve_principal(
    identity: VerifiedIdentity | None,
    memberships: MembershipStore,
) -> Principal:
    """Turn a verified identity into an authorized :class:`Principal`.

    Raises:
        NotAuthenticatedError: no trusted identity was present (401).
        AuthorizationError: the identity is real but is not an active member
            of the organization it claims (403).
    """
    if identity is None:
        logger.warning(
            "request rejected: no trusted identity",
            extra={"event_type": "authentication_failed", "outcome": "denied"},
        )
        raise NotAuthenticatedError("Authentication is required.")

    membership = memberships.get_membership(identity.user_id, identity.organization_id)

    if membership is None:
        logger.warning(
            "request rejected: no membership record",
            extra={
                "event_type": "authorization_denied",
                "outcome": "denied",
                "reason": "no_membership",
                "principal_id": identity.user_id,
                "organization_id": identity.organization_id,
            },
        )
        raise AuthorizationError("Access to this organization is not permitted.")

    if membership.status != "active":
        logger.warning(
            "request rejected: membership not active",
            extra={
                "event_type": "authorization_denied",
                "outcome": "denied",
                "reason": "membership_inactive",
                "principal_id": identity.user_id,
                "organization_id": identity.organization_id,
            },
        )
        raise AuthorizationError("Access to this organization is not permitted.")

    # The membership record wins. A mismatch means the token is stale or
    # someone is probing, and either way it is worth seeing in the logs.
    if identity.claimed_role and identity.claimed_role != membership.role.value:
        logger.warning(
            "token role claim does not match membership record",
            extra={
                "event_type": "role_claim_mismatch",
                "outcome": "allowed",
                "reason": "membership_record_is_authoritative",
                "principal_id": identity.user_id,
                "organization_id": identity.organization_id,
            },
        )

    return Principal(
        user_id=identity.user_id,
        organization_id=identity.organization_id,
        role=OrganizationRole(membership.role),
    )
