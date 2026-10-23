"""FastAPI dependency wiring.

Construction lives here so routes depend on interfaces, and a test can replace
one dependency to swap in an in-memory store with no AWS involved.

``get_principal`` is the application's authentication *and* authorization gate.
Every protected route depends on it, which means:

* there is exactly one place to review the identity trust decision, and
* a route that forgets to depend on it has no principal to pass to the service
  layer, so it will not compile into something that silently works.
"""

from __future__ import annotations

from fastapi import Depends, Request

from app.repositories.base import TicketStore
from app.repositories.membership_repository import (
    DynamoDbMembershipRepository,
    MembershipStore,
)
from app.repositories.ticket_repository import DynamoDbTicketRepository
from app.security.identity import IdentityProvider, resolve_principal
from app.security.principal import Principal
from app.services.ticket_service import TicketService


def get_ticket_store() -> TicketStore:
    """Return the configured ticket store."""
    return DynamoDbTicketRepository()


def get_membership_store() -> MembershipStore:
    """Return the configured membership store."""
    return DynamoDbMembershipRepository()


def get_identity_provider(request: Request) -> IdentityProvider:
    """Return the identity provider chosen at application startup.

    Built once in ``create_app`` rather than per request: the choice depends
    only on configuration, and constructing the local adapter emits a warning
    that should appear once at cold start, not on every invocation.
    """
    return request.app.state.identity_provider  # type: ignore[no-any-return]


def get_principal(
    request: Request,
    provider: IdentityProvider = Depends(get_identity_provider),
    memberships: MembershipStore = Depends(get_membership_store),
) -> Principal:
    """Resolve, and authorize, the caller for this request.

    Two distinct failures:

    * **401** -- no trusted identity was present (``NotAuthenticatedError``).
    * **403** -- the identity is real, but is not an active member of the
      organization in its token (``AuthorizationError``).

    Returning a ``Principal`` means both the authentication and the membership
    checks passed, so downstream code never has to wonder.
    """
    identity = provider.extract(request)
    return resolve_principal(identity, memberships)


def get_ticket_service(
    store: TicketStore = Depends(get_ticket_store),
) -> TicketService:
    """Return a ticket service bound to the configured store."""
    return TicketService(store)
