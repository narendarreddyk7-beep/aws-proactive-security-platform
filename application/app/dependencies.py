"""FastAPI dependency wiring.

Keeping construction here means routes depend on interfaces, and tests can
override a single dependency to swap in an in-memory store.
"""

from __future__ import annotations

from fastapi import Depends, Request

from app.repositories.base import TicketStore
from app.repositories.membership_repository import (
    DynamoDbMembershipRepository,
    MembershipStore,
)
from app.repositories.ticket_repository import DynamoDbTicketRepository
from app.security.identity import extract_principal
from app.security.principal import Principal
from app.services.ticket_service import TicketService


def get_ticket_store() -> TicketStore:
    """Return the configured ticket store."""
    return DynamoDbTicketRepository()


def get_membership_store() -> MembershipStore:
    """Return the configured membership store."""
    return DynamoDbMembershipRepository()


def get_principal(request: Request) -> Principal:
    """Resolve the authenticated caller for this request."""
    return extract_principal(request)


def get_ticket_service(
    store: TicketStore = Depends(get_ticket_store),
) -> TicketService:
    """Return a ticket service bound to the configured store."""
    return TicketService(store)
