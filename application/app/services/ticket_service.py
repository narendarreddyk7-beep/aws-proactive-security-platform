"""Ticket business rules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.models.ticket import (
    Ticket,
    TicketCreateRequest,
    TicketPriority,
    TicketStatus,
    TicketUpdateRequest,
)
from app.observability.logging import get_logger
from app.repositories.base import TicketStore
from app.security.authorization import can_read_ticket
from app.security.errors import AuthorizationError, ResourceNotFoundError
from app.security.principal import Principal

logger = get_logger("app.services.ticket")


class TicketService:
    """Create, read, list and update support tickets."""

    def __init__(self, store: TicketStore) -> None:
        self._store = store

    def create_ticket(self, principal: Principal, payload: TicketCreateRequest) -> Ticket:
        """Create a new ticket for the caller's organization."""
        now = datetime.now(tz=UTC)
        organization_id = payload.organization_id or principal.organization_id

        ticket = Ticket(
            ticket_id=str(uuid.uuid4()),
            organization_id=organization_id,
            created_by=principal.user_id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority or TicketPriority.MEDIUM,
            status=TicketStatus.OPEN,
            created_at=now,
            updated_at=now,
        )
        self._store.put_ticket(ticket)
        logger.info(
            "ticket created",
            extra={
                "event_type": "ticket_created",
                "ticket": ticket.model_dump(mode="json"),
            },
        )
        return ticket

    def get_ticket(self, principal: Principal, ticket_id: str) -> Ticket:
        """Return a single ticket the caller is permitted to read."""
        ticket = self._store.get_ticket(principal.organization_id, ticket_id)
        if ticket is None:
            raise ResourceNotFoundError(f"Ticket {ticket_id} not found")

        if not can_read_ticket(principal, ticket):
            raise AuthorizationError(
                f"User {principal.user_id} may not read ticket {ticket_id} "
                f"owned by {ticket.created_by} in organization {ticket.organization_id}"
            )
        return ticket

    def list_tickets(
        self,
        principal: Principal,
        *,
        limit: int,
        cursor: dict[str, Any] | None = None,
    ) -> tuple[list[Ticket], dict[str, Any] | None]:
        """Return a page of tickets for the caller's organization."""
        return self._store.list_tickets(
            principal.organization_id,
            limit=limit,
            cursor=cursor,
        )

    def update_ticket(
        self,
        principal: Principal,
        ticket_id: str,
        payload: TicketUpdateRequest,
    ) -> Ticket:
        """Apply a partial update to a ticket."""
        ticket = self._store.get_ticket(principal.organization_id, ticket_id)
        if ticket is None:
            raise ResourceNotFoundError(f"Ticket {ticket_id} not found")

        changes = payload.model_dump(exclude_unset=True)
        current = ticket.model_dump(mode="json")
        current.update(changes)
        current["updated_at"] = datetime.now(tz=UTC).isoformat()

        updated = Ticket.model_validate(current)
        self._store.save_ticket(updated)
        logger.info(
            "ticket updated",
            extra={"event_type": "ticket_updated", "changes": changes},
        )
        return updated
