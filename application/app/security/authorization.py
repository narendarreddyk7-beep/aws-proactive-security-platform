"""Authorization policy for ticket operations."""

from __future__ import annotations

from app.models.ticket import Ticket
from app.security.principal import Principal


def can_read_ticket(principal: Principal, ticket: Ticket) -> bool:
    """Return True when the principal may read the ticket."""
    if principal.is_admin:
        return True
    return ticket.created_by == principal.user_id


def can_update_ticket(principal: Principal, ticket: Ticket) -> bool:
    """Return True when the principal may modify the ticket."""
    if principal.is_admin:
        return True
    return ticket.created_by == principal.user_id
