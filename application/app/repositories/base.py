"""Storage protocols.

Services depend on these protocols rather than on boto3, so business rules and
authorization can be unit-tested against an in-memory fake with no AWS calls
and no credentials.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.models.ticket import Ticket


class TicketStore(Protocol):
    """Tenant-scoped persistence for support tickets."""

    def put_ticket(self, ticket: Ticket) -> None:
        """Persist a new ticket."""
        ...

    def get_ticket(self, organization_id: str, ticket_id: str) -> Ticket | None:
        """Return one ticket, or ``None`` when it does not exist."""
        ...

    def list_tickets(
        self,
        organization_id: str,
        *,
        limit: int,
        cursor: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> tuple[list[Ticket], dict[str, Any] | None]:
        """Return a page of tickets and the next ``LastEvaluatedKey``."""
        ...

    def save_ticket(self, ticket: Ticket) -> None:
        """Persist an updated ticket."""
        ...
