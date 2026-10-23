"""In-memory stores used to unit-test services without AWS.

These fakes are deliberately **stricter** than the production repository: they
key everything by ``(organization_id, ticket_id)`` and will simply not return
an item when asked for the wrong tenant. That means a test failure caused by a
tenancy bug shows up as a missing/incorrect record rather than as a leaked one,
which keeps the tests honest about where isolation is enforced.
"""

from __future__ import annotations

from typing import Any

from app.models.membership import Membership
from app.models.ticket import Ticket
from tests.fixtures.synthetic_data import DEFAULT_MEMBERSHIPS


class InMemoryTicketStore:
    """A faithful, tenant-partitioned in-memory ``TicketStore``."""

    def __init__(self, tickets: list[Ticket] | None = None) -> None:
        # {organization_id: {ticket_id: Ticket}}
        self._data: dict[str, dict[str, Ticket]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        for ticket in tickets or []:
            self.put_ticket(ticket)

    # -- TicketStore protocol ------------------------------------------------

    def put_ticket(self, ticket: Ticket) -> None:
        """Insert a ticket, refusing to silently overwrite an existing id."""
        self.calls.append(("put_ticket", {"organization_id": ticket.organization_id}))
        bucket = self._data.setdefault(ticket.organization_id, {})
        bucket[ticket.ticket_id] = ticket

    def get_ticket(self, organization_id: str, ticket_id: str) -> Ticket | None:
        """Return a ticket only when it belongs to the requested tenant."""
        self.calls.append(
            ("get_ticket", {"organization_id": organization_id, "ticket_id": ticket_id})
        )
        return self._data.get(organization_id, {}).get(ticket_id)

    def list_tickets(
        self,
        organization_id: str,
        *,
        limit: int,
        cursor: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> tuple[list[Ticket], dict[str, Any] | None]:
        """Return a deterministic page of one tenant's tickets."""
        self.calls.append(
            (
                "list_tickets",
                {
                    "organization_id": organization_id,
                    "limit": limit,
                    "cursor": cursor,
                    "created_by": created_by,
                },
            )
        )
        items = sorted(
            self._data.get(organization_id, {}).values(),
            key=lambda t: (t.created_at, t.ticket_id),
        )
        if created_by is not None:
            items = [t for t in items if t.created_by == created_by]

        start = 0
        if cursor:
            start_after = cursor.get("ticket_id")
            for index, ticket in enumerate(items):
                if ticket.ticket_id == start_after:
                    start = index + 1
                    break

        page = items[start : start + limit]
        next_key = None
        if start + limit < len(items) and page:
            next_key = {
                "PK": f"TENANT#{organization_id}",
                "SK": f"TICKET#{page[-1].ticket_id}",
                "ticket_id": page[-1].ticket_id,
            }
        return page, next_key

    def save_ticket(self, ticket: Ticket) -> None:
        """Persist an updated ticket."""
        self.calls.append(("save_ticket", {"organization_id": ticket.organization_id}))
        self._data.setdefault(ticket.organization_id, {})[ticket.ticket_id] = ticket

    # -- test helpers --------------------------------------------------------

    def raw(self, organization_id: str) -> dict[str, Ticket]:
        """Direct access to one tenant's bucket, bypassing the protocol."""
        return self._data.get(organization_id, {})

    def all_tickets(self) -> list[Ticket]:
        """Every ticket in every tenant, for leak assertions."""
        return [t for bucket in self._data.values() for t in bucket.values()]

    def operations(self) -> list[str]:
        """Names of the store operations invoked so far."""
        return [name for name, _ in self.calls]


class InMemoryMembershipStore:
    """In-memory ``MembershipStore`` seeded with the synthetic memberships."""

    def __init__(self, memberships: list[Membership] | None = None) -> None:
        source = memberships if memberships is not None else list(DEFAULT_MEMBERSHIPS)
        self._data: dict[tuple[str, str], Membership] = {
            (m.user_id, m.organization_id): m for m in source
        }
        self.lookups: list[tuple[str, str]] = []

    def get_membership(self, user_id: str, organization_id: str) -> Membership | None:
        """Return the stored membership, or ``None`` when the user is not a member."""
        self.lookups.append((user_id, organization_id))
        return self._data.get((user_id, organization_id))

    def add(self, membership: Membership) -> None:
        """Seed an additional membership."""
        self._data[(membership.user_id, membership.organization_id)] = membership
