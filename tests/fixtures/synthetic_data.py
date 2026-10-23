"""Synthetic tenants, users, and tickets used across the test suite.

Two organizations are modelled so every test can express a cross-tenant
expectation:

* ``org-northwind``  -- the "caller's" tenant in most tests.
* ``org-contoso``    -- the "other" tenant that must never be reachable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.membership import Membership, OrganizationRole
from app.models.ticket import Ticket, TicketPriority, TicketStatus

ORG_A = "org-northwind"
ORG_B = "org-contoso"

USER_A_ADMIN = "11111111-1111-4111-8111-111111111111"
USER_A_MEMBER = "22222222-2222-4222-8222-222222222222"
USER_A_MEMBER_2 = "33333333-3333-4333-8333-333333333333"
USER_B_MEMBER = "44444444-4444-4444-8444-444444444444"
USER_UNAFFILIATED = "55555555-5555-4555-8555-555555555555"

TICKET_A1 = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
TICKET_A2 = "aaaaaaaa-2222-4222-8222-aaaaaaaaaaaa"
TICKET_B1 = "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"

FIXED_TIME = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)

# A string that would be damaging if it ever appeared in a log line.
SENSITIVE_DESCRIPTION = (
    "Customer reported login failure. Reference internal case SYNTHETIC-9910. "
    "Contact placeholder: person@example.invalid"
)

DEFAULT_MEMBERSHIPS: tuple[Membership, ...] = (
    Membership(user_id=USER_A_ADMIN, organization_id=ORG_A, role=OrganizationRole.ADMIN),
    Membership(user_id=USER_A_MEMBER, organization_id=ORG_A, role=OrganizationRole.MEMBER),
    Membership(user_id=USER_A_MEMBER_2, organization_id=ORG_A, role=OrganizationRole.MEMBER),
    Membership(user_id=USER_B_MEMBER, organization_id=ORG_B, role=OrganizationRole.MEMBER),
)


def make_ticket(
    *,
    ticket_id: str = TICKET_A1,
    organization_id: str = ORG_A,
    created_by: str = USER_A_MEMBER,
    title: str = "Unable to access account",
    description: str = SENSITIVE_DESCRIPTION,
    priority: TicketPriority = TicketPriority.MEDIUM,
    status: TicketStatus = TicketStatus.OPEN,
) -> Ticket:
    """Build a synthetic ticket with deterministic timestamps."""
    return Ticket(
        ticket_id=ticket_id,
        organization_id=organization_id,
        created_by=created_by,
        title=title,
        description=description,
        priority=priority,
        status=status,
        created_at=FIXED_TIME,
        updated_at=FIXED_TIME,
    )
