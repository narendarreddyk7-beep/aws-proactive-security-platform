"""Ticket service unit tests.

The service is where authorization is enforced, so these tests exercise it
directly against an in-memory store -- no HTTP, no AWS. That isolation makes
it possible to assert things the HTTP tests cannot easily see, such as "the
store was never called at all".
"""

from __future__ import annotations

import pytest

from app.models.membership import OrganizationRole
from app.models.ticket import (
    TicketCreateRequest,
    TicketStatus,
    TicketUpdateRequest,
)
from app.security.errors import AuthorizationError, ConflictError, ResourceNotFoundError
from app.security.principal import Principal
from app.services.ticket_service import TicketService
from tests.fixtures.fake_store import InMemoryTicketStore
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    TICKET_A2,
    TICKET_B1,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    make_ticket,
)

pytestmark = pytest.mark.unit

ADMIN = Principal(user_id=USER_A_ADMIN, organization_id=ORG_A, role=OrganizationRole.ADMIN)
MEMBER = Principal(user_id=USER_A_MEMBER, organization_id=ORG_A, role=OrganizationRole.MEMBER)
OTHER_TENANT = Principal(
    user_id="99999999-9999-4999-8999-999999999999",
    organization_id=ORG_B,
    role=OrganizationRole.ADMIN,
)

UNKNOWN_TICKET = "77777777-7777-4777-8777-777777777777"


@pytest.fixture
def store() -> InMemoryTicketStore:
    """A store seeded with two org-A tickets and one org-B ticket."""
    return InMemoryTicketStore(
        [
            make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, created_by=USER_A_MEMBER),
            make_ticket(ticket_id=TICKET_A2, organization_id=ORG_A, created_by=USER_A_MEMBER_2),
            make_ticket(ticket_id=TICKET_B1, organization_id=ORG_B),
        ]
    )


@pytest.fixture
def service(store: InMemoryTicketStore) -> TicketService:
    """Service under test."""
    return TicketService(store)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def test_create_takes_tenancy_and_owner_from_the_principal(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """The two fields an attacker would want to control are not inputs."""
    ticket = service.create_ticket(
        MEMBER, TicketCreateRequest(title="New", description="Synthetic")
    )

    assert ticket.organization_id == ORG_A
    assert ticket.created_by == USER_A_MEMBER
    assert ticket.status is TicketStatus.OPEN
    assert store.raw(ORG_A)[ticket.ticket_id] == ticket


def test_create_generates_a_unique_server_side_identifier(service: TicketService) -> None:
    """Two creates with identical payloads must not collide."""
    payload = TicketCreateRequest(title="Same", description="Same")
    first = service.create_ticket(MEMBER, payload)
    second = service.create_ticket(MEMBER, payload)
    assert first.ticket_id != second.ticket_id


def test_create_sets_matching_timestamps(service: TicketService) -> None:
    """A newly created ticket has never been updated."""
    ticket = service.create_ticket(MEMBER, TicketCreateRequest(title="t", description="d"))
    assert ticket.created_at == ticket.updated_at


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def test_owner_can_read_their_ticket(service: TicketService) -> None:
    """The happy path."""
    assert service.get_ticket(MEMBER, TICKET_A1).ticket_id == TICKET_A1


def test_admin_can_read_any_ticket_in_the_organization(service: TicketService) -> None:
    """Admin reach is organization-wide."""
    assert service.get_ticket(ADMIN, TICKET_A2).ticket_id == TICKET_A2


@pytest.mark.security
def test_member_reading_another_members_ticket_is_forbidden(service: TicketService) -> None:
    """403: the ticket exists in the caller's tenant, but is not theirs."""
    with pytest.raises(AuthorizationError):
        service.get_ticket(MEMBER, TICKET_A2)


@pytest.mark.security
@pytest.mark.regression
def test_cross_tenant_read_is_not_found_rather_than_forbidden(
    service: TicketService,
) -> None:
    """Guards finding F-008.

    A 403 here would confirm that org A's ticket exists. Because the read is
    partition-scoped, the service genuinely cannot tell the difference between
    "another tenant's ticket" and "no such ticket" -- so the honest answer and
    the safe answer are the same one.
    """
    with pytest.raises(ResourceNotFoundError):
        service.get_ticket(OTHER_TENANT, TICKET_A1)


def test_unknown_ticket_is_not_found(service: TicketService) -> None:
    """A genuinely absent ticket behaves identically to the cross-tenant case."""
    with pytest.raises(ResourceNotFoundError):
        service.get_ticket(MEMBER, UNKNOWN_TICKET)


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


def test_admin_listing_is_organization_scoped(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """An admin sees the whole org, and the store is asked for exactly that."""
    tickets, cursor = service.list_tickets(ADMIN, limit=50)

    assert {t.ticket_id for t in tickets} == {TICKET_A1, TICKET_A2}
    assert cursor is None
    assert store.calls[-1][1]["created_by"] is None


@pytest.mark.security
def test_member_listing_is_narrowed_in_the_query(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """The author filter is pushed into the store call, not applied after.

    This is the assertion that distinguishes "we filtered the results" from
    "we never read them" (findings F-003, F-006).
    """
    tickets, _ = service.list_tickets(MEMBER, limit=50)

    assert {t.ticket_id for t in tickets} == {TICKET_A1}
    assert store.calls[-1][1]["created_by"] == USER_A_MEMBER


@pytest.mark.security
def test_list_never_asks_the_store_for_another_tenant(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """The tenant passed to the store is always the principal's."""
    service.list_tickets(MEMBER, limit=10)
    service.list_tickets(ADMIN, limit=10)
    service.list_tickets(OTHER_TENANT, limit=10)

    organizations = [kwargs["organization_id"] for _, kwargs in store.calls]
    assert organizations == [ORG_A, ORG_A, ORG_B]


def test_list_emits_a_cursor_when_more_pages_exist(service: TicketService) -> None:
    """Pagination is wired end to end through the service."""
    _, cursor = service.list_tickets(ADMIN, limit=1)
    assert cursor is not None

    second, _ = service.list_tickets(ADMIN, limit=1, cursor=cursor)
    assert second and second[0].ticket_id == TICKET_A2


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


def test_owner_can_update_permitted_fields(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """Only the four client-writable fields change."""
    before = store.raw(ORG_A)[TICKET_A1]
    updated = service.update_ticket(
        MEMBER, TICKET_A1, TicketUpdateRequest(title="Reworded", priority="high")
    )

    assert updated.title == "Reworded"
    assert updated.priority.value == "high"
    assert updated.created_by == before.created_by
    assert updated.organization_id == before.organization_id
    assert updated.created_at == before.created_at
    assert updated.updated_at > before.updated_at


@pytest.mark.security
@pytest.mark.regression
def test_member_cannot_update_another_members_ticket(
    service: TicketService, store: InMemoryTicketStore
) -> None:
    """Guards finding F-003 -- the path that had no authorization check."""
    before = store.raw(ORG_A)[TICKET_A2]
    with pytest.raises(AuthorizationError):
        service.update_ticket(MEMBER, TICKET_A2, TicketUpdateRequest(title="Hijacked"))

    assert store.raw(ORG_A)[TICKET_A2] == before, "The ticket changed despite the denial"


@pytest.mark.security
@pytest.mark.regression
def test_cross_tenant_update_is_not_found(service: TicketService) -> None:
    """Guards findings F-001 and F-008."""
    with pytest.raises(ResourceNotFoundError):
        service.update_ticket(OTHER_TENANT, TICKET_A1, TicketUpdateRequest(title="x"))


@pytest.mark.security
@pytest.mark.regression
def test_member_cannot_close_a_ticket(service: TicketService) -> None:
    """Guards finding F-013: closing is a privileged transition."""
    with pytest.raises(AuthorizationError):
        service.update_ticket(MEMBER, TICKET_A1, TicketUpdateRequest(status=TicketStatus.CLOSED))


def test_admin_can_close_a_ticket(service: TicketService) -> None:
    """Guards finding F-013: the privileged transition works for admins."""
    updated = service.update_ticket(
        ADMIN, TICKET_A1, TicketUpdateRequest(status=TicketStatus.CLOSED)
    )
    assert updated.status is TicketStatus.CLOSED


@pytest.mark.security
@pytest.mark.regression
def test_illegal_transition_is_a_conflict_not_a_denial() -> None:
    """Guards finding F-013.

    403 and 409 mean different things: the caller *is* allowed to update this
    ticket, the ticket is simply in a state that does not permit the move.
    Conflating them would make the API confusing and the logs misleading.
    """
    store = InMemoryTicketStore(
        [
            make_ticket(
                ticket_id=TICKET_A1,
                organization_id=ORG_A,
                created_by=USER_A_MEMBER,
                status=TicketStatus.CLOSED,
            )
        ]
    )
    service = TicketService(store)

    with pytest.raises(ConflictError):
        service.update_ticket(
            ADMIN, TICKET_A1, TicketUpdateRequest(status=TicketStatus.IN_PROGRESS)
        )


def test_reasserting_the_current_status_is_accepted(service: TicketService) -> None:
    """An idempotent retry must not be rejected as an illegal transition."""
    updated = service.update_ticket(
        MEMBER, TICKET_A1, TicketUpdateRequest(status=TicketStatus.OPEN)
    )
    assert updated.status is TicketStatus.OPEN


def test_update_of_unknown_ticket_is_not_found(service: TicketService) -> None:
    """No implicit create through the update path."""
    with pytest.raises(ResourceNotFoundError):
        service.update_ticket(ADMIN, UNKNOWN_TICKET, TicketUpdateRequest(title="x"))
