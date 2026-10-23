"""Data-access scoping tests (DynamoDB).

These tests assert the *mechanism* of tenant isolation at the storage layer,
using an in-process DynamoDB (``moto``) and a wrapper that records every API
call the repository makes.

Why assert the mechanism rather than only the result? Because a ``Scan`` with a
``FilterExpression`` on ``organization_id`` produces the right answer today
while leaving isolation dependent on a filter that any future refactor can
drop. A key-scoped ``Query`` cannot return another tenant's items at all --
DynamoDB will not read outside the partition. The security property should come
from the access pattern, not from remembering to filter.
"""

from __future__ import annotations

import pytest

from app.models.ticket import TicketStatus
from app.repositories.keys import tenant_pk, ticket_sk
from app.repositories.ticket_repository import DynamoDbTicketRepository
from tests.fixtures.recording_table import condition_values
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    TICKET_A2,
    TICKET_B1,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    USER_B_MEMBER,
    make_ticket,
)

pytestmark = [pytest.mark.security, pytest.mark.integration]


@pytest.fixture
def repository(recording_table) -> DynamoDbTicketRepository:
    """A repository bound to the recording moto table, seeded cross-tenant."""
    repo = DynamoDbTicketRepository(table=recording_table)
    repo.put_ticket(make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, created_by=USER_A_MEMBER))
    repo.put_ticket(
        make_ticket(ticket_id=TICKET_A2, organization_id=ORG_A, created_by=USER_A_MEMBER_2)
    )
    repo.put_ticket(make_ticket(ticket_id=TICKET_B1, organization_id=ORG_B, created_by=USER_B_MEMBER))
    recording_table.calls.clear()
    return repo


# ---------------------------------------------------------------------------
# F-006: no Scan in a user-facing read path
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_listing_never_uses_scan(repository: DynamoDbTicketRepository, recording_table) -> None:
    """Guards finding F-006 (CWE-285 and resource exhaustion).

    A ``Scan`` reads every item in the table -- including every other tenant's
    -- and bills for it. It must never appear in a user-facing read path.
    """
    repository.list_tickets(ORG_A, limit=10)

    operations = recording_table.operations()
    assert "scan" not in operations, f"Repository performed a Scan: {operations}"
    assert "query" in operations, f"Expected a Query, saw {operations}"


@pytest.mark.regression
def test_query_key_condition_pins_the_tenant_partition(
    repository: DynamoDbTicketRepository, recording_table
) -> None:
    """Guards finding F-006.

    The key condition must constrain the partition key to the caller's tenant
    and the sort key to the ticket prefix, so the query is physically unable to
    return another tenant's items or a non-ticket record.
    """
    repository.list_tickets(ORG_A, limit=10)

    query = recording_table.calls_to("query")[0]
    values = condition_values(query.kwargs["KeyConditionExpression"])

    assert "#PK" in values
    assert tenant_pk(ORG_A) in values, f"Key condition did not pin the tenant: {values}"
    assert "TICKET#" in values, f"Key condition did not pin the entity prefix: {values}"
    assert tenant_pk(ORG_B) not in values


@pytest.mark.regression
def test_member_listing_uses_an_index_scoped_to_tenant_and_user(
    repository: DynamoDbTicketRepository, recording_table
) -> None:
    """Guards findings F-003 and F-006.

    A member's listing must be narrowed in the key condition, not filtered in
    Python after the fact -- otherwise the coworker's tickets were read from
    the database (and billed, and present in memory) before being discarded.
    """
    repository.list_tickets(ORG_A, limit=10, created_by=USER_A_MEMBER)

    assert "scan" not in recording_table.operations()
    query = recording_table.calls_to("query")[0]

    assert query.kwargs.get("IndexName") == "GSI1"
    values = condition_values(query.kwargs["KeyConditionExpression"])
    assert any(ORG_A in value and USER_A_MEMBER in value for value in values), (
        f"GSI1 key condition is not scoped to tenant+user: {values}"
    )
    assert "FilterExpression" not in query.kwargs or USER_A_MEMBER_2 not in condition_values(
        query.kwargs.get("FilterExpression", "")
    )


def test_listing_returns_only_the_requested_tenant(repository: DynamoDbTicketRepository) -> None:
    """The functional outcome of the key-scoped query."""
    tickets, _ = repository.list_tickets(ORG_A, limit=50)
    assert {t.ticket_id for t in tickets} == {TICKET_A1, TICKET_A2}

    tickets_b, _ = repository.list_tickets(ORG_B, limit=50)
    assert {t.ticket_id for t in tickets_b} == {TICKET_B1}


def test_member_listing_returns_only_their_own_tickets(
    repository: DynamoDbTicketRepository,
) -> None:
    """Index-scoped listing returns the right rows as well as reading the right rows."""
    tickets, _ = repository.list_tickets(ORG_A, limit=50, created_by=USER_A_MEMBER)
    assert {t.ticket_id for t in tickets} == {TICKET_A1}


# ---------------------------------------------------------------------------
# Point reads and writes
# ---------------------------------------------------------------------------


def test_get_item_key_is_tenant_scoped(
    repository: DynamoDbTicketRepository, recording_table
) -> None:
    """A point read addresses exactly one item in exactly one tenant partition."""
    repository.get_ticket(ORG_A, TICKET_A1)

    call = recording_table.calls_to("get_item")[0]
    assert call.kwargs["Key"] == {"PK": tenant_pk(ORG_A), "SK": ticket_sk(TICKET_A1)}


def test_cross_tenant_point_read_returns_none(repository: DynamoDbTicketRepository) -> None:
    """Asking tenant A's partition for tenant B's ticket simply finds nothing."""
    assert repository.get_ticket(ORG_A, TICKET_B1) is None
    assert repository.get_ticket(ORG_B, TICKET_A1) is None


@pytest.mark.regression
def test_create_refuses_to_overwrite_an_existing_ticket(
    repository: DynamoDbTicketRepository,
) -> None:
    """Guards finding F-015.

    An unconditional ``PutItem`` silently replaces whatever was at the key. A
    conditional write turns an id collision into a visible error instead of
    destroying a record.
    """
    from app.security.errors import ConflictError

    duplicate = make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, title="Overwrite attempt")
    with pytest.raises(ConflictError):
        repository.put_ticket(duplicate)

    stored = repository.get_ticket(ORG_A, TICKET_A1)
    assert stored is not None
    assert stored.title != "Overwrite attempt"


@pytest.mark.regression
def test_save_requires_the_ticket_to_already_exist(
    repository: DynamoDbTicketRepository, recording_table
) -> None:
    """Guards finding F-015.

    ``save_ticket`` is an update, so it must assert existence. Without that
    condition a racing delete would be resurrected as a partial record, and a
    bug in the service layer could create a ticket through the update path --
    bypassing the create-time authorization checks.
    """
    from app.security.errors import ConflictError

    ghost = make_ticket(
        ticket_id="cccccccc-1111-4111-8111-cccccccccccc",
        organization_id=ORG_A,
        status=TicketStatus.RESOLVED,
    )
    with pytest.raises(ConflictError):
        repository.save_ticket(ghost)

    write_calls = [
        call
        for call in recording_table.calls
        if call.operation in {"put_item", "update_item"}
    ]
    assert write_calls, "No write was attempted"
    assert all("ConditionExpression" in call.kwargs for call in write_calls), (
        "A write was issued with no ConditionExpression"
    )


def test_updates_are_persisted_within_the_tenant_partition(
    repository: DynamoDbTicketRepository,
) -> None:
    """A legitimate update round-trips and stays in its own partition."""
    ticket = repository.get_ticket(ORG_A, TICKET_A1)
    assert ticket is not None

    updated = ticket.model_copy(update={"status": TicketStatus.RESOLVED})
    repository.save_ticket(updated)

    assert repository.get_ticket(ORG_A, TICKET_A1).status is TicketStatus.RESOLVED  # type: ignore[union-attr]
    assert repository.get_ticket(ORG_B, TICKET_A1) is None


# ---------------------------------------------------------------------------
# F-010: cursors at the repository boundary
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_repository_rejects_a_cursor_from_another_partition(
    repository: DynamoDbTicketRepository,
) -> None:
    """Guards finding F-010 — defence in depth below the HTTP layer.

    The route layer validates cursors, but the repository must not rely on
    that: it is a reusable component and the next caller may not validate.
    """
    from app.security.errors import ValidationFailedError

    foreign_cursor = {"PK": tenant_pk(ORG_B), "SK": ticket_sk(TICKET_B1)}
    with pytest.raises(ValidationFailedError):
        repository.list_tickets(ORG_A, limit=10, cursor=foreign_cursor)


@pytest.mark.regression
def test_repository_clamps_the_page_size(
    repository: DynamoDbTicketRepository, recording_table
) -> None:
    """Guards finding F-009 — defence in depth below the HTTP layer."""
    repository.list_tickets(ORG_A, limit=100_000)

    query = recording_table.calls_to("query")[0]
    assert query.kwargs["Limit"] <= 100, query.kwargs["Limit"]
