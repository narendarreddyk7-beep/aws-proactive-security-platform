"""DynamoDB repository integration tests against an in-process table (moto).

The table definition in ``conftest.dynamodb_table`` mirrors
``infrastructure/terraform/dynamodb.tf``. If the two diverge -- a renamed
index, a changed key schema -- these tests fail, which is the cheapest
available substitute for deploying on every change.

Limitation: moto emulates DynamoDB, it is not DynamoDB. Conditional-write and
``ValidationException`` semantics are asserted against that emulation. See
``docs/TESTING.md`` for what that does and does not prove.
"""

from __future__ import annotations

import pytest

from app.models.membership import OrganizationRole
from app.models.ticket import TicketPriority, TicketStatus
from app.repositories.keys import membership_sk, tenant_pk, ticket_sk, user_pk
from app.repositories.membership_repository import DynamoDbMembershipRepository
from app.repositories.ticket_repository import DynamoDbTicketRepository
from app.security.errors import ConflictError
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    USER_A_ADMIN,
    USER_A_MEMBER,
    make_ticket,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------


def test_round_trip_preserves_every_field(dynamodb_table) -> None:
    """Serialisation must not quietly lose or mangle a field."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    original = make_ticket(priority=TicketPriority.URGENT, status=TicketStatus.IN_PROGRESS)

    repo.put_ticket(original)
    loaded = repo.get_ticket(ORG_A, original.ticket_id)

    assert loaded == original


def test_stored_item_carries_the_documented_keys(dynamodb_table) -> None:
    """The physical item shape is a contract with Terraform and the runbooks."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    ticket = make_ticket(created_by=USER_A_MEMBER)
    repo.put_ticket(ticket)

    item = dynamodb_table.get_item(Key={"PK": tenant_pk(ORG_A), "SK": ticket_sk(ticket.ticket_id)})[
        "Item"
    ]

    assert item["PK"] == f"TENANT#{ORG_A}"
    assert item["SK"] == f"TICKET#{ticket.ticket_id}"
    assert item["GSI1PK"] == f"TENANT#{ORG_A}#USER#{USER_A_MEMBER}"
    assert item["GSI1SK"].startswith("CREATED#")
    assert item["entity_type"] == "ticket"


def test_internal_attributes_never_escape_the_repository(dynamodb_table) -> None:
    """``PK``/``SK``/``GSI1*`` must not appear on the domain object.

    ``Ticket`` uses ``extra="forbid"``, so a leak here is a hard failure
    rather than an extra field that rides along into an API response.
    """
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    ticket = make_ticket()
    repo.put_ticket(ticket)

    loaded = repo.get_ticket(ORG_A, ticket.ticket_id)
    assert loaded is not None
    assert not {"PK", "SK", "GSI1PK", "GSI1SK", "entity_type"} & set(loaded.model_dump())


def test_get_returns_none_for_a_missing_ticket(dynamodb_table) -> None:
    """A missing item is ``None``, not an exception."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    assert repo.get_ticket(ORG_A, TICKET_A1) is None


@pytest.mark.security
def test_two_tenants_can_hold_the_same_ticket_id_without_collision(dynamodb_table) -> None:
    """The partition key is part of the identity of a record.

    Two organizations holding the same ticket id must be two distinct records.
    If they collided, one tenant could overwrite another's data by guessing an
    id -- so this is a tenancy test, not just a modelling detail.
    """
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    repo.put_ticket(make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, title="A side"))
    repo.put_ticket(make_ticket(ticket_id=TICKET_A1, organization_id=ORG_B, title="B side"))

    assert repo.get_ticket(ORG_A, TICKET_A1).title == "A side"  # type: ignore[union-attr]
    assert repo.get_ticket(ORG_B, TICKET_A1).title == "B side"  # type: ignore[union-attr]


def test_pagination_returns_a_last_evaluated_key(dynamodb_table) -> None:
    """A partial page must carry a continuation key."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    for index in range(5):
        repo.put_ticket(
            make_ticket(
                ticket_id=f"eeeeeeee-{index:04d}-4000-8000-eeeeeeeeeeee", organization_id=ORG_A
            )
        )

    first_page, last_key = repo.list_tickets(ORG_A, limit=2)
    assert len(first_page) == 2
    assert last_key is not None
    assert last_key["PK"] == tenant_pk(ORG_A)

    second_page, _ = repo.list_tickets(ORG_A, limit=2, cursor=last_key)
    assert {t.ticket_id for t in first_page}.isdisjoint({t.ticket_id for t in second_page})


def test_member_index_ordering_is_chronological(dynamodb_table) -> None:
    """GSI1SK is built so lexicographic order equals creation order."""
    from datetime import UTC, datetime

    repo = DynamoDbTicketRepository(table=dynamodb_table)
    for day in (3, 1, 2):
        ticket = make_ticket(
            ticket_id=f"ffffffff-000{day}-4000-8000-ffffffffffff",
            organization_id=ORG_A,
            created_by=USER_A_MEMBER,
        ).model_copy(update={"created_at": datetime(2026, 3, day, tzinfo=UTC)})
        repo.put_ticket(ticket)

    tickets, _ = repo.list_tickets(ORG_A, limit=10, created_by=USER_A_MEMBER)
    assert [t.created_at.day for t in tickets] == [1, 2, 3]


# ---------------------------------------------------------------------------
# Conditional writes (finding F-015)
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.regression
def test_duplicate_create_raises_conflict(dynamodb_table) -> None:
    """Guards finding F-015: create must not overwrite."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    repo.put_ticket(make_ticket(ticket_id=TICKET_A1, title="Original"))

    with pytest.raises(ConflictError):
        repo.put_ticket(make_ticket(ticket_id=TICKET_A1, title="Replacement"))

    assert repo.get_ticket(ORG_A, TICKET_A1).title == "Original"  # type: ignore[union-attr]


@pytest.mark.security
@pytest.mark.regression
def test_update_of_a_missing_ticket_raises_conflict(dynamodb_table) -> None:
    """Guards finding F-015: update must not create."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)

    with pytest.raises(ConflictError):
        repo.save_ticket(make_ticket(ticket_id=TICKET_A1))

    assert repo.get_ticket(ORG_A, TICKET_A1) is None


def test_update_of_an_existing_ticket_succeeds(dynamodb_table) -> None:
    """The condition must not block legitimate updates."""
    repo = DynamoDbTicketRepository(table=dynamodb_table)
    ticket = make_ticket(ticket_id=TICKET_A1)
    repo.put_ticket(ticket)

    repo.save_ticket(ticket.model_copy(update={"status": TicketStatus.RESOLVED}))

    assert repo.get_ticket(ORG_A, TICKET_A1).status is TicketStatus.RESOLVED  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Memberships
# ---------------------------------------------------------------------------


def _seed_membership(table, user_id: str, organization_id: str, role: str, status: str = "active"):
    """Write a membership record the way the admin process would."""
    table.put_item(
        Item={
            "PK": user_pk(user_id),
            "SK": membership_sk(organization_id),
            "role": role,
            "status": status,
            "entity_type": "membership",
        }
    )


def test_membership_lookup_returns_the_stored_role(dynamodb_table) -> None:
    """The membership record is the authoritative source of role."""
    _seed_membership(dynamodb_table, USER_A_ADMIN, ORG_A, "admin")
    repo = DynamoDbMembershipRepository(table=dynamodb_table)

    membership = repo.get_membership(USER_A_ADMIN, ORG_A)

    assert membership is not None
    assert membership.role is OrganizationRole.ADMIN
    assert membership.status == "active"


@pytest.mark.security
@pytest.mark.regression
def test_membership_lookup_is_scoped_to_one_organization(dynamodb_table) -> None:
    """Guards finding F-002.

    A user who is an admin of org A must produce no membership for org B.
    """
    _seed_membership(dynamodb_table, USER_A_ADMIN, ORG_A, "admin")
    repo = DynamoDbMembershipRepository(table=dynamodb_table)

    assert repo.get_membership(USER_A_ADMIN, ORG_B) is None


def test_missing_membership_returns_none(dynamodb_table) -> None:
    """An unknown user is simply not a member."""
    repo = DynamoDbMembershipRepository(table=dynamodb_table)
    assert repo.get_membership("00000000-0000-4000-8000-000000000000", ORG_A) is None


@pytest.mark.security
def test_revoked_membership_is_returned_with_its_status(dynamodb_table) -> None:
    """Revocation is represented, not deleted.

    Keeping the record with ``status=revoked`` preserves the audit trail and
    lets the authorization layer deny explicitly, rather than treating a
    revoked user the same as one who never existed.
    """
    _seed_membership(dynamodb_table, USER_A_MEMBER, ORG_A, "member", status="revoked")
    repo = DynamoDbMembershipRepository(table=dynamodb_table)

    membership = repo.get_membership(USER_A_MEMBER, ORG_A)
    assert membership is not None
    assert membership.status == "revoked"


@pytest.mark.security
def test_membership_and_ticket_records_share_a_table_without_overlap(dynamodb_table) -> None:
    """Single-table design must not let one entity type shadow another.

    Memberships live under ``USER#`` and tickets under ``TENANT#``, so a
    ticket query (``PK = TENANT#..., SK begins_with TICKET#``) can never
    return a membership record -- which would otherwise be a way to read
    authorization data through the ticket endpoint.
    """
    _seed_membership(dynamodb_table, USER_A_MEMBER, ORG_A, "admin")
    ticket_repo = DynamoDbTicketRepository(table=dynamodb_table)
    ticket_repo.put_ticket(make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A))

    tickets, _ = ticket_repo.list_tickets(ORG_A, limit=50)
    assert [t.ticket_id for t in tickets] == [TICKET_A1]
