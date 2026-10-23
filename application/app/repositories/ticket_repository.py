"""DynamoDB-backed ticket repository.

TENANT ISOLATION IS AN ACCESS-PATTERN PROPERTY
----------------------------------------------
Every read here is a ``Query`` whose key condition pins the caller's partition.
DynamoDB will not read outside a queried partition, so a cross-tenant result is
not "prevented" by this code -- it is impossible.

The original implementation used ``Scan`` with a ``FilterExpression`` on
``organization_id`` (finding F-006). That produced correct answers while
leaving isolation dependent on a filter that any refactor could drop, read
every other tenant's items on every request, and billed for all of them.

ACCESS PATTERNS
---------------
=========================  ==========  ====================================
Query                      Index       Key condition
=========================  ==========  ====================================
Admin lists org tickets    base table  ``PK = TENANT#{org}``,
                                       ``SK begins_with TICKET#``
Member lists own tickets   GSI1        ``GSI1PK = TENANT#{org}#USER#{user}``
Read one ticket            base table  exact ``(PK, SK)``
=========================  ==========  ====================================

The member path uses an index rather than a post-query filter so that a
coworker's tickets are never read from the database at all -- not read, not
billed, not briefly held in memory.

WRITES ARE CONDITIONAL
----------------------
``put_ticket`` asserts the item does not exist; ``save_ticket`` asserts it
does. Unconditional ``PutItem`` silently replaces whatever is at the key, which
turns an id collision into destroyed data and lets a bug in the service layer
create a record through the update path -- bypassing create-time checks
(finding F-015).
"""

from __future__ import annotations

from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.config import MAX_PAGE_SIZE
from app.models.ticket import Ticket
from app.observability.logging import get_logger
from app.repositories.dynamodb import get_table
from app.repositories.keys import (
    TICKET_PREFIX,
    member_index_pk,
    member_index_sk,
    tenant_pk,
    ticket_sk,
)
from app.repositories.pagination import validate_cursor_key
from app.security.errors import ConflictError

logger = get_logger("app.repositories.ticket")

GSI1_NAME = "GSI1"

#: Internal attributes that must never reach an API response.
_INTERNAL_ATTRIBUTES = frozenset({"PK", "SK", "GSI1PK", "GSI1SK", "entity_type"})


def _to_item(ticket: Ticket) -> dict[str, Any]:
    """Serialise a ticket into a DynamoDB item, including index keys."""
    item = ticket.model_dump(mode="json")
    item["PK"] = tenant_pk(ticket.organization_id)
    item["SK"] = ticket_sk(ticket.ticket_id)
    item["GSI1PK"] = member_index_pk(ticket.organization_id, ticket.created_by)
    item["GSI1SK"] = member_index_sk(item["created_at"], ticket.ticket_id)
    item["entity_type"] = "ticket"
    return item


def _from_item(item: dict[str, Any]) -> Ticket:
    """Deserialise a DynamoDB item into a ticket, dropping internal attributes."""
    payload = {key: value for key, value in item.items() if key not in _INTERNAL_ATTRIBUTES}
    return Ticket.model_validate(payload)


class DynamoDbTicketRepository:
    """Tenant-scoped ticket persistence against the single DynamoDB table."""

    def __init__(self, table: Any | None = None) -> None:
        self._table = table if table is not None else get_table()

    # -- writes --------------------------------------------------------------

    def put_ticket(self, ticket: Ticket) -> None:
        """Insert a new ticket, failing if one already exists at that key."""
        try:
            self._table.put_item(
                Item=_to_item(ticket),
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ConflictError(
                    "The ticket could not be created.", detail="ticket_already_exists"
                ) from exc
            raise

    def save_ticket(self, ticket: Ticket) -> None:
        """Persist an updated ticket, failing if it no longer exists.

        The condition also closes a race: if the ticket were deleted between
        the read and this write, an unconditional put would resurrect it from
        stale in-memory state.
        """
        try:
            self._table.put_item(
                Item=_to_item(ticket),
                ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ConflictError(
                    "The ticket could not be updated.", detail="ticket_missing_or_changed"
                ) from exc
            raise

    # -- reads ---------------------------------------------------------------

    def get_ticket(self, organization_id: str, ticket_id: str) -> Ticket | None:
        """Fetch one ticket by its exact composite key within one tenant.

        A ticket id belonging to another tenant simply is not in this
        partition, so the answer is ``None`` -- the same answer as for an id
        that does not exist anywhere. That identical outcome is what lets the
        service return an identical 404 for both (finding F-008).
        """
        response = self._table.get_item(
            Key={"PK": tenant_pk(organization_id), "SK": ticket_sk(ticket_id)}
        )
        item = response.get("Item")
        return _from_item(item) if item else None

    def list_tickets(
        self,
        organization_id: str,
        *,
        limit: int,
        cursor: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> tuple[list[Ticket], dict[str, Any] | None]:
        """Return one page of tickets, always scoped to a single tenant.

        Args:
            organization_id: Tenant to read. Comes from the verified principal.
            limit: Requested page size. Clamped to ``MAX_PAGE_SIZE`` here as
                well as at the HTTP edge (finding F-009) -- the repository is
                reusable and must not trust its caller.
            cursor: A previously-issued ``LastEvaluatedKey``. Re-validated
                against this tenant (finding F-010).
            created_by: When set, narrow to one author using GSI1.
        """
        page_size = max(1, min(int(limit), MAX_PAGE_SIZE))

        kwargs: dict[str, Any] = {"Limit": page_size}
        if cursor is not None:
            kwargs["ExclusiveStartKey"] = validate_cursor_key(
                cursor, organization_id=organization_id
            )

        if created_by is not None:
            kwargs["IndexName"] = GSI1_NAME
            kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(
                member_index_pk(organization_id, created_by)
            )
        else:
            kwargs["KeyConditionExpression"] = Key("PK").eq(tenant_pk(organization_id)) & Key(
                "SK"
            ).begins_with(TICKET_PREFIX)

        response = self._table.query(**kwargs)
        tickets = [_from_item(item) for item in response.get("Items", [])]

        last_key = response.get("LastEvaluatedKey")
        logger.debug(
            "ticket query complete",
            extra={
                "event_type": "ticket_query",
                "organization_id": organization_id,
                "result_count": len(tickets),
            },
        )
        return tickets, last_key
