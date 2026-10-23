"""DynamoDB-backed ticket repository."""

from __future__ import annotations

from typing import Any

from boto3.dynamodb.conditions import Attr

from app.models.ticket import Ticket
from app.repositories.dynamodb import get_table
from app.repositories.keys import tenant_pk, ticket_sk


def _to_item(ticket: Ticket) -> dict[str, Any]:
    """Serialise a ticket into a DynamoDB item."""
    item = ticket.model_dump(mode="json")
    item["PK"] = tenant_pk(ticket.organization_id)
    item["SK"] = ticket_sk(ticket.ticket_id)
    return item


def _from_item(item: dict[str, Any]) -> Ticket:
    """Deserialise a DynamoDB item into a ticket."""
    payload = {k: v for k, v in item.items() if k not in {"PK", "SK"}}
    return Ticket.model_validate(payload)


class DynamoDbTicketRepository:
    """Ticket persistence against the single DynamoDB table."""

    def __init__(self, table: Any | None = None) -> None:
        self._table = table if table is not None else get_table()

    def put_ticket(self, ticket: Ticket) -> None:
        """Insert a new ticket."""
        self._table.put_item(Item=_to_item(ticket))

    def get_ticket(self, organization_id: str, ticket_id: str) -> Ticket | None:
        """Fetch a single ticket by tenant and id."""
        response = self._table.get_item(
            Key={"PK": tenant_pk(organization_id), "SK": ticket_sk(ticket_id)}
        )
        item = response.get("Item")
        if not item:
            return None
        return _from_item(item)

    def list_tickets(
        self,
        organization_id: str,
        *,
        limit: int,
        cursor: dict[str, Any] | None = None,
        created_by: str | None = None,
    ) -> tuple[list[Ticket], dict[str, Any] | None]:
        """Return a page of tickets for an organization.

        A scan with a filter keeps this simple while the access patterns are
        still settling -- it works for any combination of filters without
        needing a secondary index.
        """
        kwargs: dict[str, Any] = {
            "Limit": limit,
            "FilterExpression": Attr("organization_id").eq(organization_id),
        }
        if created_by:
            kwargs["FilterExpression"] = kwargs["FilterExpression"] & Attr("created_by").eq(
                created_by
            )
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor

        response = self._table.scan(**kwargs)
        tickets = [_from_item(item) for item in response.get("Items", [])]
        return tickets, response.get("LastEvaluatedKey")

    def save_ticket(self, ticket: Ticket) -> None:
        """Overwrite an existing ticket with its updated representation."""
        self._table.put_item(Item=_to_item(ticket))
