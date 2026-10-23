"""Server-side organization membership lookup.

The membership record is the authoritative statement of *which organization a
user belongs to* and *what role they hold there*. It is written by an
administrative process outside this API, so a support-API caller cannot modify
their own tenancy or role.
"""

from __future__ import annotations

from typing import Any, Protocol

from app.models.membership import Membership
from app.repositories.dynamodb import get_membership_table
from app.repositories.keys import membership_sk, user_pk


class MembershipStore(Protocol):
    """Lookup of a user's membership of an organization."""

    def get_membership(self, user_id: str, organization_id: str) -> Membership | None:
        """Return the membership record, or ``None`` if the user is not a member."""
        ...


class DynamoDbMembershipRepository:
    """Membership lookup against the dedicated membership table.

    Read-only by construction: this class exposes no write method, and the
    execution role is granted ``GetItem`` on this table and nothing else. A
    membership is created by an out-of-band administrative process, so there is
    no code path -- and now no *permission* -- by which a support-API request
    can modify its own tenancy or role.
    """

    def __init__(self, table: Any | None = None) -> None:
        self._table = table if table is not None else get_membership_table()

    def get_membership(self, user_id: str, organization_id: str) -> Membership | None:
        """Fetch one membership record by its exact composite key."""
        response = self._table.get_item(
            Key={"PK": user_pk(user_id), "SK": membership_sk(organization_id)},
            # Consistent read: a membership revocation must take effect
            # immediately, so an eventually-consistent read is not acceptable
            # for an authorization input.
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return None
        return Membership(
            user_id=user_id,
            organization_id=organization_id,
            role=item["role"],
            status=item.get("status", "active"),
        )
