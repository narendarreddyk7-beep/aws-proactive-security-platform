"""DynamoDB key construction.

Single-table design:

=====================  ===========================  ============================
Entity                 PK                           SK
=====================  ===========================  ============================
Ticket                 ``TENANT#{organization_id}`` ``TICKET#{ticket_id}``
Membership             ``USER#{user_id}``           ``MEMBERSHIP#{organization}``
=====================  ===========================  ============================

Putting the organization in the partition key means a ``Query`` is physically
unable to return another tenant's items.
"""

from __future__ import annotations

TENANT_PREFIX = "TENANT#"
TICKET_PREFIX = "TICKET#"
USER_PREFIX = "USER#"
MEMBERSHIP_PREFIX = "MEMBERSHIP#"


def tenant_pk(organization_id: str) -> str:
    """Partition key for all records belonging to one organization."""
    return f"{TENANT_PREFIX}{organization_id}"


def ticket_sk(ticket_id: str) -> str:
    """Sort key for a single ticket."""
    return f"{TICKET_PREFIX}{ticket_id}"


def user_pk(user_id: str) -> str:
    """Partition key for records owned by one Cognito identity."""
    return f"{USER_PREFIX}{user_id}"


def membership_sk(organization_id: str) -> str:
    """Sort key for one user's membership of one organization."""
    return f"{MEMBERSHIP_PREFIX}{organization_id}"
