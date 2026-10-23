"""DynamoDB key construction.

Single-table design:

=====================  ===========================  ============================
Entity                 PK                           SK
=====================  ===========================  ============================
Ticket                 ``TENANT#{organization_id}`` ``TICKET#{ticket_id}``
Membership             ``USER#{user_id}``           ``MEMBERSHIP#{organization}``
=====================  ===========================  ============================

GSI1 exists so that a member can list their own tickets without reading the
rest of the organization's partition:

=====================  ==================================  ========================
Index                  GSI1PK                              GSI1SK
=====================  ==================================  ========================
GSI1 (member tickets)  ``TENANT#{org}#USER#{user}``        ``CREATED#{ts}#{id}``
=====================  ==================================  ========================

WHY THIS SHAPE
--------------
Putting the organization in the partition key makes tenant isolation a
property of the access pattern: a ``Query`` is physically unable to return
another tenant's items. The alternative -- a flat table filtered by an
``organization_id`` attribute -- makes isolation a property of remembering to
filter, which is exactly the kind of control that survives code review and
then dies in a refactor.

The GSI1 partition key embeds *both* tenant and user. Keying it on the user
alone would have let a user's tickets from one organization appear in a query
scoped to another, reintroducing the cross-tenant path through the index.

IDENTIFIER VALIDATION
---------------------
``#`` is the separator, so an unvalidated identifier containing ``#`` could
address a key the application never intended to expose (finding F-011).
Identifiers are validated as UUIDs at the HTTP edge; :func:`ticket_sk` asserts
the invariant again here, because this module is the last line of defence
before a key is constructed.
"""

from __future__ import annotations

from app.security.errors import ValidationFailedError

TENANT_PREFIX = "TENANT#"
TICKET_PREFIX = "TICKET#"
USER_PREFIX = "USER#"
MEMBERSHIP_PREFIX = "MEMBERSHIP#"
CREATED_PREFIX = "CREATED#"

KEY_SEPARATOR = "#"


def _assert_no_separator(value: str, field: str) -> str:
    """Reject an identifier that could manipulate the key structure.

    Raises:
        ValidationFailedError: the value is empty or contains the separator.
    """
    if not value or not value.strip():
        raise ValidationFailedError("Invalid identifier.", detail=f"{field}_empty")
    if KEY_SEPARATOR in value:
        raise ValidationFailedError("Invalid identifier.", detail=f"{field}_contains_separator")
    return value


def tenant_pk(organization_id: str) -> str:
    """Partition key for all records belonging to one organization."""
    return f"{TENANT_PREFIX}{_assert_no_separator(organization_id, 'organization_id')}"


def ticket_sk(ticket_id: str) -> str:
    """Sort key for a single ticket."""
    return f"{TICKET_PREFIX}{_assert_no_separator(ticket_id, 'ticket_id')}"


def user_pk(user_id: str) -> str:
    """Partition key for records owned by one Cognito identity."""
    return f"{USER_PREFIX}{_assert_no_separator(user_id, 'user_id')}"


def membership_sk(organization_id: str) -> str:
    """Sort key for one user's membership of one organization."""
    return f"{MEMBERSHIP_PREFIX}{_assert_no_separator(organization_id, 'organization_id')}"


def member_index_pk(organization_id: str, user_id: str) -> str:
    """GSI1 partition key scoping tickets to one user within one tenant."""
    organization = _assert_no_separator(organization_id, "organization_id")
    user = _assert_no_separator(user_id, "user_id")
    return f"{TENANT_PREFIX}{organization}{KEY_SEPARATOR}{USER_PREFIX}{user}"


def member_index_sk(created_at_iso: str, ticket_id: str) -> str:
    """GSI1 sort key giving newest-last ordering within a member's tickets.

    ISO-8601 UTC timestamps sort lexicographically in chronological order, so
    no numeric conversion is needed. The ticket id is appended to break ties
    between tickets created in the same millisecond.
    """
    return f"{CREATED_PREFIX}{created_at_iso}{KEY_SEPARATOR}{ticket_id}"
