"""Support ticket domain and API models.

VALIDATION POSTURE
------------------
Every request model sets ``extra="forbid"``. An unexpected field is therefore a
**rejection**, not a silently-ignored field. That matters for two reasons:

1. It closes mass assignment (finding F-004). ``organization_id`` and
   ``created_by`` are server-controlled; a client that tries to set them gets a
   422 rather than having the value quietly dropped -- or, worse, applied.
2. It makes probing visible. A 422 is logged and alertable; a silent drop is
   invisible, so an attacker can map the schema at leisure.

The response model is separate from the storage model so that internal
attributes (``PK``, ``SK``, ``GSI1PK``) can never leak into an API response.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

#: Bounds chosen against DynamoDB's 400 KB item limit with plenty of headroom,
#: so that a single request can neither bloat an item nor be used to fill a
#: tenant's partition (finding F-009 / CWE-770).
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 10_000

TicketTitle = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_TITLE_LENGTH),
]
TicketDescription = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_DESCRIPTION_LENGTH),
]


class TicketPriority(StrEnum):
    """Business priority of a support ticket."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class TicketStatus(StrEnum):
    """Lifecycle state of a support ticket."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_CUSTOMER = "pending_customer"
    RESOLVED = "resolved"
    CLOSED = "closed"


#: Permitted status transitions (finding F-013).
#:
#: ``CLOSED`` is terminal. A support ticket is part of the audit trail for a
#: customer relationship, so reopening is a new ticket, not a mutation of the
#: old one. Making the terminal state actually terminal also removes a whole
#: class of "flip the record after the fact" abuse.
ALLOWED_STATUS_TRANSITIONS: dict[TicketStatus, frozenset[TicketStatus]] = {
    TicketStatus.OPEN: frozenset(
        {
            TicketStatus.IN_PROGRESS,
            TicketStatus.PENDING_CUSTOMER,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.IN_PROGRESS: frozenset(
        {
            TicketStatus.OPEN,
            TicketStatus.PENDING_CUSTOMER,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.PENDING_CUSTOMER: frozenset(
        {
            TicketStatus.OPEN,
            TicketStatus.IN_PROGRESS,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.RESOLVED: frozenset(
        {TicketStatus.OPEN, TicketStatus.IN_PROGRESS, TicketStatus.CLOSED}
    ),
    TicketStatus.CLOSED: frozenset(),
}

#: Transitions only an organization administrator may perform.
#:
#: Closing a ticket ends the support obligation and stops SLA measurement. If a
#: member could close their own ticket, a tenant could quietly suppress its own
#: support record -- and an attacker who compromised one member account could
#: hide the evidence of what they did.
PRIVILEGED_STATUSES: frozenset[TicketStatus] = frozenset({TicketStatus.CLOSED})

#: Fields a client may change through PATCH. Anything else is server-controlled.
CLIENT_UPDATABLE_FIELDS: frozenset[str] = frozenset({"title", "description", "priority", "status"})


def is_transition_allowed(current: TicketStatus, target: TicketStatus) -> bool:
    """Return True when ``current -> target`` is a permitted transition."""
    if current is target:
        return True
    return target in ALLOWED_STATUS_TRANSITIONS.get(current, frozenset())


class Ticket(BaseModel):
    """A support ticket as stored and returned by the API.

    ``extra="forbid"`` here guards the *read* path: if a stray attribute ever
    appears on a stored item, deserialisation fails loudly instead of the
    attribute riding along into an API response.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    ticket_id: str
    organization_id: str
    created_by: str
    title: str
    description: str
    priority: TicketPriority
    status: TicketStatus
    created_at: datetime
    updated_at: datetime


class TicketCreateRequest(BaseModel):
    """Client payload for creating a ticket.

    Note what is *absent*: ``ticket_id`` (server-generated), ``created_by``
    (taken from the verified principal), ``organization_id`` (taken from the
    verified principal), ``status`` (always starts ``open``) and the
    timestamps. Those are the fields an attacker would want to control.
    """

    model_config = ConfigDict(extra="forbid")

    title: TicketTitle
    description: TicketDescription
    priority: TicketPriority = TicketPriority.MEDIUM


class TicketUpdateRequest(BaseModel):
    """Client payload for a partial ticket update."""

    model_config = ConfigDict(extra="forbid")

    title: TicketTitle | None = None
    description: TicketDescription | None = None
    priority: TicketPriority | None = None
    status: TicketStatus | None = None

    @model_validator(mode="after")
    def _require_at_least_one_change(self) -> Self:
        """Reject an update that would change nothing.

        An empty PATCH is almost always a client bug, and accepting it would
        bump ``updated_at`` and emit an audit event for a non-event -- noise
        that makes the real audit trail harder to read.
        """
        if not self.changed_fields():
            raise ValueError(
                "At least one of title, description, priority or status must be provided."
            )
        return self

    def changed_fields(self) -> list[str]:
        """Names of the fields the client explicitly set to a non-null value.

        Only field *names* are ever logged -- never values (finding F-007).
        """
        return sorted(
            name
            for name in self.model_fields_set & CLIENT_UPDATABLE_FIELDS
            if getattr(self, name) is not None
        )

    def changes(self) -> dict[str, object]:
        """The explicit, non-null changes as a mapping of allow-listed fields."""
        return {name: getattr(self, name) for name in self.changed_fields()}


class TicketPage(BaseModel):
    """One page of tickets plus an opaque continuation cursor."""

    model_config = ConfigDict(extra="forbid")

    items: list[Ticket]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page. Tenant-bound and validated server-side.",
    )
