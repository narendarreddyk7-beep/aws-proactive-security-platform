"""Support ticket domain and API models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


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


class Ticket(BaseModel):
    """A support ticket as stored and returned by the API."""

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
    """Client payload for creating a ticket."""

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    priority: TicketPriority = TicketPriority.MEDIUM
    organization_id: str | None = None


class TicketUpdateRequest(BaseModel):
    """Client payload for updating a ticket.

    ``extra="allow"`` keeps the endpoint flexible while the ticket schema is
    still evolving, so new fields can be stored without a deploy.
    """

    model_config = ConfigDict(extra="allow")

    title: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None


class TicketPage(BaseModel):
    """One page of tickets plus an opaque continuation cursor."""

    items: list[Ticket]
    next_cursor: str | None = None
