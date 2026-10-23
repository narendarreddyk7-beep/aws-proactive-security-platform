"""Ticket endpoints.

Routes are deliberately thin: validate transport-level input, delegate, return.
No authorization logic lives here -- it belongs in the service layer where it
can be reviewed in one place (``app/services/ticket_service.py``).

Two edge-level validations are worth calling out:

* ``ticket_id`` is typed ``UUID``, so a malformed identifier is rejected by
  FastAPI before any handler runs and can never reach DynamoDB key
  construction (finding F-011).
* ``limit`` is bounded by ``ge``/``le``, so an unbounded page size is a 422
  rather than a full-partition read (finding F-009).
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.config import MAX_PAGE_SIZE, get_settings
from app.dependencies import get_principal, get_ticket_service
from app.models.ticket import (
    Ticket,
    TicketCreateRequest,
    TicketPage,
    TicketUpdateRequest,
)
from app.security.principal import Principal
from app.services.ticket_service import TicketService

router = APIRouter(prefix="/v1/tickets", tags=["tickets"])

ERROR_RESPONSES: dict[int | str, dict[str, str]] = {
    400: {"description": "Invalid request (for example a malformed cursor)"},
    401: {"description": "No valid authenticated identity"},
    403: {"description": "Authenticated but not permitted"},
    404: {"description": "Not found within the caller's organization"},
    409: {"description": "Conflicts with the ticket's current state"},
    422: {"description": "Request failed schema validation"},
}


@router.post(
    "",
    response_model=Ticket,
    status_code=status.HTTP_201_CREATED,
    summary="Create a support ticket",
    responses=ERROR_RESPONSES,
)
def create_ticket(
    payload: TicketCreateRequest,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Create a ticket owned by the caller, in the caller's organization.

    The organization and the owner are taken from the verified principal, so
    the request body cannot influence either.
    """
    return service.create_ticket(principal, payload)


@router.get(
    "",
    response_model=TicketPage,
    summary="List tickets visible to the caller",
    responses=ERROR_RESPONSES,
)
def list_tickets(
    limit: int | None = Query(
        default=None,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Page size, 1-{MAX_PAGE_SIZE}. Defaults to the server page size.",
    ),
    cursor: str | None = Query(
        default=None,
        description="Opaque cursor from a previous response. Bound to your organization.",
    ),
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> TicketPage:
    """Return a page of tickets.

    Administrators see every ticket in their organization; members see the
    tickets they created.
    """
    page_size = limit if limit is not None else get_settings().default_page_size
    tickets, next_cursor = service.list_tickets(principal, limit=page_size, cursor=cursor)
    return TicketPage(items=tickets, next_cursor=next_cursor)


@router.get(
    "/{ticket_id}",
    response_model=Ticket,
    summary="Get a ticket by id",
    responses=ERROR_RESPONSES,
)
def get_ticket(
    ticket_id: UUID,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Return a single ticket the caller is permitted to read."""
    return service.get_ticket(principal, str(ticket_id))


@router.patch(
    "/{ticket_id}",
    response_model=Ticket,
    summary="Partially update a ticket",
    responses=ERROR_RESPONSES,
)
def update_ticket(
    ticket_id: UUID,
    payload: TicketUpdateRequest,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Apply a partial update to a ticket the caller may modify.

    Only ``title``, ``description``, ``priority`` and ``status`` are writable.
    Closing a ticket requires the administrator role.
    """
    return service.update_ticket(principal, str(ticket_id), payload)
