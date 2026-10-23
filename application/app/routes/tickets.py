"""Ticket endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.config import get_settings
from app.dependencies import get_principal, get_ticket_service
from app.models.ticket import (
    Ticket,
    TicketCreateRequest,
    TicketPage,
    TicketUpdateRequest,
)
from app.observability.logging import get_logger
from app.repositories.pagination import decode_cursor, encode_cursor
from app.security.principal import Principal
from app.services.ticket_service import TicketService

router = APIRouter(prefix="/v1/tickets", tags=["tickets"])
logger = get_logger("app.routes.tickets")


@router.post(
    "",
    response_model=Ticket,
    status_code=status.HTTP_201_CREATED,
    summary="Create a support ticket",
)
def create_ticket(
    payload: TicketCreateRequest,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Create a ticket on behalf of the authenticated caller."""
    logger.info("create ticket request", extra={"payload": payload.model_dump()})
    return service.create_ticket(principal, payload)


@router.get("", response_model=TicketPage, summary="List tickets")
def list_tickets(
    limit: int = Query(default=None, description="Maximum number of tickets to return"),
    cursor: str | None = Query(default=None, description="Opaque pagination cursor"),
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> TicketPage:
    """Return a page of tickets visible to the caller."""
    settings = get_settings()
    page_size = limit if limit is not None else settings.default_page_size
    tickets, last_key = service.list_tickets(
        principal,
        limit=page_size,
        cursor=decode_cursor(cursor),
    )
    return TicketPage(items=tickets, next_cursor=encode_cursor(last_key))


@router.get("/{ticket_id}", response_model=Ticket, summary="Get a ticket by id")
def get_ticket(
    ticket_id: str,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Return a single ticket."""
    return service.get_ticket(principal, ticket_id)


@router.patch("/{ticket_id}", response_model=Ticket, summary="Update a ticket")
def update_ticket(
    ticket_id: str,
    payload: TicketUpdateRequest,
    principal: Principal = Depends(get_principal),
    service: TicketService = Depends(get_ticket_service),
) -> Ticket:
    """Apply a partial update to a ticket."""
    return service.update_ticket(principal, ticket_id, payload)
