"""Data access layer.

All DynamoDB interaction is funnelled through this package so that tenant
scoping is enforced in one reviewable place rather than scattered across
route handlers.
"""

from app.repositories.base import TicketStore
from app.repositories.ticket_repository import DynamoDbTicketRepository

__all__ = ["DynamoDbTicketRepository", "TicketStore"]
