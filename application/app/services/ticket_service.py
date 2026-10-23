"""Ticket business rules and authorization enforcement points.

This is the single layer where an authorization decision is *made and
enforced* for a ticket operation. Routes do transport concerns; repositories do
tenant-scoped persistence; the policy itself lives in
``app.security.authorization``. Keeping enforcement in one layer is what makes
"is every operation guarded?" a question you can answer by reading one file.

Every operation follows the same shape:

1. Load the object **from the caller's tenant partition** (so a cross-tenant
   object cannot exist by this point).
2. Treat "not found in my tenant" as 404 -- identical for a ticket that is
   absent and one that belongs to someone else (finding F-008).
3. Ask the policy for an explicit :class:`~app.security.authorization.Decision`
   and enforce it (finding F-003).
4. Emit an audit event carrying identifiers and outcomes only, never content
   (finding F-007).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.models.ticket import (
    Ticket,
    TicketCreateRequest,
    TicketStatus,
    TicketUpdateRequest,
)
from app.observability.logging import get_logger
from app.repositories.base import TicketStore
from app.repositories.pagination import decode_cursor, encode_cursor
from app.security.authorization import (
    authorize_read_ticket,
    authorize_status_change,
    authorize_update_ticket,
    enforce,
    ensure_transition_allowed,
    list_scope,
)
from app.security.errors import ResourceNotFoundError
from app.security.principal import Principal

logger = get_logger("app.services.ticket")

RESOURCE_TYPE = "ticket"


class TicketService:
    """Create, read, list and update support tickets."""

    def __init__(self, store: TicketStore) -> None:
        self._store = store

    # -- create --------------------------------------------------------------

    def create_ticket(self, principal: Principal, payload: TicketCreateRequest) -> Ticket:
        """Create a ticket owned by the caller, in the caller's organization.

        ``organization_id`` and ``created_by`` come from the verified principal.
        There is no code path by which a client can influence either
        (findings F-001, F-004), and ``ticket_id`` is server-generated so a
        client cannot choose a key.
        """
        now = datetime.now(tz=UTC)
        ticket = Ticket(
            ticket_id=str(uuid.uuid4()),
            organization_id=principal.organization_id,
            created_by=principal.user_id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
            status=TicketStatus.OPEN,
            created_at=now,
            updated_at=now,
        )
        self._store.put_ticket(ticket)

        logger.info(
            "ticket created",
            extra={
                "event_type": "ticket_created",
                "outcome": "allowed",
                "principal_id": principal.user_id,
                "organization_id": principal.organization_id,
                "resource_type": RESOURCE_TYPE,
                "resource_id": ticket.ticket_id,
            },
        )
        return ticket

    # -- read ----------------------------------------------------------------

    def get_ticket(self, principal: Principal, ticket_id: str) -> Ticket:
        """Return one ticket the caller is permitted to read."""
        ticket = self._load_or_404(principal, ticket_id)

        decision = authorize_read_ticket(principal, ticket)
        if not decision.allowed:
            self._log_denial(principal, ticket_id, "read", decision.reason)
        enforce(decision)

        logger.info(
            "ticket read",
            extra={
                "event_type": "ticket_read",
                "outcome": "allowed",
                "reason": decision.reason,
                "principal_id": principal.user_id,
                "organization_id": principal.organization_id,
                "resource_type": RESOURCE_TYPE,
                "resource_id": ticket_id,
            },
        )
        return ticket

    def list_tickets(
        self,
        principal: Principal,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> tuple[list[Ticket], str | None]:
        """Return a page of tickets the caller is permitted to see.

        The role decides the *query*, not a post-filter: a member's listing is
        narrowed in the key condition via GSI1, so other members' tickets are
        never read (findings F-003, F-006).

        The cursor is decoded and bound to the caller's tenant before use
        (finding F-010); a cursor belonging to another tenant raises
        ``ValidationFailedError`` and the store is never called.
        """
        start_key = decode_cursor(cursor, organization_id=principal.organization_id)
        scope = list_scope(principal)

        tickets, last_key = self._store.list_tickets(
            principal.organization_id,
            limit=limit,
            cursor=start_key,
            created_by=scope,
        )

        logger.info(
            "tickets listed",
            extra={
                "event_type": "ticket_list",
                "outcome": "allowed",
                "reason": "organization_scope" if scope is None else "own_tickets_scope",
                "principal_id": principal.user_id,
                "organization_id": principal.organization_id,
                "resource_type": RESOURCE_TYPE,
                "result_count": len(tickets),
            },
        )
        return tickets, encode_cursor(last_key)

    # -- update --------------------------------------------------------------

    def update_ticket(
        self,
        principal: Principal,
        ticket_id: str,
        payload: TicketUpdateRequest,
    ) -> Ticket:
        """Apply a partial update to a ticket the caller may modify."""
        ticket = self._load_or_404(principal, ticket_id)

        # 1. May this principal touch this object at all?
        decision = authorize_update_ticket(principal, ticket)
        if not decision.allowed:
            self._log_denial(principal, ticket_id, "update", decision.reason)
        enforce(decision)

        changes = payload.changes()
        target_status = changes.get("status")

        # 2. Is this specific state change permitted for this role?
        if target_status is not None and target_status is not ticket.status:
            status_decision = authorize_status_change(principal, TicketStatus(target_status))
            if not status_decision.allowed:
                self._log_denial(principal, ticket_id, "status_change", status_decision.reason)
            enforce(status_decision)

            # 3. Is it a legal transition at all? (409, not 403 -- the caller
            #    is allowed to act, the ticket is simply not in a state that
            #    permits it.)
            ensure_transition_allowed(ticket.status, TicketStatus(target_status))

        updated = ticket.model_copy(
            update={**changes, "updated_at": datetime.now(tz=UTC)},
        )
        self._store.save_ticket(updated)

        logger.info(
            "ticket updated",
            extra={
                "event_type": "ticket_updated",
                "outcome": "allowed",
                "reason": decision.reason,
                "principal_id": principal.user_id,
                "organization_id": principal.organization_id,
                "resource_type": RESOURCE_TYPE,
                "resource_id": ticket_id,
                # Field NAMES only. The values are customer content (F-007).
                "changed_fields": payload.changed_fields(),
            },
        )
        return updated

    # -- internals -----------------------------------------------------------

    def _load_or_404(self, principal: Principal, ticket_id: str) -> Ticket:
        """Load a ticket from the caller's partition, or raise 404.

        Because the read is partition-scoped, "belongs to another tenant" and
        "does not exist" are the same outcome here -- which is precisely the
        indistinguishable response the API needs to avoid confirming that
        another organization's ticket exists (finding F-008).
        """
        ticket = self._store.get_ticket(principal.organization_id, ticket_id)
        if ticket is None:
            logger.info(
                "ticket not found in tenant",
                extra={
                    "event_type": "resource_not_found",
                    "outcome": "denied",
                    "principal_id": principal.user_id,
                    "organization_id": principal.organization_id,
                    "resource_type": RESOURCE_TYPE,
                    "resource_id": ticket_id,
                },
            )
            raise ResourceNotFoundError("The requested ticket was not found.")
        return ticket

    @staticmethod
    def _log_denial(principal: Principal, ticket_id: str, action: str, reason: str) -> None:
        """Emit the security event behind the authorization-denial alarm.

        This event is what the ``AuthorizationDenied`` CloudWatch metric filter
        counts and what runbook A triages. A denial that is not logged cannot
        be alerted on, so this is a security control in its own right, not
        just diagnostics.
        """
        logger.warning(
            "authorization denied",
            extra={
                "event_type": "authorization_denied",
                "outcome": "denied",
                "reason": f"{action}:{reason}",
                "principal_id": principal.user_id,
                "organization_id": principal.organization_id,
                "role": principal.role.value,
                "resource_type": RESOURCE_TYPE,
                "resource_id": ticket_id,
            },
        )
