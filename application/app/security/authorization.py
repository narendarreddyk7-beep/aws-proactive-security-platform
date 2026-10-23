"""Authorization policy.

DESIGN
------
Authorization is expressed as functions that return an explicit
:class:`Decision` -- never a bare ``bool``, and never an implicit "we got this
far so it must be fine". Three properties follow from that:

1. **Every decision has a reason.** The reason string is what gets logged and
   what the runbook keys off; it is never returned to the caller.
2. **A forgotten check is visible.** Callers must pass the ``Decision`` to
   :func:`enforce`, so a code path with no enforcement stands out in review.
   The original implementation defined ``can_update_ticket`` and then never
   called it on the update path (finding F-003); a boolean helper makes that
   easy to miss, an unused ``Decision`` does not.
3. **Policy is testable without HTTP.** Each function is pure.

POLICY
------
============  ==========================================  ==========================
Operation     Organization Member                         Organization Administrator
============  ==========================================  ==========================
Create        yes                                         yes
Read          tickets they created                        every ticket in the org
List          tickets they created (index-scoped)         every ticket in the org
Update        tickets they created                        every ticket in the org
Set status    any non-privileged, legal transition        any legal transition
============  ==========================================  ==========================

Tenancy is **not** checked here. It cannot be: by the time a ticket reaches
this module it was loaded from a partition keyed by the caller's organization,
so a cross-tenant object is already impossible. Keeping tenancy in the data
layer and permissions here means neither one can be bypassed by forgetting the
other.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.ticket import (
    PRIVILEGED_STATUSES,
    Ticket,
    TicketStatus,
    is_transition_allowed,
)
from app.security.errors import AuthorizationError, ConflictError
from app.security.principal import Principal


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of one authorization question."""

    allowed: bool
    #: Machine-readable reason, for logs and alerting. Never sent to a client.
    reason: str

    def __bool__(self) -> bool:
        """Allow ``if decision:`` while keeping the reason available."""
        return self.allowed


ALLOW_ADMIN = Decision(True, "organization_admin")
ALLOW_OWNER = Decision(True, "ticket_owner")
DENY_NOT_OWNER = Decision(False, "not_ticket_owner")
DENY_PRIVILEGED_STATUS = Decision(False, "privileged_status_requires_admin")


def authorize_read_ticket(principal: Principal, ticket: Ticket) -> Decision:
    """May this principal read this ticket?"""
    if principal.is_admin:
        return ALLOW_ADMIN
    if ticket.created_by == principal.user_id:
        return ALLOW_OWNER
    return DENY_NOT_OWNER


def authorize_update_ticket(principal: Principal, ticket: Ticket) -> Decision:
    """May this principal modify this ticket at all?"""
    if principal.is_admin:
        return ALLOW_ADMIN
    if ticket.created_by == principal.user_id:
        return ALLOW_OWNER
    return DENY_NOT_OWNER


def authorize_status_change(principal: Principal, target: TicketStatus) -> Decision:
    """May this principal move a ticket *into* ``target``?

    Separate from :func:`authorize_update_ticket` because owning a ticket does
    not imply the right to make every transition on it.
    """
    if target in PRIVILEGED_STATUSES and not principal.is_admin:
        return DENY_PRIVILEGED_STATUS
    return Decision(True, "status_change_permitted")


def list_scope(principal: Principal) -> str | None:
    """Return the ``created_by`` filter to apply when listing.

    ``None`` means organization-wide. Returning a value here (rather than
    filtering results afterwards) is what lets the repository narrow the
    *query* -- so a member's coworkers' tickets are never read from the
    database at all, let alone returned (findings F-003, F-006).
    """
    return None if principal.is_admin else principal.user_id


def enforce(decision: Decision, message: str = "You do not have access to this resource.") -> None:
    """Raise :class:`AuthorizationError` unless the decision allows the action.

    The caller-facing ``message`` is deliberately generic and identical for
    every denial: a specific one would disclose who owns a record or why
    access failed (finding F-008). The machine-readable reason stays in
    ``decision.reason`` for the logs.
    """
    if not decision.allowed:
        raise AuthorizationError(message, detail=decision.reason)


def ensure_transition_allowed(current: TicketStatus, target: TicketStatus) -> None:
    """Raise :class:`ConflictError` for an illegal lifecycle transition."""
    if not is_transition_allowed(current, target):
        raise ConflictError(
            f"A ticket in status '{current.value}' cannot move to '{target.value}'.",
            detail=f"invalid_transition:{current.value}->{target.value}",
        )
