"""Authorization policy unit tests.

The policy functions are pure, so they can be exhaustively tested without
HTTP, without a database and without identity plumbing. That matters: this is
the logic that decides who sees what, and it should be the best-tested code in
the repository.
"""

from __future__ import annotations

import pytest

from app.models.membership import OrganizationRole
from app.models.ticket import TicketStatus
from app.security.authorization import (
    Decision,
    authorize_read_ticket,
    authorize_status_change,
    authorize_update_ticket,
    enforce,
    ensure_transition_allowed,
    list_scope,
)
from app.security.errors import AuthorizationError, ConflictError
from app.security.principal import Principal
from tests.fixtures.synthetic_data import (
    ORG_A,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    make_ticket,
)

pytestmark = pytest.mark.unit

ADMIN = Principal(user_id=USER_A_ADMIN, organization_id=ORG_A, role=OrganizationRole.ADMIN)
MEMBER = Principal(user_id=USER_A_MEMBER, organization_id=ORG_A, role=OrganizationRole.MEMBER)
OTHER_MEMBER = Principal(
    user_id=USER_A_MEMBER_2, organization_id=ORG_A, role=OrganizationRole.MEMBER
)

OWNED_BY_MEMBER = make_ticket(created_by=USER_A_MEMBER)


# ---------------------------------------------------------------------------
# Read / update
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("principal", "expected", "reason"),
    [
        (ADMIN, True, "organization_admin"),
        (MEMBER, True, "ticket_owner"),
        (OTHER_MEMBER, False, "not_ticket_owner"),
    ],
)
def test_read_decisions(principal: Principal, expected: bool, reason: str) -> None:
    """Admins see everything in the org; members see only what they created."""
    decision = authorize_read_ticket(principal, OWNED_BY_MEMBER)
    assert decision.allowed is expected
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("principal", "expected"),
    [(ADMIN, True), (MEMBER, True), (OTHER_MEMBER, False)],
)
def test_update_decisions(principal: Principal, expected: bool) -> None:
    """The update policy mirrors the read policy for ticket ownership."""
    assert authorize_update_ticket(principal, OWNED_BY_MEMBER).allowed is expected


def test_decision_carries_a_reason_even_when_allowed() -> None:
    """Every decision is explainable, which is what makes the audit log useful."""
    for principal in (ADMIN, MEMBER, OTHER_MEMBER):
        for decision in (
            authorize_read_ticket(principal, OWNED_BY_MEMBER),
            authorize_update_ticket(principal, OWNED_BY_MEMBER),
        ):
            assert decision.reason, "A decision with no reason cannot be audited"


def test_decision_is_truthy_only_when_allowed() -> None:
    """``if decision:`` must behave, so the type is safe to use in a condition."""
    assert bool(Decision(True, "ok")) is True
    assert bool(Decision(False, "nope")) is False


# ---------------------------------------------------------------------------
# Listing scope (findings F-003, F-006)
# ---------------------------------------------------------------------------


def test_list_scope_is_organization_wide_for_admins() -> None:
    """An admin's listing is not narrowed by author."""
    assert list_scope(ADMIN) is None


def test_list_scope_is_restricted_to_self_for_members() -> None:
    """A member's listing is narrowed to their own user id.

    Returning the filter (rather than filtering results) is what lets the
    repository narrow the *query*, so a coworker's tickets are never read.
    """
    assert list_scope(MEMBER) == USER_A_MEMBER


# ---------------------------------------------------------------------------
# Status transitions (finding F-013)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("principal", "target", "expected"),
    [
        (MEMBER, TicketStatus.IN_PROGRESS, True),
        (MEMBER, TicketStatus.PENDING_CUSTOMER, True),
        (MEMBER, TicketStatus.RESOLVED, True),
        (MEMBER, TicketStatus.CLOSED, False),
        (ADMIN, TicketStatus.CLOSED, True),
        (ADMIN, TicketStatus.RESOLVED, True),
    ],
)
def test_status_change_authorization(
    principal: Principal, target: TicketStatus, expected: bool
) -> None:
    """Closing is privileged; the rest of the workflow is not."""
    assert authorize_status_change(principal, target).allowed is expected


@pytest.mark.parametrize(
    ("current", "target", "allowed"),
    [
        (TicketStatus.OPEN, TicketStatus.IN_PROGRESS, True),
        (TicketStatus.OPEN, TicketStatus.CLOSED, True),
        (TicketStatus.RESOLVED, TicketStatus.OPEN, True),
        (TicketStatus.RESOLVED, TicketStatus.PENDING_CUSTOMER, False),
        (TicketStatus.CLOSED, TicketStatus.OPEN, False),
        (TicketStatus.CLOSED, TicketStatus.IN_PROGRESS, False),
        (TicketStatus.CLOSED, TicketStatus.RESOLVED, False),
    ],
)
def test_transition_legality(current: TicketStatus, target: TicketStatus, allowed: bool) -> None:
    """``closed`` is terminal; everything else moves within the workflow."""
    if allowed:
        ensure_transition_allowed(current, target)
    else:
        with pytest.raises(ConflictError):
            ensure_transition_allowed(current, target)


def test_transition_to_the_same_status_is_a_no_op() -> None:
    """Re-asserting the current status must not be an error."""
    for status in TicketStatus:
        ensure_transition_allowed(status, status)


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------


def test_enforce_raises_for_a_denial() -> None:
    """A denied decision becomes a 403-mapped error."""
    with pytest.raises(AuthorizationError) as exc_info:
        enforce(Decision(False, "not_ticket_owner"))

    error = exc_info.value
    assert error.http_status == 403
    assert error.error_code == "forbidden"
    # The machine reason is kept for logs but is not in the caller-facing text.
    assert error.detail == "not_ticket_owner"
    assert "not_ticket_owner" not in error.message


def test_enforce_is_silent_when_allowed() -> None:
    """The happy path must not raise."""
    enforce(Decision(True, "organization_admin"))


@pytest.mark.security
def test_denial_messages_are_identical_regardless_of_reason() -> None:
    """Guards finding F-008.

    A different message per denial reason would let a caller distinguish "not
    your ticket" from "wrong role" -- a small but real information leak that
    helps an attacker map the policy.
    """
    messages = set()
    for reason in ("not_ticket_owner", "privileged_status_requires_admin", "anything_else"):
        try:
            enforce(Decision(False, reason))
        except AuthorizationError as exc:
            messages.add(exc.message)

    assert len(messages) == 1, f"Denial messages differ by reason: {messages}"
