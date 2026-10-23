"""Authorization policy tests.

Tenant isolation keeps organizations apart. *Within* one organization the
authorization policy decides who may do what:

============  =========================================  =========================
Operation     Organization Member                        Organization Administrator
============  =========================================  =========================
Create        yes                                        yes
Read          own tickets only                           every ticket in the org
List          own tickets only                           every ticket in the org
Update        own tickets; may not set ``closed``         every ticket in the org
Close         no                                         yes
============  =========================================  =========================

The role used for these decisions comes from the **server-side membership
record**, never from the token claim (see finding F-002).
"""

from __future__ import annotations

import pytest

from app.models.membership import Membership, OrganizationRole
from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.synthetic_data import (
    ORG_A,
    TICKET_A1,
    TICKET_A2,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    USER_UNAFFILIATED,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# F-002: membership is verified server-side
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_request_without_a_membership_record_is_denied(
    app_factory: AppFactory, seeded_tickets: list
) -> None:
    """Guards finding F-002.

    A validly-authenticated Cognito identity with no membership of the
    organization named in its token must be denied. A token alone is not
    authorization.
    """
    harness = app_factory(tickets=seeded_tickets, memberships=[])
    harness.injector.authenticate_as(USER_UNAFFILIATED, ORG_A, "admin")

    response = harness.client.get("/v1/tickets")
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "forbidden"
    assert harness.tickets.operations() == [], "Data was accessed before authorization"


@pytest.mark.regression
def test_role_claim_in_token_cannot_escalate_privilege(
    app_factory: AppFactory, seeded_tickets: list
) -> None:
    """Guards finding F-002.

    The token says ``custom:role=admin``; the membership record says ``member``.
    The membership record must win, so the caller must not get admin reach.

    This matters because a role claim is only as fresh as the token: a user
    demoted five minutes ago still holds a token asserting the old role.
    """
    harness = app_factory(tickets=seeded_tickets)
    harness.injector.authenticate_as(USER_A_MEMBER, ORG_A, "admin")

    # TICKET_A2 belongs to a different member; only a real admin may read it.
    response = harness.client.get(f"/v1/tickets/{TICKET_A2}")
    assert response.status_code == 403, (
        "A token role claim escalated the caller to administrator. "
        f"Got {response.status_code}: {response.text}"
    )


@pytest.mark.regression
def test_membership_in_a_different_organization_does_not_grant_access(
    app_factory: AppFactory, seeded_tickets: list
) -> None:
    """Guards finding F-002.

    Being an admin somewhere is not being an admin here.
    """
    harness = app_factory(
        tickets=seeded_tickets,
        memberships=[
            Membership(
                user_id=USER_UNAFFILIATED,
                organization_id="org-unrelated",
                role=OrganizationRole.ADMIN,
            )
        ],
    )
    harness.injector.authenticate_as(USER_UNAFFILIATED, ORG_A, "admin")

    assert harness.client.get("/v1/tickets").status_code == 403


@pytest.mark.regression
def test_revoked_membership_is_denied(app_factory: AppFactory, seeded_tickets: list) -> None:
    """Guards finding F-002: a suspended membership must not authorize anything."""
    harness = app_factory(
        tickets=seeded_tickets,
        memberships=[
            Membership(
                user_id=USER_A_MEMBER,
                organization_id=ORG_A,
                role=OrganizationRole.MEMBER,
                status="revoked",
            )
        ],
    )
    harness.injector.authenticate_as(USER_A_MEMBER, ORG_A, "member")

    assert harness.client.get("/v1/tickets").status_code == 403


# ---------------------------------------------------------------------------
# F-003: object-level authorization on every operation
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_member_cannot_read_another_members_ticket(harness: ApiHarness) -> None:
    """Guards finding F-003 (OWASP API1 — Broken Object Level Authorization)."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get(f"/v1/tickets/{TICKET_A2}")
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "forbidden"


@pytest.mark.regression
def test_member_cannot_update_another_members_ticket(harness: ApiHarness) -> None:
    """Guards finding F-003.

    The update path is the one that was missing an authorization check: the
    policy helper existed but was never invoked. This test calls the exact
    operation that was unguarded.
    """
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.patch(
        f"/v1/tickets/{TICKET_A2}",
        json={"title": "Modified by a user who does not own this ticket"},
    )
    assert response.status_code == 403, (
        f"A member modified another member's ticket. Got {response.status_code}: {response.text}"
    )

    stored = harness.tickets.raw(ORG_A)[TICKET_A2]
    assert stored.title == "Billing discrepancy", "The ticket was modified despite the denial"


@pytest.mark.regression
def test_member_list_returns_only_their_own_tickets(harness: ApiHarness) -> None:
    """Guards finding F-003.

    Listing is an object-level authorization decision too: a member must not
    be able to read a coworker's ticket titles and descriptions through the
    collection endpoint just because the per-item endpoint is guarded.
    """
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get("/v1/tickets")
    assert response.status_code == 200, response.text

    items = response.json()["items"]
    assert {item["ticket_id"] for item in items} == {TICKET_A1}
    assert all(item["created_by"] == USER_A_MEMBER for item in items)


def test_member_can_read_and_update_their_own_ticket(harness: ApiHarness) -> None:
    """The policy must not be so strict that it breaks the product."""
    harness.as_member(ORG_A, USER_A_MEMBER)

    assert harness.client.get(f"/v1/tickets/{TICKET_A1}").status_code == 200

    response = harness.client.patch(
        f"/v1/tickets/{TICKET_A1}", json={"description": "Updated by the owner"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["description"] == "Updated by the owner"


def test_admin_can_read_list_and_update_every_ticket_in_the_organization(
    harness: ApiHarness,
) -> None:
    """Administrators have organization-wide reach -- but only their own org."""
    harness.as_admin(ORG_A, USER_A_ADMIN)

    assert harness.client.get(f"/v1/tickets/{TICKET_A2}").status_code == 200

    listed = harness.client.get("/v1/tickets").json()["items"]
    assert {item["ticket_id"] for item in listed} == {TICKET_A1, TICKET_A2}

    response = harness.client.patch(f"/v1/tickets/{TICKET_A2}", json={"priority": "urgent"})
    assert response.status_code == 200, response.text
    assert response.json()["priority"] == "urgent"


def test_both_roles_may_create_tickets(app_factory: AppFactory) -> None:
    """Creating a ticket is available to every member of an organization."""
    for role, user in (("member", USER_A_MEMBER), ("admin", USER_A_ADMIN)):
        harness = app_factory()
        harness.injector.authenticate_as(user, ORG_A, role)
        response = harness.client.post(
            "/v1/tickets",
            json={"title": "New request", "description": "Synthetic body"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["created_by"] == user
        assert response.json()["organization_id"] == ORG_A


# ---------------------------------------------------------------------------
# F-013: ticket status state machine
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_member_cannot_close_a_ticket(harness: ApiHarness) -> None:
    """Guards finding F-013.

    Closing is a privileged transition: it ends the support obligation and
    stops SLA timers. A member closing their own ticket would let a tenant
    quietly suppress its own support record.
    """
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"status": "closed"})

    assert response.status_code == 403, response.text
    assert harness.tickets.raw(ORG_A)[TICKET_A1].status.value == "open"


@pytest.mark.regression
def test_admin_can_close_a_ticket(harness: ApiHarness) -> None:
    """Guards finding F-013: the privileged transition works for admins."""
    harness.as_admin(ORG_A, USER_A_ADMIN)
    response = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"status": "closed"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"


@pytest.mark.regression
def test_closed_tickets_cannot_be_silently_reopened_by_a_member(
    app_factory: AppFactory,
) -> None:
    """Guards finding F-013: terminal states are enforced, not advisory."""
    from app.models.ticket import TicketStatus
    from tests.fixtures.synthetic_data import make_ticket

    harness = app_factory(
        tickets=[
            make_ticket(
                ticket_id=TICKET_A1,
                organization_id=ORG_A,
                created_by=USER_A_MEMBER,
                status=TicketStatus.CLOSED,
            )
        ]
    ).as_member(ORG_A, USER_A_MEMBER)

    response = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"status": "open"})
    assert response.status_code in (403, 409), response.text
    assert harness.tickets.raw(ORG_A)[TICKET_A1].status.value == "closed"


@pytest.mark.regression
@pytest.mark.parametrize("target", ["in_progress", "pending_customer", "resolved"])
def test_members_may_make_non_privileged_transitions(harness: ApiHarness, target: str) -> None:
    """Guards finding F-013: the state machine permits legitimate workflow."""
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"status": target})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == target


def test_other_member_of_same_org_is_still_denied_even_for_same_role(
    harness: ApiHarness,
) -> None:
    """Same role, same tenant, different owner: still denied."""
    harness.as_other_member(ORG_A)
    assert harness.client.get(f"/v1/tickets/{TICKET_A1}").status_code == 403
    assert USER_A_MEMBER_2 != USER_A_MEMBER
