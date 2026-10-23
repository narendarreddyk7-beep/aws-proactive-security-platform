"""End-to-end API tests through the ASGI boundary.

These are the functional tests: do the documented endpoints behave as the
README and OpenAPI description say? The security properties are asserted
separately in ``tests/security/``.
"""

from __future__ import annotations

import pytest

from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.synthetic_data import ORG_A, TICKET_A1, TICKET_A2, USER_A_ADMIN, USER_A_MEMBER

pytestmark = pytest.mark.integration


def test_full_ticket_lifecycle(app_factory: AppFactory) -> None:
    """Create, read, list, update, resolve, then close as an administrator."""
    harness = app_factory().as_admin(ORG_A, USER_A_ADMIN)

    created = harness.client.post(
        "/v1/tickets",
        json={
            "title": "Cannot access billing portal",
            "description": "Synthetic report for the lifecycle test.",
            "priority": "high",
        },
    )
    assert created.status_code == 201, created.text
    ticket_id = created.json()["ticket_id"]
    assert created.json()["status"] == "open"
    assert created.json()["priority"] == "high"

    fetched = harness.client.get(f"/v1/tickets/{ticket_id}")
    assert fetched.status_code == 200
    assert fetched.json() == created.json()

    listed = harness.client.get("/v1/tickets")
    assert listed.status_code == 200
    assert ticket_id in {item["ticket_id"] for item in listed.json()["items"]}

    progressed = harness.client.patch(f"/v1/tickets/{ticket_id}", json={"status": "in_progress"})
    assert progressed.status_code == 200
    assert progressed.json()["status"] == "in_progress"

    resolved = harness.client.patch(f"/v1/tickets/{ticket_id}", json={"status": "resolved"})
    assert resolved.status_code == 200

    closed = harness.client.patch(f"/v1/tickets/{ticket_id}", json={"status": "closed"})
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"

    # Closed is terminal.
    reopened = harness.client.patch(f"/v1/tickets/{ticket_id}", json={"status": "open"})
    assert reopened.status_code == 409, reopened.text
    assert reopened.json()["error"] == "conflict"


def test_member_workflow(app_factory: AppFactory) -> None:
    """A member creates a ticket, works it, but cannot close it."""
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)

    created = harness.client.post(
        "/v1/tickets", json={"title": "Password reset", "description": "Synthetic"}
    )
    assert created.status_code == 201
    ticket_id = created.json()["ticket_id"]

    assert harness.client.get(f"/v1/tickets/{ticket_id}").status_code == 200
    assert (
        harness.client.patch(
            f"/v1/tickets/{ticket_id}", json={"description": "More detail"}
        ).status_code
        == 200
    )
    assert (
        harness.client.patch(f"/v1/tickets/{ticket_id}", json={"status": "closed"}).status_code
        == 403
    )


def test_partial_update_leaves_other_fields_untouched(harness: ApiHarness) -> None:
    """PATCH semantics: only the supplied fields change."""
    harness.as_member(ORG_A, USER_A_MEMBER)
    before = harness.client.get(f"/v1/tickets/{TICKET_A1}").json()

    after = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"priority": "urgent"}).json()

    assert after["priority"] == "urgent"
    for field in (
        "ticket_id",
        "organization_id",
        "created_by",
        "title",
        "description",
        "created_at",
    ):
        assert after[field] == before[field], f"{field} changed unexpectedly"
    assert after["updated_at"] != before["updated_at"]


def test_pagination_walks_every_ticket_exactly_once(app_factory: AppFactory) -> None:
    """A full walk with a small page size returns each ticket once."""
    from tests.fixtures.synthetic_data import make_ticket

    tickets = [
        make_ticket(ticket_id=f"dddddddd-{n:04d}-4000-8000-dddddddddddd", organization_id=ORG_A)
        for n in range(7)
    ]
    harness = app_factory(tickets=tickets).as_admin(ORG_A, USER_A_ADMIN)

    collected: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, object] = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        body = harness.client.get("/v1/tickets", params=params).json()
        collected.extend(item["ticket_id"] for item in body["items"])
        cursor = body["next_cursor"]
        if not cursor:
            break

    assert sorted(collected) == sorted(t.ticket_id for t in tickets)
    assert len(collected) == len(set(collected))


def test_empty_list_returns_an_empty_page(app_factory: AppFactory) -> None:
    """No tickets is a valid state, not an error."""
    harness = app_factory().as_admin(ORG_A, USER_A_ADMIN)
    response = harness.client.get("/v1/tickets")

    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


def test_admin_sees_both_members_tickets_but_member_sees_one(harness: ApiHarness) -> None:
    """The role genuinely changes what the collection endpoint returns."""
    admin_items = harness.as_admin(ORG_A, USER_A_ADMIN).client.get("/v1/tickets").json()["items"]
    member_items = harness.as_member(ORG_A, USER_A_MEMBER).client.get("/v1/tickets").json()["items"]

    assert {item["ticket_id"] for item in admin_items} == {TICKET_A1, TICKET_A2}
    assert {item["ticket_id"] for item in member_items} == {TICKET_A1}


def test_health_is_reachable_and_stable(app_factory: AppFactory) -> None:
    """The liveness contract used by monitors."""
    harness = app_factory().anonymous()
    response = harness.client.get("/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ticket-api"
    assert set(body) == {"status", "service", "version", "environment"}
