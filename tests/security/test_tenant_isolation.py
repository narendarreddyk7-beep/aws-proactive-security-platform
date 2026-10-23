"""Tenant isolation tests.

The single most important property of this system: **an identity in one
organization must never be able to read, enumerate, or modify another
organization's data, by any route.**

Three defences are asserted here:

1. The effective tenant comes only from verified claims.
2. Every data-store call is scoped to that tenant.
3. A denial does not reveal that another tenant's resource exists.
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    TICKET_A2,
    TICKET_B1,
    USER_A_ADMIN,
    USER_B_MEMBER,
)

pytestmark = pytest.mark.security

UNKNOWN_TICKET = "99999999-9999-4999-8999-999999999999"


# ---------------------------------------------------------------------------
# Cross-tenant read
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_cross_tenant_read_is_denied(harness: ApiHarness) -> None:
    """Guards findings F-001 and F-003.

    A member of org B requesting a ticket that exists in org A must be denied.
    """
    response = harness.as_other_tenant().client.get(f"/v1/tickets/{TICKET_A1}")
    assert response.status_code == 404, response.text


@pytest.mark.regression
def test_cross_tenant_denial_does_not_disclose_existence(harness: ApiHarness) -> None:
    """Guards finding F-008.

    A cross-tenant read must be indistinguishable from a read of a ticket that
    does not exist. Otherwise the API becomes an oracle for enumerating other
    tenants' ticket IDs, organization names and ticket owners.
    """
    harness.as_other_tenant()

    existing_elsewhere = harness.client.get(f"/v1/tickets/{TICKET_A1}")
    does_not_exist = harness.client.get(f"/v1/tickets/{UNKNOWN_TICKET}")

    assert existing_elsewhere.status_code == does_not_exist.status_code == 404
    assert existing_elsewhere.json() == does_not_exist.json(), (
        "Responses differ, so the API confirms whether another tenant's ticket exists"
    )

    body = existing_elsewhere.text
    for leaked in (ORG_A, TICKET_A1):
        assert leaked not in body, f"Response body disclosed {leaked!r}"


@pytest.mark.regression
def test_cross_tenant_update_is_denied(harness: ApiHarness) -> None:
    """Guards findings F-001 and F-003."""
    response = harness.as_other_tenant().client.patch(
        f"/v1/tickets/{TICKET_A1}", json={"status": "closed"}
    )
    assert response.status_code == 404, response.text

    # And the target ticket must be byte-for-byte unchanged.
    stored = harness.tickets.raw(ORG_A)[TICKET_A1]
    assert stored.status.value == "open"


# ---------------------------------------------------------------------------
# Cross-tenant enumeration via list
# ---------------------------------------------------------------------------


def test_list_returns_only_the_callers_tenant(harness: ApiHarness) -> None:
    """An admin of org A sees org A tickets and nothing else."""
    response = harness.as_admin(ORG_A, USER_A_ADMIN).client.get("/v1/tickets")
    assert response.status_code == 200, response.text

    items = response.json()["items"]
    assert {item["ticket_id"] for item in items} == {TICKET_A1, TICKET_A2}
    assert {item["organization_id"] for item in items} == {ORG_A}


def test_other_tenant_list_is_disjoint(harness: ApiHarness) -> None:
    """Org B sees only org B tickets, confirming the partition holds both ways."""
    response = harness.as_other_tenant().client.get("/v1/tickets")
    assert response.status_code == 200, response.text

    items = response.json()["items"]
    assert {item["ticket_id"] for item in items} == {TICKET_B1}


def test_every_store_call_is_scoped_to_the_verified_tenant(harness: ApiHarness) -> None:
    """No data-store call may be made with a tenant other than the caller's."""
    harness.as_admin(ORG_A, USER_A_ADMIN)
    harness.client.get("/v1/tickets")
    harness.client.get(f"/v1/tickets/{TICKET_A1}")
    harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"priority": "high"})

    organizations = {
        kwargs.get("organization_id")
        for _name, kwargs in harness.tickets.calls
        if kwargs.get("organization_id") is not None
    }
    assert organizations == {ORG_A}, f"Store was accessed with tenants {organizations}"


# ---------------------------------------------------------------------------
# F-001 / F-004: client-supplied organization identifiers
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_create_cannot_target_another_tenant_via_request_body(
    empty_harness: ApiHarness,
) -> None:
    """Guards findings F-001 and F-004.

    ``organization_id`` is not a client-writable field. Supplying it must be
    rejected outright rather than silently honoured or silently dropped --
    rejection makes a probing client visible in the logs.
    """
    response = empty_harness.as_member(ORG_A).client.post(
        "/v1/tickets",
        json={
            "title": "Cross-tenant write attempt",
            "description": "Synthetic test payload",
            "organization_id": ORG_B,
        },
    )
    assert response.status_code == 422, response.text

    assert empty_harness.tickets.all_tickets() == [], (
        "A ticket was persisted despite the request being rejected"
    )


@pytest.mark.regression
def test_update_cannot_move_a_ticket_to_another_tenant(harness: ApiHarness) -> None:
    """Guards finding F-004.

    Mass assignment through PATCH must not be able to rewrite the tenancy or
    ownership of a record.
    """
    harness.as_member(ORG_A)
    response = harness.client.patch(
        f"/v1/tickets/{TICKET_A1}",
        json={"organization_id": ORG_B, "created_by": USER_B_MEMBER},
    )
    assert response.status_code == 422, response.text

    stored = harness.tickets.raw(ORG_A)[TICKET_A1]
    assert stored.organization_id == ORG_A
    assert stored.created_by != USER_B_MEMBER
    assert harness.tickets.raw(ORG_B) == {}


# ---------------------------------------------------------------------------
# F-010: pagination cursors are client-controlled input
# ---------------------------------------------------------------------------


def _forge_cursor(organization_id: str, ticket_id: str) -> str:
    """Build a cursor that points into another tenant's partition."""
    key = {
        "PK": f"TENANT#{organization_id}",
        "SK": f"TICKET#{ticket_id}",
        "ticket_id": ticket_id,
    }
    raw = json.dumps(key, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(raw.encode()).decode()


@pytest.mark.regression
def test_pagination_cursor_from_another_tenant_is_rejected(harness: ApiHarness) -> None:
    """Guards finding F-010.

    An opaque cursor is still attacker-controlled input. A cursor whose
    partition key does not belong to the caller must be refused, not passed
    through to DynamoDB as an ``ExclusiveStartKey``.
    """
    forged = _forge_cursor(ORG_B, TICKET_B1)
    response = harness.as_member(ORG_A).client.get("/v1/tickets", params={"cursor": forged})

    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_request"

    forwarded = [
        kwargs.get("cursor") for name, kwargs in harness.tickets.calls if name == "list_tickets"
    ]
    assert all(c is None for c in forwarded), (
        f"A forged cursor was forwarded to the data store: {forwarded}"
    )


@pytest.mark.regression
@pytest.mark.parametrize(
    "cursor",
    [
        pytest.param("not-base64!!", id="not-base64"),
        pytest.param(base64.urlsafe_b64encode(b"not json").decode(), id="not-json"),
        pytest.param(base64.urlsafe_b64encode(b'["a","list"]').decode(), id="json-not-object"),
        pytest.param(base64.urlsafe_b64encode(b'{"PK":"TENANT#x"}').decode(), id="missing-sk"),
        pytest.param(base64.urlsafe_b64encode(b"{}").decode(), id="empty-object"),
        pytest.param("A" * 5000, id="oversized"),
    ],
)
def test_malformed_pagination_cursor_is_rejected(harness: ApiHarness, cursor: str) -> None:
    """Guards finding F-010: malformed cursors are a 400, never a 500."""
    response = harness.as_member(ORG_A).client.get("/v1/tickets", params={"cursor": cursor})
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_request"


def test_legitimate_pagination_round_trip(app_factory: AppFactory) -> None:
    """A cursor the API itself issued must work, and must not skip or repeat."""
    from tests.fixtures.synthetic_data import make_ticket

    tickets = [
        make_ticket(ticket_id=f"aaaaaaaa-{n:04d}-4000-8000-aaaaaaaaaaaa", organization_id=ORG_A)
        for n in range(5)
    ]
    harness = app_factory(tickets=tickets).as_admin(ORG_A, USER_A_ADMIN)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(5):
        params: dict[str, object] = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        response = harness.client.get("/v1/tickets", params=params)
        assert response.status_code == 200, response.text
        body = response.json()
        seen.extend(item["ticket_id"] for item in body["items"])
        cursor = body.get("next_cursor")
        if not cursor:
            break

    assert len(seen) == len(set(seen)) == 5, f"Pagination skipped or repeated items: {seen}"
