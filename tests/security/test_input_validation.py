"""Input validation tests.

Every byte that crosses the trust boundary is validated against an explicit
schema. Pydantic models use ``extra="forbid"`` so that an unexpected field is
a *rejection*, not a silently-ignored field -- an attacker probing for mass
assignment should get a 422 that is visible in the logs, not a 200.
"""

from __future__ import annotations

import pytest

from tests.conftest import ApiHarness
from tests.fixtures.synthetic_data import ORG_A, TICKET_A1, USER_A_ADMIN, USER_A_MEMBER

pytestmark = pytest.mark.security

VALID_CREATE = {"title": "Cannot sign in", "description": "Synthetic description"}


# ---------------------------------------------------------------------------
# Create: required fields, types, bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="empty-body"),
        pytest.param({"description": "no title"}, id="missing-title"),
        pytest.param({"title": "no description"}, id="missing-description"),
        pytest.param({"title": "", "description": "x"}, id="empty-title"),
        pytest.param({"title": "x", "description": ""}, id="empty-description"),
        pytest.param({"title": "   ", "description": "x"}, id="whitespace-title"),
        pytest.param({"title": 12345, "description": "x"}, id="title-wrong-type"),
        pytest.param({"title": "x", "description": ["a", "b"]}, id="description-wrong-type"),
        pytest.param({"title": ["x"], "description": "y"}, id="title-is-list"),
        pytest.param({"title": None, "description": "y"}, id="title-null"),
        pytest.param({**VALID_CREATE, "priority": "catastrophic"}, id="unsupported-priority"),
        pytest.param({**VALID_CREATE, "priority": 3}, id="priority-wrong-type"),
        pytest.param({**VALID_CREATE, "status": "open"}, id="status-not-client-settable"),
        pytest.param({**VALID_CREATE, "ticket_id": TICKET_A1}, id="ticket-id-not-client-settable"),
        pytest.param({**VALID_CREATE, "created_by": "someone-else"}, id="created-by-not-settable"),
        pytest.param({**VALID_CREATE, "organization_id": "org-other"}, id="org-not-settable"),
        pytest.param({**VALID_CREATE, "created_at": "2020-01-01T00:00:00Z"}, id="timestamp"),
        pytest.param({**VALID_CREATE, "__proto__": {"admin": True}}, id="prototype-pollution"),
        pytest.param({**VALID_CREATE, "unexpected_field": "x"}, id="unknown-field"),
    ],
)
def test_invalid_create_payloads_are_rejected(empty_harness: ApiHarness, payload: dict) -> None:
    """Invalid or over-reaching create payloads must be a 422, never a 201."""
    response = empty_harness.as_member().client.post("/v1/tickets", json=payload)
    assert response.status_code == 422, f"payload={payload} -> {response.status_code}"
    assert empty_harness.tickets.all_tickets() == []


@pytest.mark.parametrize(
    ("field", "length"),
    [("title", 201), ("description", 10_001)],
)
def test_oversized_input_is_rejected(empty_harness: ApiHarness, field: str, length: int) -> None:
    """Field length is bounded so a single request cannot bloat an item.

    DynamoDB's hard item limit is 400 KB; an unbounded description would turn
    a write into a reliability and cost problem, and would let one tenant fill
    a partition.
    """
    payload = {**VALID_CREATE, field: "A" * length}
    response = empty_harness.as_member().client.post("/v1/tickets", json=payload)
    assert response.status_code == 422, response.text


def test_input_at_the_boundary_is_accepted(empty_harness: ApiHarness) -> None:
    """The limits must be inclusive, so legitimate maximum-length input works."""
    payload = {"title": "A" * 200, "description": "B" * 10_000, "priority": "urgent"}
    response = empty_harness.as_member().client.post("/v1/tickets", json=payload)
    assert response.status_code == 201, response.text


def test_malformed_json_body_is_rejected(empty_harness: ApiHarness) -> None:
    """A body that is not JSON must be a 4xx, never a 500."""
    response = empty_harness.as_member().client.post(
        "/v1/tickets",
        content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422, response.text


def test_wrong_content_type_is_rejected(empty_harness: ApiHarness) -> None:
    """A form-encoded body must not be coerced into the JSON model."""
    response = empty_harness.as_member().client.post(
        "/v1/tickets",
        content=b"title=x&description=y",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code in (415, 422), response.text


# ---------------------------------------------------------------------------
# F-004: update payloads and mass assignment
# ---------------------------------------------------------------------------


@pytest.mark.regression
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"organization_id": "org-other"}, id="organization_id"),
        pytest.param({"created_by": "attacker"}, id="created_by"),
        pytest.param({"ticket_id": "forged"}, id="ticket_id"),
        pytest.param({"created_at": "2020-01-01T00:00:00Z"}, id="created_at"),
        pytest.param({"updated_at": "2020-01-01T00:00:00Z"}, id="updated_at"),
        pytest.param({"PK": "TENANT#org-other"}, id="raw-partition-key"),
        pytest.param({"SK": "TICKET#forged"}, id="raw-sort-key"),
        pytest.param({"role": "admin"}, id="unrelated-privilege-field"),
        pytest.param({"title": "ok", "organization_id": "org-other"}, id="valid-plus-forbidden"),
    ],
)
def test_update_rejects_server_controlled_fields(harness: ApiHarness, payload: dict) -> None:
    """Guards finding F-004 (CWE-915, mass assignment).

    Server-controlled attributes must not be writable through PATCH. The model
    forbids unknown fields, so these are rejected before any business logic
    runs.
    """
    before = harness.tickets.raw(ORG_A)[TICKET_A1].model_dump()
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.patch(
        f"/v1/tickets/{TICKET_A1}", json=payload
    )

    assert response.status_code == 422, f"payload={payload} -> {response.text}"
    assert harness.tickets.raw(ORG_A)[TICKET_A1].model_dump() == before


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="no-fields"),
        pytest.param({"title": None, "description": None}, id="all-null"),
        pytest.param({"status": "nonexistent_status"}, id="invalid-status"),
        pytest.param({"status": 1}, id="status-wrong-type"),
        pytest.param({"priority": "catastrophic"}, id="invalid-priority"),
        pytest.param({"title": "A" * 201}, id="oversized-title"),
        pytest.param({"title": ""}, id="empty-title"),
    ],
)
def test_invalid_update_payloads_are_rejected(harness: ApiHarness, payload: dict) -> None:
    """An update must carry at least one valid, in-range field."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.patch(
        f"/v1/tickets/{TICKET_A1}", json=payload
    )
    assert response.status_code == 422, f"payload={payload} -> {response.text}"


# ---------------------------------------------------------------------------
# F-011: identifier validation (sort-key injection)
# ---------------------------------------------------------------------------


@pytest.mark.regression
@pytest.mark.parametrize(
    "ticket_id",
    [
        pytest.param("not-a-uuid", id="not-a-uuid"),
        pytest.param("../../etc/passwd", id="path-traversal"),
        pytest.param("TICKET#x", id="embedded-key-prefix"),
        pytest.param("aaaa#bbbb", id="embedded-separator"),
        pytest.param("", id="empty"),
        pytest.param("  ", id="whitespace"),
        pytest.param("a" * 300, id="oversized"),
        pytest.param("00000000-0000-0000-0000-00000000000g", id="invalid-hex"),
        pytest.param("%2e%2e%2f", id="encoded-traversal"),
        pytest.param("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa\u0000", id="null-byte"),
    ],
)
def test_ticket_identifier_must_be_a_uuid(harness: ApiHarness, ticket_id: str) -> None:
    """Guards finding F-011 (CWE-20).

    ``ticket_id`` is concatenated into a DynamoDB sort key. An identifier
    containing the ``#`` separator could address a key the application never
    intended to expose, so the format is constrained to a UUID at the edge.
    """
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.get(f"/v1/tickets/{ticket_id}")
    assert response.status_code in (404, 422), f"{ticket_id!r} -> {response.status_code}"
    # The crucial part: a malformed id must never reach the data store.
    assert all(
        name != "get_ticket" or _looks_like_uuid(kwargs.get("ticket_id", ""))
        for name, kwargs in harness.tickets.calls
    ), f"A malformed identifier reached the store: {harness.tickets.calls}"


def _looks_like_uuid(value: str) -> bool:
    """True when the value is a canonical 36-character UUID string."""
    import uuid

    try:
        return str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def test_valid_uuid_identifier_is_accepted(harness: ApiHarness) -> None:
    """The validation must not reject legitimate identifiers."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get(f"/v1/tickets/{TICKET_A1}")
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# F-009: bounded pagination
# ---------------------------------------------------------------------------


@pytest.mark.regression
@pytest.mark.parametrize(
    "limit",
    [
        pytest.param("0", id="zero"),
        pytest.param("-1", id="negative"),
        pytest.param("101", id="above-maximum"),
        pytest.param("100000", id="far-above-maximum"),
        pytest.param("abc", id="not-a-number"),
        pytest.param("1.5", id="not-an-integer"),
        pytest.param("9999999999999999999999", id="integer-overflow-attempt"),
        pytest.param("", id="empty"),
    ],
)
def test_pagination_limit_is_bounded(harness: ApiHarness, limit: str) -> None:
    """Guards finding F-009 (CWE-770).

    An unbounded ``limit`` lets a single request read an entire tenant
    partition, which is both a cost/denial-of-service lever and a bulk
    exfiltration lever if any other control ever fails.
    """
    response = harness.as_admin(ORG_A, USER_A_ADMIN).client.get(
        "/v1/tickets", params={"limit": limit}
    )
    assert response.status_code == 422, f"limit={limit!r} -> {response.status_code}"


@pytest.mark.parametrize("limit", ["1", "25", "100"])
def test_pagination_limit_accepts_values_in_range(harness: ApiHarness, limit: str) -> None:
    """Valid limits must be honoured."""
    response = harness.as_admin(ORG_A, USER_A_ADMIN).client.get(
        "/v1/tickets", params={"limit": limit}
    )
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) <= int(limit)


def test_omitted_limit_uses_the_server_default(harness: ApiHarness) -> None:
    """A client that sends no limit gets the configured default, not everything."""
    response = harness.as_admin(ORG_A, USER_A_ADMIN).client.get("/v1/tickets")
    assert response.status_code == 200, response.text

    limits = [
        kwargs["limit"] for name, kwargs in harness.tickets.calls if name == "list_tickets"
    ]
    assert limits and all(1 <= value <= 100 for value in limits), limits
