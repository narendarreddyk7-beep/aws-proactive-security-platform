"""Error-handling and information-disclosure tests.

An error response is an output channel like any other. These tests assert that
failures are useful to the caller and to the on-call engineer, without handing
an attacker a map of the system.
"""

from __future__ import annotations

import pytest

from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.synthetic_data import (
    ORG_A,
    SENSITIVE_DESCRIPTION,
    TICKET_A1,
    TICKET_A2,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
)

pytestmark = pytest.mark.security

UNKNOWN_TICKET = "99999999-9999-4999-8999-999999999999"


class _ExplodingStore:
    """A store whose every method raises, to drive the 500 path."""

    def __init__(self, message: str) -> None:
        self._message = message
        self.calls = 0

    def _boom(self) -> None:
        self.calls += 1
        raise RuntimeError(self._message)

    def put_ticket(self, *_: object, **__: object) -> None:
        self._boom()

    def get_ticket(self, *_: object, **__: object) -> None:
        self._boom()

    def list_tickets(self, *_: object, **__: object) -> None:
        self._boom()

    def save_ticket(self, *_: object, **__: object) -> None:
        self._boom()


# ---------------------------------------------------------------------------
# F-008: unhandled errors must not leak internals
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_unhandled_error_response_contains_no_diagnostics(app_factory: AppFactory) -> None:
    """Guards finding F-008 (CWE-209).

    The 500 body must not contain a stack trace, an exception message, a file
    path, a module name, or a library name. Those tell an attacker which
    libraries and versions are in play and where the code lives.
    """
    from app.dependencies import get_ticket_store

    secret_marker = "SYNTHETIC-INTERNAL-DETAIL-9f3a"
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    harness.app.dependency_overrides[get_ticket_store] = lambda: _ExplodingStore(
        f"connection to table failed: {secret_marker}"
    )

    response = harness.client.get("/v1/tickets")

    assert response.status_code == 500
    body = response.text
    assert secret_marker not in body, "The exception message was returned to the client"
    for leak in ("Traceback", "RuntimeError", ".py", "app/", "site-packages", "boto"):
        assert leak not in body, f"Response leaked {leak!r}: {body}"

    payload = response.json()
    assert set(payload) == {"error", "message", "request_id"}, payload
    assert payload["error"] == "internal_error"
    assert payload["request_id"]


@pytest.mark.regression
def test_unhandled_error_is_logged_with_full_detail(
    app_factory: AppFactory, capture_logs
) -> None:
    """Guards finding F-008.

    Redaction must not destroy debuggability: the detail the client does *not*
    get has to be in CloudWatch, correlated by request id, or nobody can fix
    the bug.
    """
    from app.dependencies import get_ticket_store

    marker = "SYNTHETIC-INTERNAL-DETAIL-b71c"
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    harness.app.dependency_overrides[get_ticket_store] = lambda: _ExplodingStore(marker)
    logs = capture_logs()

    response = harness.client.get("/v1/tickets")
    request_id = response.json()["request_id"]

    assert marker in logs.text(), "The failure detail was not logged anywhere"
    assert any(
        payload.get("request_id") == request_id for payload in logs.payloads()
    ), "The log line cannot be correlated to the response the caller received"


@pytest.mark.regression
def test_not_found_message_is_generic(harness: ApiHarness) -> None:
    """Guards finding F-008: a 404 must not echo identifiers or tenancy."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get(f"/v1/tickets/{UNKNOWN_TICKET}")

    assert response.status_code == 404
    body = response.text
    assert UNKNOWN_TICKET not in body
    assert ORG_A not in body
    assert set(response.json()) == {"error", "message", "request_id"}


@pytest.mark.regression
def test_forbidden_message_does_not_disclose_the_owner(harness: ApiHarness) -> None:
    """Guards finding F-008.

    A 403 confirms the ticket exists inside the caller's own tenant, which is
    acceptable. It must not additionally disclose *who* owns it or any of its
    content.
    """
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get(f"/v1/tickets/{TICKET_A2}")

    assert response.status_code == 403
    body = response.text
    assert USER_A_MEMBER_2 not in body, "The 403 disclosed the owning user id"
    assert "Billing discrepancy" not in body, "The 403 disclosed ticket content"
    assert set(response.json()) == {"error", "message", "request_id"}


@pytest.mark.regression
def test_validation_error_does_not_echo_submitted_values(empty_harness: ApiHarness) -> None:
    """Guards finding F-008.

    FastAPI's default 422 body echoes the offending input. For a support API
    that is a real exposure: validation errors are frequently logged by API
    gateways, proxies and client-side error reporters, so echoing the raw
    submitted ticket body widens where that content can end up.
    """
    response = empty_harness.as_member().client.post(
        "/v1/tickets",
        json={"title": "x", "description": SENSITIVE_DESCRIPTION, "priority": "bogus"},
    )

    assert response.status_code == 422
    assert SENSITIVE_DESCRIPTION not in response.text, (
        "The 422 body echoed the submitted ticket description"
    )
    payload = response.json()
    assert set(payload) == {"error", "message", "request_id", "fields"}
    # The caller still learns *which* field was wrong -- just not its value.
    assert any("priority" in str(entry) for entry in payload["fields"])
    for entry in payload["fields"]:
        assert "input" not in entry
        assert "ctx" not in entry


def test_error_shape_is_consistent_across_status_codes(
    app_factory: AppFactory, seeded_tickets: list
) -> None:
    """Every error response shares one envelope so clients can parse uniformly."""
    from app.dependencies import get_ticket_store

    harness = app_factory(tickets=seeded_tickets)

    harness.anonymous()
    unauthenticated = harness.client.get("/v1/tickets")

    harness.as_member(ORG_A, USER_A_MEMBER)
    forbidden = harness.client.get(f"/v1/tickets/{TICKET_A2}")
    not_found = harness.client.get(f"/v1/tickets/{UNKNOWN_TICKET}")

    harness.app.dependency_overrides[get_ticket_store] = lambda: _ExplodingStore("boom")
    server_error = harness.client.get("/v1/tickets")

    codes = [
        unauthenticated.status_code,
        forbidden.status_code,
        not_found.status_code,
        server_error.status_code,
    ]
    assert codes == [401, 403, 404, 500], codes

    for response in (unauthenticated, forbidden, not_found, server_error):
        payload = response.json()
        assert "error" in payload and "message" in payload, payload
        assert isinstance(payload["error"], str)
        assert "trace" not in payload
        assert "traceback" not in payload


def test_no_server_banner_headers_are_returned(harness: ApiHarness) -> None:
    """Version banners make fingerprinting trivial; they must not be present."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get("/v1/health")
    lowered = {key.lower(): value for key, value in response.headers.items()}
    assert "x-powered-by" not in lowered
    assert "uvicorn" not in lowered.get("server", "").lower()
