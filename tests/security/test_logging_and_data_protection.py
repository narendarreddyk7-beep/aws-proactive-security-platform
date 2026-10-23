"""Logging and data-protection tests.

CloudWatch Logs is a long-lived, widely-readable data store. Anything written
there inherits a much larger blast radius than the request that produced it, so
these tests assert what the application is **forbidden** to log, and what it is
**required** to log for security investigation.

Design: the application's logger uses a field allow-list. A new field is
invisible until it is explicitly permitted, which fails safe when someone adds
``extra={"ticket": ticket}`` in a hurry.
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import AppFactory
from tests.fixtures.synthetic_data import (
    ORG_A,
    SENSITIVE_DESCRIPTION,
    TICKET_A1,
    TICKET_A2,
    USER_A_ADMIN,
    USER_A_MEMBER,
)

pytestmark = pytest.mark.security

SYNTHETIC_TOKEN = "eyJhbGciOiJSUzI1NiJ9.SYNTHETIC-ACCESS-TOKEN-DO-NOT-LOG.signature"


# ---------------------------------------------------------------------------
# F-007: secrets and customer content must never be logged
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_authorization_header_is_never_logged(app_factory: AppFactory, capture_logs) -> None:
    """Guards finding F-007 (CWE-532).

    A bearer token in CloudWatch is a replayable credential available to
    everyone with log-read access, for the whole retention period.
    """
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    response = harness.client.post(
        "/v1/tickets",
        json={"title": "Login issue", "description": "Synthetic body"},
        headers={"Authorization": f"Bearer {SYNTHETIC_TOKEN}"},
    )
    assert response.status_code == 201, response.text

    output = logs.text()
    assert SYNTHETIC_TOKEN not in output, "The access token was written to the logs"
    assert "Bearer " not in output
    assert "authorization" not in output.lower()


@pytest.mark.regression
def test_ticket_content_is_never_logged(app_factory: AppFactory, capture_logs) -> None:
    """Guards finding F-007.

    Ticket titles and descriptions are customer content: they routinely contain
    account identifiers, contact details and operational detail about the
    customer's own systems. Logging them copies customer data into a second
    store with different access controls and a different retention policy.
    """
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    response = harness.client.post(
        "/v1/tickets",
        json={"title": "Cannot export invoices", "description": SENSITIVE_DESCRIPTION},
    )
    assert response.status_code == 201, response.text

    output = logs.text()
    assert SENSITIVE_DESCRIPTION not in output, "The ticket description was logged"
    assert "Cannot export invoices" not in output, "The ticket title was logged"
    assert "person@example.invalid" not in output
    assert "SYNTHETIC-9910" not in output


@pytest.mark.regression
def test_update_changes_are_logged_as_field_names_only(
    app_factory: AppFactory, seeded_tickets: list, capture_logs
) -> None:
    """Guards finding F-007.

    Knowing *which* fields changed is valuable for audit. Knowing their values
    is customer content. The audit log keeps the former and drops the latter.
    """
    harness = app_factory(tickets=seeded_tickets).as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    secret = "NEW-DESCRIPTION-SYNTHETIC-4c2d"
    response = harness.client.patch(f"/v1/tickets/{TICKET_A1}", json={"description": secret})
    assert response.status_code == 200, response.text

    output = logs.text()
    assert secret not in output, "The new field value was logged"

    events = logs.events("ticket_updated")
    assert events, "No ticket_updated audit event was emitted"
    assert events[0].get("changed_fields") == ["description"]


@pytest.mark.regression
def test_log_payloads_only_contain_allow_listed_fields(
    app_factory: AppFactory, capture_logs
) -> None:
    """Guards finding F-007.

    The allow-list is the control. This test asserts the control itself: a
    caller that smuggles an unexpected ``extra`` field must not see it appear
    in the rendered log line.
    """
    from app.observability.logging import ALLOWED_LOG_FIELDS, get_logger

    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    get_logger("app.test").info(
        "synthetic event",
        extra={
            "event_type": "synthetic",
            "outcome": "allowed",
            "secret_value": "MUST-NOT-APPEAR-1a2b",
            "ticket": {"description": "MUST-NOT-APPEAR-3c4d"},
        },
    )
    harness.client.get("/v1/tickets")

    output = logs.text()
    assert "MUST-NOT-APPEAR-1a2b" not in output
    assert "MUST-NOT-APPEAR-3c4d" not in output

    for payload in logs.payloads():
        unexpected = set(payload) - ALLOWED_LOG_FIELDS
        assert not unexpected, f"Log line carried non-allow-listed fields: {unexpected}"


def test_every_log_line_is_single_line_json(app_factory: AppFactory, capture_logs) -> None:
    """CloudWatch Logs Insights needs one JSON object per line to query fields."""
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()
    harness.client.get("/v1/tickets")

    assert logs.lines, "Nothing was logged for a successful request"
    for line in logs.lines:
        assert "\n" not in line, f"Multi-line log record would break ingestion: {line!r}"
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
        for required in ("timestamp", "severity", "component", "request_id"):
            assert required in parsed, f"{required} missing from {parsed}"


# ---------------------------------------------------------------------------
# Required security events
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_authorization_denial_emits_a_security_event(
    app_factory: AppFactory, seeded_tickets: list, capture_logs
) -> None:
    """A denial that is not logged cannot be alerted on or investigated.

    This event is the signal behind the ``AuthorizationDenied`` CloudWatch
    metric filter and alarm defined in ``infrastructure/terraform/monitoring.tf``,
    and it is the primary input to runbook A.
    """
    harness = app_factory(tickets=seeded_tickets).as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    assert harness.client.get(f"/v1/tickets/{TICKET_A2}").status_code == 403

    events = logs.events("authorization_denied")
    assert events, f"No authorization_denied event logged. Saw: {logs.payloads()}"

    event = events[0]
    assert event["severity"] == "warning"
    assert event["outcome"] == "denied"
    assert event["request_id"]
    # Identifiers needed to investigate, nothing more.
    assert event.get("organization_id") == ORG_A
    assert event.get("principal_id") == USER_A_MEMBER
    assert "description" not in event


def test_authentication_failure_emits_a_security_event(
    app_factory: AppFactory, capture_logs
) -> None:
    """Unauthenticated access attempts must be visible for alerting."""
    harness = app_factory().anonymous()
    logs = capture_logs()

    assert harness.client.get("/v1/tickets").status_code == 401

    events = logs.events("authentication_failed")
    assert events, f"No authentication_failed event logged. Saw: {logs.payloads()}"
    assert events[0]["outcome"] == "denied"


def test_successful_access_is_auditable_without_content(
    app_factory: AppFactory, seeded_tickets: list, capture_logs
) -> None:
    """Successful privileged reads are audit-relevant too."""
    harness = app_factory(tickets=seeded_tickets).as_admin(ORG_A, USER_A_ADMIN)
    logs = capture_logs()

    assert harness.client.get(f"/v1/tickets/{TICKET_A2}").status_code == 200

    events = logs.events("ticket_read")
    assert events, f"No ticket_read audit event logged. Saw: {logs.payloads()}"
    assert events[0]["outcome"] == "allowed"
    assert events[0].get("principal_id") == USER_A_ADMIN
    assert "Billing discrepancy" not in logs.text()


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def test_request_id_is_returned_and_correlates_with_logs(
    app_factory: AppFactory, capture_logs
) -> None:
    """One identifier must tie a caller's report to the log lines it produced."""
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    response = harness.client.get("/v1/tickets")
    request_id = response.headers.get("X-Request-Id")

    assert request_id, "No X-Request-Id response header"
    assert any(p.get("request_id") == request_id for p in logs.payloads()), (
        f"No log line carries request_id={request_id}"
    )


def test_client_supplied_request_id_cannot_poison_the_logs(
    app_factory: AppFactory, capture_logs
) -> None:
    """A client-supplied correlation id must be constrained.

    Accepting an arbitrary client string lets a caller forge or collide with
    another request's identifier, or inject newlines to fabricate log entries.
    """
    harness = app_factory().as_member(ORG_A, USER_A_MEMBER)
    logs = capture_logs()

    harness.client.get(
        "/v1/tickets",
        headers={"X-Request-Id": 'spoofed"}\n{"severity":"info","message":"forged'},
    )

    output = logs.text()
    assert "forged" not in output, "A client injected a fabricated log record"
    for line in logs.lines:
        json.loads(line)  # every line must still be valid JSON
