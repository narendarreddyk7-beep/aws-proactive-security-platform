"""HTTP and API-surface security tests.

Covers the controls that live at the protocol layer rather than in business
logic: response headers, allowed methods, response-schema discipline, CORS, and
what the service discloses about itself.
"""

from __future__ import annotations

import pytest

from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.synthetic_data import ORG_A, TICKET_A1, USER_A_MEMBER

pytestmark = pytest.mark.security

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


# ---------------------------------------------------------------------------
# F-014: security response headers
# ---------------------------------------------------------------------------


@pytest.mark.regression
@pytest.mark.parametrize("header", sorted(EXPECTED_SECURITY_HEADERS))
def test_security_headers_present_on_success(harness: ApiHarness, header: str) -> None:
    """Guards finding F-014 (CWE-693).

    ``no-store`` matters most here: without it a shared cache or a browser can
    retain another tenant's ticket data. ``nosniff`` prevents a JSON body
    containing attacker-influenced text from being re-interpreted as HTML.
    """
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get(f"/v1/tickets/{TICKET_A1}")
    assert response.status_code == 200, response.text

    actual = {key.lower(): value for key, value in response.headers.items()}
    assert actual.get(header) == EXPECTED_SECURITY_HEADERS[header], actual


@pytest.mark.regression
def test_security_headers_present_on_error_responses(harness: ApiHarness) -> None:
    """Guards finding F-014: error paths must not skip the headers."""
    harness.anonymous()
    unauthenticated = harness.client.get("/v1/tickets")

    harness.as_member(ORG_A, USER_A_MEMBER)
    not_found = harness.client.get("/v1/tickets/99999999-9999-4999-8999-999999999999")

    for response in (unauthenticated, not_found):
        actual = {key.lower(): value for key, value in response.headers.items()}
        for header, expected in EXPECTED_SECURITY_HEADERS.items():
            assert actual.get(header) == expected, (
                f"{header} missing on {response.status_code}: {actual}"
            )


# ---------------------------------------------------------------------------
# HTTP method discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("DELETE", "/v1/tickets/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
        ("PUT", "/v1/tickets/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
        ("POST", "/v1/tickets/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
        ("DELETE", "/v1/tickets"),
        ("PATCH", "/v1/tickets"),
        ("PUT", "/v1/tickets"),
        ("POST", "/v1/health"),
        ("DELETE", "/v1/health"),
    ],
)
def test_undefined_methods_are_rejected(harness: ApiHarness, method: str, path: str) -> None:
    """Only the documented verbs exist.

    Ticket deletion is deliberately not implemented: support records are an
    audit trail, and the closed status is the end state. An endpoint that does
    not exist cannot be abused.
    """
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.request(method, path, json={})
    assert response.status_code == 405, f"{method} {path} -> {response.status_code}"


def test_trace_and_connect_are_not_routed(harness: ApiHarness) -> None:
    """TRACE can be used to reflect headers; it must not be served."""
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.request("TRACE", "/v1/tickets")
    assert response.status_code in (404, 405, 501), response.status_code


def test_unknown_paths_return_404_without_detail(harness: ApiHarness) -> None:
    """A 404 for an unknown path must not reveal the routing table."""
    harness.as_member(ORG_A, USER_A_MEMBER)
    response = harness.client.get("/v1/admin/internal")
    assert response.status_code == 404
    assert "tickets" not in response.text.lower()


# ---------------------------------------------------------------------------
# Response schema discipline
# ---------------------------------------------------------------------------


EXPECTED_TICKET_FIELDS = {
    "ticket_id",
    "organization_id",
    "created_by",
    "title",
    "description",
    "priority",
    "status",
    "created_at",
    "updated_at",
}


def test_ticket_response_contains_exactly_the_documented_fields(
    empty_harness: ApiHarness,
) -> None:
    """No internal attributes (``PK``, ``SK``, ``GSI1PK``) may leak into the API."""
    response = empty_harness.as_member(ORG_A, USER_A_MEMBER).client.post(
        "/v1/tickets",
        json={"title": "Schema check", "description": "Synthetic body"},
    )
    assert response.status_code == 201, response.text
    assert set(response.json()) == EXPECTED_TICKET_FIELDS, set(response.json())


def test_list_response_shape_is_stable(harness: ApiHarness) -> None:
    """The collection envelope is exactly ``items`` + ``next_cursor``."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get("/v1/tickets")
    assert response.status_code == 200, response.text

    body = response.json()
    assert set(body) == {"items", "next_cursor"}
    for item in body["items"]:
        assert set(item) == EXPECTED_TICKET_FIELDS


def test_created_resource_returns_201_and_server_generated_identity(
    empty_harness: ApiHarness,
) -> None:
    """Server-generated identity: the client cannot choose the ticket id."""
    import uuid

    response = empty_harness.as_member(ORG_A, USER_A_MEMBER).client.post(
        "/v1/tickets",
        json={"title": "Identity check", "description": "Synthetic body"},
    )
    assert response.status_code == 201

    body = response.json()
    uuid.UUID(body["ticket_id"])  # raises if not a UUID
    assert body["created_by"] == USER_A_MEMBER
    assert body["organization_id"] == ORG_A
    assert body["status"] == "open"


def test_content_type_is_json(harness: ApiHarness) -> None:
    """Responses declare JSON so a browser never sniffs them as markup."""
    response = harness.as_member(ORG_A, USER_A_MEMBER).client.get("/v1/health")
    assert response.headers["content-type"].startswith("application/json")


# ---------------------------------------------------------------------------
# F-012: CORS and self-disclosure
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_cors_does_not_reflect_arbitrary_origins(app_factory: AppFactory) -> None:
    """Guards finding F-012 (CWE-942).

    ``Access-Control-Allow-Origin: *`` combined with credentialed requests
    would let any website read a signed-in user's tickets. The allow-list is
    configured per environment; an origin outside it must not be reflected.
    """
    harness = app_factory(env={"APP_CORS_ALLOW_ORIGINS": "https://app.example.invalid"})
    harness.as_member(ORG_A, USER_A_MEMBER)

    response = harness.client.get(
        "/v1/health", headers={"Origin": "https://evil.example.invalid"}
    )
    allowed = response.headers.get("access-control-allow-origin")
    assert allowed != "*", "Wildcard CORS origin is configured"
    assert allowed != "https://evil.example.invalid", "An untrusted origin was reflected"


@pytest.mark.regression
def test_cors_allows_the_configured_origin(app_factory: AppFactory) -> None:
    """Guards finding F-012: the allow-list must still work for the real UI."""
    harness = app_factory(env={"APP_CORS_ALLOW_ORIGINS": "https://app.example.invalid"})
    harness.as_member(ORG_A, USER_A_MEMBER)

    response = harness.client.get(
        "/v1/health", headers={"Origin": "https://app.example.invalid"}
    )
    assert response.headers.get("access-control-allow-origin") == "https://app.example.invalid"


@pytest.mark.regression
def test_health_endpoint_does_not_disclose_configuration(app_factory: AppFactory) -> None:
    """Guards finding F-012.

    The health endpoint is unauthenticated, so everything it returns is public.
    It must not name the DynamoDB table, the region, the user pool, or anything
    else that helps an attacker aim.
    """
    harness = app_factory(
        env={"APP_TABLE_NAME": "support-platform-secretname", "APP_AWS_REGION": "eu-west-2"}
    ).anonymous()

    response = harness.client.get("/v1/health")
    assert response.status_code == 200

    body = response.text
    for secret in ("support-platform-secretname", "eu-west-2", "cognito", "dynamodb"):
        assert secret.lower() not in body.lower(), f"Health endpoint disclosed {secret!r}"


@pytest.mark.regression
def test_interactive_docs_are_disabled_outside_local(app_factory: AppFactory) -> None:
    """Guards finding F-012.

    ``/docs`` and ``/openapi.json`` publish the whole API surface, including
    field names and bounds. Useful locally; an unnecessary disclosure in a
    deployed environment.
    """
    harness = app_factory(env={"APP_ENVIRONMENT": "production"}).anonymous()

    for path in ("/docs", "/redoc", "/openapi.json"):
        assert harness.client.get(path).status_code == 404, f"{path} is exposed"


def test_interactive_docs_are_available_locally(app_factory: AppFactory) -> None:
    """Developer experience must not be sacrificed for the above."""
    harness = app_factory(env={"APP_ENVIRONMENT": "local"}).anonymous()
    assert harness.client.get("/openapi.json").status_code == 200
