"""Lambda handler integration tests.

These tests exercise the real boundary that the security model depends on:
**Mangum translating an API Gateway HTTP API v2 event into an ASGI scope, with
the verified authorizer claims available at ``scope["aws.event"]``.**

This is worth testing directly rather than only through the ASGI harness. The
entire tenant-isolation design rests on the claim that the claims the gateway
verified really do arrive where ``ApiGatewayJwtIdentityProvider`` looks for
them. If Mangum changed that, every HTTP-level test would still pass while
production fell back to 401 (or worse).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from mangum import Mangum

from app.dependencies import get_membership_store, get_ticket_store
from app.main import create_app
from tests.fixtures.fake_store import InMemoryMembershipStore, InMemoryTicketStore
from tests.fixtures.gateway import build_event, gateway_claims
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    TICKET_B1,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_B_MEMBER,
    make_ticket,
)

pytestmark = pytest.mark.integration


def _lambda_context() -> SimpleNamespace:
    """A minimal stand-in for the AWS Lambda context object."""
    return SimpleNamespace(
        function_name="support-api-test",
        function_version="$LATEST",
        invoked_function_arn=("arn:aws:lambda:us-east-1:000000000000:function:support-api-test"),
        memory_limit_in_mb="512",
        aws_request_id="synthetic-lambda-request-id",
        log_group_name="/aws/lambda/support-api-test",
        log_stream_name="synthetic-stream",
        get_remaining_time_in_millis=lambda: 30_000,
    )


@pytest.fixture
def lambda_handler():
    """A Mangum handler over an app wired to in-memory stores."""
    from app.config import get_settings

    get_settings.cache_clear()
    application = create_app()

    tickets = InMemoryTicketStore(
        [
            make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, created_by=USER_A_MEMBER),
            make_ticket(ticket_id=TICKET_B1, organization_id=ORG_B, created_by=USER_B_MEMBER),
        ]
    )
    application.dependency_overrides[get_ticket_store] = lambda: tickets
    application.dependency_overrides[get_membership_store] = lambda: InMemoryMembershipStore()

    handler = Mangum(application, lifespan="off")
    handler.test_tickets = tickets  # type: ignore[attr-defined]
    return handler


def _invoke(handler: Any, event: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Invoke the handler and return (status, parsed body, headers)."""
    response = handler(event, _lambda_context())
    body = json.loads(response["body"]) if response.get("body") else {}
    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
    return response["statusCode"], body, headers


# ---------------------------------------------------------------------------
# The claim-plumbing contract
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.regression
def test_verified_gateway_claims_reach_the_application(lambda_handler) -> None:
    """Guards finding F-001.

    The whole identity model depends on these claims arriving at
    ``scope["aws.event"]["requestContext"]["authorizer"]["jwt"]["claims"]``.
    """
    event = build_event(
        gateway_claims(USER_A_MEMBER, ORG_A, "member"),
        method="GET",
        path="/v1/tickets",
    )
    status, body, _ = _invoke(lambda_handler, event)

    assert status == 200, body
    assert {item["ticket_id"] for item in body["items"]} == {TICKET_A1}
    assert {item["organization_id"] for item in body["items"]} == {ORG_A}


@pytest.mark.security
@pytest.mark.regression
def test_event_without_authorizer_context_is_unauthenticated(lambda_handler) -> None:
    """Guards finding F-001.

    This is the only state the function can observe for a token the gateway
    rejected (expired, bad signature, wrong audience): no authorizer context.
    """
    event = build_event(None, method="GET", path="/v1/tickets")
    status, body, _ = _invoke(lambda_handler, event)

    assert status == 401, body
    assert body["error"] == "not_authenticated"
    assert lambda_handler.test_tickets.operations() == []


@pytest.mark.security
@pytest.mark.regression
def test_identity_headers_on_the_lambda_event_are_ignored(lambda_handler) -> None:
    """Guards finding F-001 at the real integration boundary.

    An attacker who can reach the function directly (or past a misconfigured
    route) controls the headers but not the authorizer context.
    """
    event = build_event(None, method="GET", path="/v1/tickets")
    event["headers"] = {
        "x-user-id": USER_A_MEMBER,
        "x-org-id": ORG_A,
        "x-role": "admin",
        "x-local-user-id": USER_A_MEMBER,
        "x-local-org-id": ORG_A,
        "authorization": "Bearer synthetic-unverified-token",
    }
    status, body, _ = _invoke(lambda_handler, event)

    assert status == 401, f"Headers on the Lambda event were trusted: {body}"


@pytest.mark.security
def test_tenant_in_the_claims_decides_the_tenant_in_the_response(lambda_handler) -> None:
    """Switching only the claims switches only the visible tenant."""
    event_a = build_event(
        gateway_claims(USER_A_ADMIN, ORG_A, "admin"), method="GET", path="/v1/tickets"
    )
    event_b = build_event(
        gateway_claims(USER_B_MEMBER, ORG_B, "member"), method="GET", path="/v1/tickets"
    )

    _, body_a, _ = _invoke(lambda_handler, event_a)
    _, body_b, _ = _invoke(lambda_handler, event_b)

    assert {i["ticket_id"] for i in body_a["items"]} == {TICKET_A1}
    assert {i["ticket_id"] for i in body_b["items"]} == {TICKET_B1}


# ---------------------------------------------------------------------------
# Event translation
# ---------------------------------------------------------------------------


def test_post_body_is_translated_and_returns_201(lambda_handler) -> None:
    """A JSON body on the Lambda event reaches the Pydantic model."""
    event = build_event(
        gateway_claims(USER_A_MEMBER, ORG_A, "member"), method="POST", path="/v1/tickets"
    )
    event["headers"] = {"content-type": "application/json"}
    event["body"] = json.dumps(
        {"title": "Via Lambda", "description": "Synthetic body through Mangum"}
    )

    status, body, _ = _invoke(lambda_handler, event)

    assert status == 201, body
    assert body["title"] == "Via Lambda"
    assert body["organization_id"] == ORG_A
    assert body["created_by"] == USER_A_MEMBER


def test_query_string_parameters_are_translated(lambda_handler) -> None:
    """``limit``/``cursor`` must survive the event translation."""
    event = build_event(
        gateway_claims(USER_A_ADMIN, ORG_A, "admin"), method="GET", path="/v1/tickets"
    )
    event["rawQueryString"] = "limit=1"
    event["queryStringParameters"] = {"limit": "1"}

    status, body, _ = _invoke(lambda_handler, event)
    assert status == 200, body
    assert len(body["items"]) <= 1


def test_out_of_range_limit_is_rejected_through_lambda(lambda_handler) -> None:
    """Guards finding F-009 at the Lambda boundary."""
    event = build_event(
        gateway_claims(USER_A_ADMIN, ORG_A, "admin"), method="GET", path="/v1/tickets"
    )
    event["rawQueryString"] = "limit=100000"
    event["queryStringParameters"] = {"limit": "100000"}

    status, body, _ = _invoke(lambda_handler, event)
    assert status == 422, body


@pytest.mark.security
def test_security_headers_are_present_on_the_lambda_response(lambda_handler) -> None:
    """Guards finding F-014: the headers survive the ASGI-to-Lambda mapping.

    Worth asserting separately -- a middleware that sets headers correctly in
    ASGI is useless if they are dropped in the response mapping.
    """
    event = build_event(
        gateway_claims(USER_A_MEMBER, ORG_A, "member"), method="GET", path="/v1/tickets"
    )
    _, _, headers = _invoke(lambda_handler, event)

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("cache-control") == "no-store"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-request-id")


def test_health_route_works_without_an_authorizer(lambda_handler) -> None:
    """The public liveness route must not depend on the authorizer context."""
    event = build_event(None, method="GET", path="/v1/health")
    status, body, _ = _invoke(lambda_handler, event)

    assert status == 200, body
    assert body["status"] == "ok"
