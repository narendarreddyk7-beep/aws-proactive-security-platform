"""Authentication boundary tests.

TRUST MODEL UNDER TEST
----------------------
In AWS, API Gateway's JWT authorizer validates the Cognito token's signature,
issuer (``iss``), audience/client (``aud``/``client_id``) and expiry *before*
Lambda is invoked, and publishes the verified claims at
``event.requestContext.authorizer.jwt.claims``.

Therefore the application's job is **not** to validate tokens. Its job is to
refuse to accept identity from anywhere other than that verified location.
These tests assert exactly that.

What can and cannot be tested locally is spelled out in
``docs/TESTING.md`` §"Gateway contract vs AWS integration".
"""

from __future__ import annotations

import pytest

from tests.conftest import ApiHarness, AppFactory
from tests.fixtures.gateway import build_event, gateway_claims
from tests.fixtures.synthetic_data import ORG_A, ORG_B, USER_A_MEMBER

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Unauthenticated access
# ---------------------------------------------------------------------------


def test_health_endpoint_requires_no_authentication(empty_harness: ApiHarness) -> None:
    """The liveness probe is intentionally public so monitors can reach it."""
    response = empty_harness.anonymous().client.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/tickets"),
        ("POST", "/v1/tickets"),
        ("GET", "/v1/tickets/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
        ("PATCH", "/v1/tickets/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"),
    ],
)
def test_every_ticket_endpoint_rejects_missing_authorizer_context(
    empty_harness: ApiHarness, method: str, path: str
) -> None:
    """No authorizer context on the event means no identity, so 401."""
    empty_harness.anonymous()
    response = empty_harness.client.request(method, path, json={})
    assert response.status_code == 401, response.text
    assert response.json()["error"] == "not_authenticated"


def test_request_outside_lambda_is_rejected(empty_harness: ApiHarness) -> None:
    """With no Lambda event in the scope at all there is no trusted identity.

    This is the shape of a request that reached the ASGI app directly -- a
    developer running uvicorn, or an attacker who found a path around the
    gateway. Either way the answer must be 401, never a default identity.
    """
    empty_harness.outside_lambda()
    response = empty_harness.client.get("/v1/tickets")
    assert response.status_code == 401
    assert response.json()["error"] == "not_authenticated"


# ---------------------------------------------------------------------------
# F-001: client-controlled identity must never be trusted
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_identity_headers_are_never_accepted_as_authentication(
    empty_harness: ApiHarness,
) -> None:
    """Guards finding F-001.

    A caller who supplies ``X-User-Id`` / ``X-Org-Id`` / ``X-Role`` headers with
    no verified authorizer context must be rejected. If this ever returns 2xx,
    anyone on the internet can impersonate any user in any tenant.
    """
    empty_harness.outside_lambda()
    response = empty_harness.client.get(
        "/v1/tickets",
        headers={
            "X-User-Id": USER_A_MEMBER,
            "X-Org-Id": ORG_A,
            "X-Role": "admin",
        },
    )
    assert response.status_code == 401, (
        "Client-supplied identity headers were accepted as authentication. "
        f"Got {response.status_code}: {response.text}"
    )


@pytest.mark.regression
@pytest.mark.parametrize(
    "spoof_headers",
    [
        {"X-Org-Id": ORG_B},
        {"X-Role": "admin"},
        {"X-User-Id": "attacker", "X-Org-Id": ORG_B, "X-Role": "admin"},
        {"x-org-id": ORG_B},  # header names are case-insensitive
        {"X-Organization-Id": ORG_B},
        {"X-Forwarded-User": "attacker"},
    ],
)
def test_identity_headers_cannot_override_verified_claims(
    harness: ApiHarness, spoof_headers: dict[str, str]
) -> None:
    """Guards finding F-001.

    An authenticated member of org A who also sends spoofed identity headers
    must still be treated as a member of org A.
    """
    response = harness.as_member(ORG_A).client.get("/v1/tickets", headers=spoof_headers)
    assert response.status_code == 200, response.text

    returned_orgs = {item["organization_id"] for item in response.json()["items"]}
    assert returned_orgs <= {ORG_A}, f"Spoofed headers changed the effective tenant: {returned_orgs}"

    # Every store call must have been scoped to the verified tenant.
    for _name, kwargs in harness.tickets.calls:
        assert kwargs.get("organization_id") in (None, ORG_A)


# ---------------------------------------------------------------------------
# Malformed / incomplete verified claims
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="empty-claims"),
        pytest.param({"sub": USER_A_MEMBER}, id="missing-organization"),
        pytest.param({"custom:organization_id": ORG_A}, id="missing-subject"),
        pytest.param({"sub": "", "custom:organization_id": ORG_A}, id="empty-subject"),
        pytest.param({"sub": USER_A_MEMBER, "custom:organization_id": ""}, id="empty-organization"),
        pytest.param(
            {"sub": "   ", "custom:organization_id": "   "},
            id="whitespace-only-claims",
        ),
    ],
)
def test_incomplete_claims_are_rejected(empty_harness: ApiHarness, claims: dict) -> None:
    """A verified token that lacks the claims we need is not usable identity."""
    empty_harness.injector.with_claims(claims)
    response = empty_harness.client.get("/v1/tickets")
    assert response.status_code == 401, response.text
    assert response.json()["error"] == "not_authenticated"


def test_non_dict_authorizer_context_is_rejected(empty_harness: ApiHarness) -> None:
    """A malformed event must fail closed rather than raising a 500."""
    event = build_event(None)
    event["requestContext"]["authorizer"] = {"jwt": "not-a-dict"}
    empty_harness.injector.with_event(event)
    response = empty_harness.client.get("/v1/tickets")
    assert response.status_code == 401


def test_authorizer_context_from_a_different_authorizer_type_is_rejected(
    empty_harness: ApiHarness,
) -> None:
    """A Lambda-authorizer-shaped context must not be mistaken for JWT claims.

    If the API were ever reconfigured to use a REQUEST authorizer, its context
    lives under ``authorizer.lambda``. Reading identity from there would skip
    JWT validation entirely, so it must not be accepted by this application.
    """
    event = build_event(None)
    event["requestContext"]["authorizer"] = {
        "lambda": {"organization_id": ORG_B, "sub": "attacker", "role": "admin"}
    }
    empty_harness.injector.with_event(event)
    response = empty_harness.client.get("/v1/tickets")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Expiry: gateway contract test
# ---------------------------------------------------------------------------


def test_expired_token_contract_gateway_strips_authorizer_context(
    empty_harness: ApiHarness,
) -> None:
    """Contract test for expired-token handling.

    API Gateway rejects an expired token with 401 and **never invokes Lambda**.
    This cannot be reproduced locally, so the locally-testable half of the
    contract is asserted instead: when the authorizer context is absent -- the
    only state Lambda can observe for a rejected token -- the application
    returns 401 and performs no data access.

    The AWS half is covered by ``tests/integration/test_aws_gateway_contract.py``,
    which is skipped unless real infrastructure is available.
    """
    empty_harness.anonymous()
    response = empty_harness.client.get("/v1/tickets")

    assert response.status_code == 401
    assert empty_harness.tickets.operations() == [], (
        "The application touched the data store for an unauthenticated request"
    )


def test_application_does_not_second_guess_expiry_claims(empty_harness: ApiHarness) -> None:
    """The application must not implement its own expiry logic.

    Re-validating ``exp`` in application code would be duplicated, weaker
    validation that could disagree with the gateway. If the authorizer
    published claims, the token was valid at the gateway; a stale ``exp`` in a
    verified claim set is a gateway/clock problem, not an application decision.
    This test documents that the app treats verified claims as verified.
    """
    claims = gateway_claims(USER_A_MEMBER, ORG_A, "member", exp="1")  # 1970, long expired
    empty_harness.injector.with_claims(claims)
    response = empty_harness.client.get("/v1/tickets")
    assert response.status_code == 200, (
        "Claims published by the authorizer should be trusted; the gateway owns expiry."
    )


# ---------------------------------------------------------------------------
# F-012: the local-development identity adapter must fail closed
# ---------------------------------------------------------------------------


@pytest.mark.regression
def test_local_identity_adapter_is_refused_outside_local_environment(
    app_factory: AppFactory,
) -> None:
    """Guards finding F-012.

    ``IDENTITY_SOURCE=local_test`` trusts request headers. It must be
    impossible to enable in any environment other than ``local``: a
    misconfigured deployment would otherwise be a complete authentication
    bypass. Configuration load must raise, so the Lambda fails to start
    rather than starting insecurely.
    """
    with pytest.raises(Exception) as exc_info:
        app_factory(
            env={"APP_IDENTITY_SOURCE": "local_test", "APP_ENVIRONMENT": "production"}
        )
    assert "local" in str(exc_info.value).lower()


@pytest.mark.regression
def test_gateway_is_the_default_identity_source(app_factory: AppFactory) -> None:
    """Guards finding F-012.

    With no identity configuration at all the application must use the
    gateway source -- i.e. secure by default, not header-trusting by default.
    """
    harness = app_factory(env={"APP_IDENTITY_SOURCE": "", "APP_ENVIRONMENT": ""})
    harness.outside_lambda()
    response = harness.client.get(
        "/v1/tickets", headers={"X-User-Id": USER_A_MEMBER, "X-Org-Id": ORG_A}
    )
    assert response.status_code == 401


def test_local_identity_adapter_works_only_when_explicitly_enabled_locally(
    app_factory: AppFactory, seeded_tickets: list
) -> None:
    """The documented local-development path must actually work.

    This is the adapter ``docs/DEMO.md`` uses to exercise the API with curl and
    no Cognito user pool. It is only reachable with
    ``APP_ENVIRONMENT=local`` *and* ``APP_IDENTITY_SOURCE=local_test``.
    """
    harness = app_factory(
        tickets=seeded_tickets,
        env={"APP_IDENTITY_SOURCE": "local_test", "APP_ENVIRONMENT": "local"},
    )
    harness.outside_lambda()

    response = harness.client.get(
        "/v1/tickets",
        headers={"X-Local-User-Id": USER_A_MEMBER, "X-Local-Org-Id": ORG_A},
    )
    assert response.status_code == 200, response.text
    assert all(item["organization_id"] == ORG_A for item in response.json()["items"])

    # Even here, a request with no local identity headers is unauthenticated.
    assert harness.client.get("/v1/tickets").status_code == 401
