"""AWS integration tests — skipped unless real infrastructure is available.

WHY THESE EXIST AS SKIPPED TESTS
--------------------------------
Three security behaviours **cannot** be verified without AWS, and pretending
otherwise would be the most dishonest thing this repository could do:

1. **Expired-token rejection.** API Gateway's JWT authorizer validates ``exp``
   and never invokes Lambda. There is no local equivalent; the locally-testable
   half of the contract is asserted in
   ``tests/security/test_authentication.py``.
2. **Signature and issuer validation.** Performed by the authorizer against
   the Cognito JWKS endpoint.
3. **IAM least-privilege enforcement.** That the execution role genuinely
   cannot read another table, or call ``dynamodb:Scan``, is only observable
   against real IAM.

Rather than leave those as prose caveats, they are written as real tests that
skip with an explicit reason. The suite therefore *reports* the gap on every
run instead of hiding it, and the tests are ready to run the moment someone
deploys.

TO RUN THEM
-----------
After ``terraform apply`` (see ``docs/AWS_DEPLOYMENT.md``)::

    export SUPPORT_API_BASE_URL="https://<api-id>.execute-api.<region>.amazonaws.com"
    export SUPPORT_API_ACCESS_TOKEN="<a Cognito access token>"
    export SUPPORT_API_EXPIRED_TOKEN="<a token whose exp has passed>"
    export SUPPORT_API_TABLE_NAME="support-platform-dev"
    pytest tests/integration/test_aws_gateway_contract.py -m aws -v

Never paste a token into a file or a shell history you keep. Export it in a
subshell and let it die with the shell.
"""

from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.aws, pytest.mark.security]

BASE_URL = os.environ.get("SUPPORT_API_BASE_URL")
ACCESS_TOKEN = os.environ.get("SUPPORT_API_ACCESS_TOKEN")
EXPIRED_TOKEN = os.environ.get("SUPPORT_API_EXPIRED_TOKEN")
TABLE_NAME = os.environ.get("SUPPORT_API_TABLE_NAME")

requires_api = pytest.mark.skipif(
    not BASE_URL,
    reason="SUPPORT_API_BASE_URL is not set: no deployed API Gateway stage to test against.",
)
requires_token = pytest.mark.skipif(
    not (BASE_URL and ACCESS_TOKEN),
    reason="SUPPORT_API_BASE_URL and SUPPORT_API_ACCESS_TOKEN are required.",
)
requires_expired_token = pytest.mark.skipif(
    not (BASE_URL and EXPIRED_TOKEN),
    reason="SUPPORT_API_EXPIRED_TOKEN is required to test gateway expiry enforcement.",
)
requires_table = pytest.mark.skipif(
    not TABLE_NAME,
    reason="SUPPORT_API_TABLE_NAME is required to test IAM least privilege.",
)


def _client():
    """An HTTP client bound to the deployed stage."""
    import httpx

    return httpx.Client(base_url=BASE_URL or "", timeout=15.0)


# ---------------------------------------------------------------------------
# Authorizer behaviour (cannot be reproduced locally)
# ---------------------------------------------------------------------------


@requires_api
def test_protected_route_rejects_a_request_with_no_token() -> None:
    """API Gateway must reject before Lambda is ever invoked."""
    with _client() as client:
        response = client.get("/v1/tickets")
    assert response.status_code == 401, response.text


@requires_expired_token
def test_protected_route_rejects_an_expired_token() -> None:
    """The authoritative expiry test: only the gateway can perform it."""
    with _client() as client:
        response = client.get("/v1/tickets", headers={"Authorization": f"Bearer {EXPIRED_TOKEN}"})
    assert response.status_code == 401, response.text


@requires_api
@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        "Bearer",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.",  # alg=none
        "a.b.c",
    ],
)
def test_protected_route_rejects_malformed_and_unsigned_tokens(token: str) -> None:
    """Signature validation, including the classic ``alg=none`` attempt."""
    with _client() as client:
        response = client.get("/v1/tickets", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401, response.text


@requires_api
def test_health_route_is_public_on_the_deployed_stage() -> None:
    """The health route must be configured without the authorizer."""
    with _client() as client:
        response = client.get("/v1/health")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "ok"


@requires_token
def test_valid_token_reaches_the_application() -> None:
    """The positive control: a real token works end to end."""
    with _client() as client:
        response = client.get("/v1/tickets", headers={"Authorization": f"Bearer {ACCESS_TOKEN}"})
    assert response.status_code == 200, response.text
    assert "items" in response.json()


@requires_token
def test_security_headers_are_present_on_the_deployed_stage() -> None:
    """Confirms the headers survive API Gateway's response mapping."""
    with _client() as client:
        response = client.get("/v1/health")

    headers = {key.lower(): value for key, value in response.headers.items()}
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("cache-control") == "no-store"


# ---------------------------------------------------------------------------
# IAM least privilege (only observable against real IAM)
# ---------------------------------------------------------------------------


@requires_table
def test_execution_role_policy_grants_no_scan_and_no_wildcards() -> None:
    """Inspect the deployed role's inline policy with the project's own checker.

    This reuses ``security-automation/iam_policy_checker.py`` against the live
    policy document, so the same rules that gate CI also gate the deployed
    state. Requires ``iam:GetRole``/``iam:GetRolePolicy`` read access.
    """
    import json
    import subprocess
    import sys
    from pathlib import Path

    import boto3

    role_name = os.environ.get("SUPPORT_API_ROLE_NAME")
    if not role_name:
        pytest.skip("SUPPORT_API_ROLE_NAME is required to inspect the execution role.")

    iam = boto3.client("iam")
    policy_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert policy_names, "The execution role has no inline policy to inspect."

    document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_names[0])["PolicyDocument"]

    checker = Path(__file__).resolve().parents[2] / "security-automation" / "iam_policy_checker.py"
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(checker), "--stdin", "--format", "json"],
        input=json.dumps(document),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"The deployed execution role policy has blocking findings:\n{result.stdout}"
    )


@requires_table
def test_execution_role_cannot_read_another_table() -> None:
    """The negative control for resource scoping.

    Run with the function's own credentials (for example from a one-off
    invocation), not an engineer's. With an administrator session this test is
    meaningless, so it checks for that and skips.
    """
    import boto3
    from botocore.exceptions import ClientError

    sts = boto3.client("sts")
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" not in arn or "support" not in arn.lower():
        pytest.skip(f"Current identity ({arn}) is not the Lambda execution role.")

    dynamodb = boto3.client("dynamodb")
    with pytest.raises(ClientError) as exc_info:
        dynamodb.get_item(
            TableName="a-table-this-role-must-not-reach",
            Key={"PK": {"S": "x"}, "SK": {"S": "y"}},
        )
    assert exc_info.value.response["Error"]["Code"] in (
        "AccessDeniedException",
        "AccessDenied",
    )
