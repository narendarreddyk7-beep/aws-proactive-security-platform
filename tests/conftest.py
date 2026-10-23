"""Shared pytest fixtures.

Design goals:

1. **No AWS, no credentials.** Every fixture here runs offline. The DynamoDB
   repository tests that do need AWS semantics use ``moto`` and live in
   ``tests/integration/``.
2. **Fresh settings per app.** ``app.config.get_settings`` is ``lru_cache``-d,
   so any test that changes configuration must clear the cache *before* the
   application is built. ``app_factory`` does that for you.
3. **Identity only via the gateway double.** The HTTP harness wraps the ASGI
   app in ``GatewayEventInjector`` so requests arrive with (or without) a
   verified authorizer context, exactly as they would in AWS.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.fixtures.fake_store import InMemoryMembershipStore, InMemoryTicketStore
from tests.fixtures.gateway import GatewayEventInjector
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    TICKET_A1,
    TICKET_A2,
    TICKET_B1,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    USER_B_MEMBER,
    make_ticket,
)

# Environment the whole suite runs under. Deliberately *not* "local" for the
# identity source: tests exercise the production code path.
BASE_ENV: dict[str, str] = {
    "APP_ENVIRONMENT": "test",
    "APP_IDENTITY_SOURCE": "gateway",
    "APP_DEBUG": "false",
    "APP_TABLE_NAME": "support-platform-test",
    "APP_AWS_REGION": "us-east-1",
    "APP_LOG_LEVEL": "INFO",
    "APP_CORS_ALLOW_ORIGINS": "https://app.example.invalid",
    # Guard rails: if anything ever tries to reach real AWS, fail loudly
    # instead of picking up an engineer's ambient credentials.
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105 - synthetic moto placeholder
    "AWS_SECURITY_TOKEN": "testing",  # noqa: S105
    "AWS_SESSION_TOKEN": "testing",  # noqa: S105
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_EC2_METADATA_DISABLED": "true",
}


@pytest.fixture(autouse=True)
def _base_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Apply a deterministic, credential-free environment to every test."""
    for key, value in BASE_ENV.items():
        monkeypatch.setenv(key, value)
    # Make sure a developer's real profile can never leak into a test run.
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    yield


def _clear_settings_cache() -> None:
    """Drop the cached ``Settings`` so the next build re-reads the environment."""
    from app.config import get_settings

    get_settings.cache_clear()


@dataclass
class ApiHarness:
    """An HTTP client bound to a freshly built app with in-memory stores."""

    client: TestClient
    injector: GatewayEventInjector
    tickets: InMemoryTicketStore
    memberships: InMemoryMembershipStore
    app: Any = field(repr=False, default=None)

    # -- identity helpers ----------------------------------------------------

    def as_admin(self, organization_id: str = ORG_A, user_id: str = USER_A_ADMIN) -> ApiHarness:
        """Authenticate as an organization administrator."""
        self.injector.authenticate_as(user_id, organization_id, "admin")
        return self

    def as_member(self, organization_id: str = ORG_A, user_id: str = USER_A_MEMBER) -> ApiHarness:
        """Authenticate as an organization member."""
        self.injector.authenticate_as(user_id, organization_id, "member")
        return self

    def as_other_member(self, organization_id: str = ORG_A) -> ApiHarness:
        """Authenticate as a *different* member of the same organization."""
        self.injector.authenticate_as(USER_A_MEMBER_2, organization_id, "member")
        return self

    def as_other_tenant(self) -> ApiHarness:
        """Authenticate as a member of the other organization."""
        self.injector.authenticate_as(USER_B_MEMBER, ORG_B, "member")
        return self

    def anonymous(self) -> ApiHarness:
        """Send requests with no authorizer context."""
        self.injector.anonymous()
        return self

    def outside_lambda(self) -> ApiHarness:
        """Send requests with no Lambda event in the ASGI scope at all."""
        self.injector.no_aws_event()
        return self


AppFactory = Callable[..., ApiHarness]


@pytest.fixture
def app_factory() -> Iterator[AppFactory]:
    """Return a factory that builds an isolated app + client per call.

    ``env`` lets a test override configuration; the settings cache is cleared
    before and after so no configuration leaks between tests.
    """
    created: list[TestClient] = []

    def _factory(
        *,
        tickets: list[Any] | None = None,
        memberships: list[Any] | None = None,
        env: dict[str, str] | None = None,
    ) -> ApiHarness:
        previous: dict[str, str | None] = {}
        if env:
            for key, value in env.items():
                previous[key] = os.environ.get(key)
                os.environ[key] = value

        _clear_settings_cache()
        try:
            from app.dependencies import (
                get_membership_store,
                get_ticket_store,
            )
            from app.main import create_app

            ticket_store = InMemoryTicketStore(tickets)
            membership_store = InMemoryMembershipStore(memberships)

            application = create_app()
            application.dependency_overrides[get_ticket_store] = lambda: ticket_store
            application.dependency_overrides[get_membership_store] = lambda: membership_store

            injector = GatewayEventInjector(application)
            client = TestClient(injector, raise_server_exceptions=False)
            created.append(client)
            return ApiHarness(
                client=client,
                injector=injector,
                tickets=ticket_store,
                memberships=membership_store,
                app=application,
            )
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    yield _factory

    for client in created:
        client.close()
    _clear_settings_cache()


@pytest.fixture
def seeded_tickets() -> list[Any]:
    """Two tickets in org A (different owners) and one in org B."""
    return [
        make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, created_by=USER_A_MEMBER),
        make_ticket(
            ticket_id=TICKET_A2,
            organization_id=ORG_A,
            created_by=USER_A_MEMBER_2,
            title="Billing discrepancy",
        ),
        make_ticket(
            ticket_id=TICKET_B1,
            organization_id=ORG_B,
            created_by=USER_B_MEMBER,
            title="Contoso cannot export data",
        ),
    ]


@pytest.fixture
def harness(app_factory: AppFactory, seeded_tickets: list[Any]) -> ApiHarness:
    """Default harness: seeded with cross-tenant data, authenticated as a member."""
    return app_factory(tickets=seeded_tickets).as_member()


@pytest.fixture
def empty_harness(app_factory: AppFactory) -> ApiHarness:
    """Harness with no pre-existing tickets, authenticated as a member."""
    return app_factory().as_member()


# ---------------------------------------------------------------------------
# DynamoDB (moto)
#
# The table definition here mirrors `infrastructure/terraform/dynamodb.tf`.
# If the two ever diverge, `tests/integration/test_dynamodb_repository.py`
# will start failing, which is the point.
# ---------------------------------------------------------------------------


@pytest.fixture
def dynamodb_table() -> Iterator[Any]:
    """Create an in-process DynamoDB table with the production key schema."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        resource = boto3.resource("dynamodb", region_name="us-east-1")
        table = resource.create_table(
            TableName="support-platform-test",
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
        table.wait_until_exists()
        yield table


@pytest.fixture
def recording_table(dynamodb_table: Any) -> Any:
    """The moto table wrapped so tests can assert which API calls were made."""
    from tests.fixtures.recording_table import RecordingTable

    return RecordingTable(dynamodb_table)


@pytest.fixture
def membership_table(dynamodb_table: Any) -> Any:
    """An in-process membership table, separate from the ticket table.

    Memberships live in their own table so the execution role can hold
    ``GetItem`` on them and no write action at all -- see
    ``infrastructure/terraform/policies/lambda-execution.json``. Creating a
    genuinely separate table here (rather than another partition prefix) is
    what lets a test assert that the application never writes to it.

    Depends on ``dynamodb_table`` only to inherit its ``mock_aws`` context.
    """
    import boto3

    resource = boto3.resource("dynamodb", region_name="us-east-1")
    table = resource.create_table(
        TableName="support-platform-test-memberships",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
    )
    table.wait_until_exists()
    return table


@pytest.fixture
def recording_membership_table(membership_table: Any) -> Any:
    """The membership table wrapped so tests can assert no write ever happens."""
    from tests.fixtures.recording_table import RecordingTable

    return RecordingTable(membership_table)


# ---------------------------------------------------------------------------
# Log capture
#
# `caplog` is deliberately not used for the data-protection tests: those
# assertions need to see the *rendered* output of the application's own
# JsonFormatter, because redaction happens in the formatter. Capturing the
# formatted line is what proves a secret never reaches CloudWatch.
# ---------------------------------------------------------------------------


class _CapturingHandler(logging.Handler):
    """Collects both the raw records and the formatted output lines."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Store the record and its formatted representation."""
        self.records.append(record)
        try:
            self.lines.append(self.format(record))
        except Exception as exc:  # pragma: no cover - surfaced as a test failure
            self.lines.append(f"<<formatter raised {type(exc).__name__}: {exc}>>")


@dataclass
class LogCapture:
    """Captured log output for one test."""

    handler: _CapturingHandler

    @property
    def records(self) -> list[logging.LogRecord]:
        """Raw log records."""
        return self.handler.records

    @property
    def lines(self) -> list[str]:
        """Formatted log lines, exactly as they would reach CloudWatch."""
        return self.handler.lines

    def text(self) -> str:
        """All formatted output concatenated, for substring assertions."""
        return "\n".join(self.handler.lines)

    def payloads(self) -> list[dict[str, Any]]:
        """Formatted lines parsed back from JSON."""
        parsed: list[dict[str, Any]] = []
        for line in self.handler.lines:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                parsed.append({"_unparseable": line})
        return parsed

    def events(self, event_type: str) -> list[dict[str, Any]]:
        """Parsed payloads whose ``event_type`` matches."""
        return [p for p in self.payloads() if p.get("event_type") == event_type]


@pytest.fixture
def capture_logs() -> Iterator[Callable[[], LogCapture]]:
    """Return a callable that starts capturing root-logger output.

    Call it *after* building the harness, because building the app configures
    logging::

        harness = app_factory().as_member()
        logs = capture_logs()
    """
    installed: list[_CapturingHandler] = []

    def _start() -> LogCapture:
        from app.observability.logging import JsonFormatter

        handler = _CapturingHandler()
        handler.setFormatter(JsonFormatter())
        root = logging.getLogger()
        root.addHandler(handler)
        previous_level = root.level
        root.setLevel(logging.DEBUG)
        handler._previous_root_level = previous_level  # type: ignore[attr-defined]
        installed.append(handler)
        return LogCapture(handler=handler)

    yield _start

    root = logging.getLogger()
    for handler in installed:
        root.removeHandler(handler)
        root.setLevel(getattr(handler, "_previous_root_level", logging.WARNING))
