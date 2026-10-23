"""Log formatter and request-context unit tests.

The formatter is the control that stops customer content and credentials
reaching CloudWatch (finding F-007), so it is tested directly rather than only
through the API.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.observability.logging import (
    ALLOWED_LOG_FIELDS,
    MAX_MESSAGE_LENGTH,
    JsonFormatter,
)
from app.observability.request_context import (
    get_request_id,
    new_request_id,
    sanitize_request_id,
    set_request_id,
)

pytestmark = pytest.mark.unit


def _record(
    message: str = "event", level: int = logging.INFO, **extra: object
) -> logging.LogRecord:
    """Build a log record with arbitrary ``extra`` fields attached."""
    record = logging.LogRecord(
        name="app.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def _render(record: logging.LogRecord) -> dict:
    """Format a record and parse the resulting JSON line."""
    line = JsonFormatter().format(record)
    assert "\n" not in line, "A log line must stay on one line"
    return json.loads(line)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def test_envelope_fields_are_always_present() -> None:
    """Every line carries the fields the metric filters and runbooks rely on."""
    set_request_id("req-abcdef123456")
    payload = _render(_record("something happened"))

    assert payload["severity"] == "info"
    assert payload["component"] == "app.test"
    assert payload["request_id"] == "req-abcdef123456"
    assert payload["message"] == "something happened"
    assert payload["timestamp"].endswith("+00:00"), "Timestamps must be UTC and unambiguous"


def test_severity_is_lowercased_for_queryability() -> None:
    """Consistent casing keeps CloudWatch Insights filters simple."""
    assert _render(_record(level=logging.WARNING))["severity"] == "warning"
    assert _render(_record(level=logging.ERROR))["severity"] == "error"


# ---------------------------------------------------------------------------
# F-007: the allow-list
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.regression
def test_non_allow_listed_fields_are_dropped() -> None:
    """Guards finding F-007.

    The original code logged whatever was in ``extra``, and the service layer
    passed whole ticket objects. An allow-list means a new field is invisible
    until someone reviews it -- so forgetting produces a missing dashboard
    field, not customer data in a log stream.
    """
    payload = _render(
        _record(
            event_type="ticket_created",
            ticket={"description": "CUSTOMER-CONTENT-MARKER"},
            authorization="Bearer SECRET-TOKEN-MARKER",
            password="SECRET-PASSWORD-MARKER",
            email="person@example.invalid",
        )
    )

    assert payload["event_type"] == "ticket_created"
    for dropped in ("ticket", "authorization", "password", "email"):
        assert dropped not in payload

    rendered = json.dumps(payload)
    for marker in ("CUSTOMER-CONTENT-MARKER", "SECRET-TOKEN-MARKER", "SECRET-PASSWORD-MARKER"):
        assert marker not in rendered


@pytest.mark.security
def test_rendered_keys_are_always_a_subset_of_the_allow_list() -> None:
    """The invariant stated as an invariant."""
    payload = _render(
        _record(
            event_type="x",
            outcome="denied",
            reason="y",
            principal_id="u",
            organization_id="o",
            resource_id="r",
            anything_else="z",
        )
    )
    assert set(payload) <= ALLOWED_LOG_FIELDS


@pytest.mark.security
def test_allow_list_contains_no_content_bearing_field_names() -> None:
    """A guard on the guard: review the allow-list itself.

    If someone adds ``description`` or ``title`` to the allow-list, this test
    fails and the review conversation happens before the merge, not after an
    incident.
    """
    forbidden = {
        "description",
        "title",
        "body",
        "payload",
        "ticket",
        "authorization",
        "token",
        "password",
        "secret",
        "email",
        "claims",
        "headers",
    }
    overlap = ALLOWED_LOG_FIELDS & forbidden
    assert not overlap, f"Content-bearing fields are allow-listed: {overlap}"


# ---------------------------------------------------------------------------
# Message hardening
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_long_messages_are_truncated() -> None:
    """Bounds the damage if someone ever interpolates content into a message."""
    payload = _render(_record("A" * (MAX_MESSAGE_LENGTH * 3)))
    assert len(payload["message"]) <= MAX_MESSAGE_LENGTH + len("...[truncated]")
    assert payload["message"].endswith("...[truncated]")


@pytest.mark.security
def test_newlines_in_a_message_cannot_forge_a_log_record() -> None:
    """Log injection: one record in must be one record out."""
    payload = _render(_record('done"}\n{"severity":"info","message":"forged'))
    assert "\n" not in payload["message"]
    assert payload["message"].count("forged") == 1  # present as text, not as a record


def test_broken_format_string_does_not_kill_logging() -> None:
    """A logging bug must never take down a request."""
    record = logging.LogRecord(
        name="app.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="missing arg %s %s",
        args=("only-one",),
        exc_info=None,
    )
    payload = _render(record)
    assert payload["message"]


def test_exception_detail_is_rendered_into_the_log() -> None:
    """Diagnostics belong in the log (and nowhere near the response body)."""
    try:
        raise RuntimeError("SYNTHETIC-FAILURE-DETAIL")
    except RuntimeError:
        import sys

        record = logging.LogRecord(
            name="app.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=sys.exc_info(),
        )

    payload = _render(record)
    assert "SYNTHETIC-FAILURE-DETAIL" in payload["exception"]
    assert "Traceback" in payload["exception"]


def test_non_serialisable_values_do_not_break_the_formatter() -> None:
    """An un-JSON-able value is stringified rather than raising."""

    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    payload = _render(_record(resource_id=Opaque()))
    assert payload["resource_id"] == "<opaque>"


# ---------------------------------------------------------------------------
# Request id (finding F-007)
# ---------------------------------------------------------------------------


def test_generated_request_ids_are_unique_hex() -> None:
    """Correlation ids must not collide."""
    ids = {new_request_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(len(value) == 32 for value in ids)


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param('abc"}\n{"forged":1', id="log-injection"),
        pytest.param("short", id="too-short"),
        pytest.param("A" * 65, id="too-long"),
        pytest.param("has spaces", id="spaces"),
        pytest.param("semi;colon", id="punctuation"),
        pytest.param("tab\there", id="tab"),
        pytest.param("", id="empty"),
        pytest.param(None, id="absent"),
        pytest.param("../../etc/passwd", id="traversal"),
    ],
)
def test_unsafe_client_request_ids_are_replaced(candidate: str | None) -> None:
    """Guards finding F-007.

    A client-supplied correlation id is attacker-controlled input. Anything
    outside a narrow allow-list is replaced with a generated value.
    """
    result = sanitize_request_id(candidate)
    assert result != candidate
    assert len(result) == 32


def test_well_formed_client_request_id_is_honoured() -> None:
    """Honouring a safe client id is genuinely useful for joint debugging."""
    assert sanitize_request_id("client-trace-0001") == "client-trace-0001"
    assert sanitize_request_id("A1b2C3d4.e5-f6_7") == "A1b2C3d4.e5-f6_7"


def test_request_id_defaults_to_a_placeholder_outside_a_request() -> None:
    """Logging from a startup path must not crash for want of a request id."""
    set_request_id("-")
    assert get_request_id() == "-"
