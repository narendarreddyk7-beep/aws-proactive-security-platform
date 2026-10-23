"""Unit tests for the Security Hub triage Lambda handler.

Every event here is synthetic. No AWS calls are made: the DynamoDB and SNS
clients are replaced with fakes, which is what lets these tests assert
behaviour that is otherwise only observable in a deployed account -- that a
duplicate is suppressed, that a MEDIUM finding is logged but not notified, and
that a malformed event never raises.

The handler's single most important property is that it NEVER raises.
EventBridge retries a failed invocation and then dead-letters it, so one
malformed finding must not stall triage for every other finding in the batch.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit


class FakeTable:
    """Minimal DynamoDB table double implementing the conditional write."""

    def __init__(self, *, fail_with: Exception | None = None) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.put_calls: list[dict[str, Any]] = []
        self._fail_with = fail_with

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        """Honour `attribute_not_exists(fingerprint)` like DynamoDB does."""
        if self._fail_with is not None:
            raise self._fail_with

        self.put_calls.append(kwargs)
        item = kwargs["Item"]
        key = item["fingerprint"]

        if "attribute_not_exists" in kwargs.get("ConditionExpression", "") and key in self.items:
            raise ConditionalCheckFailedException("The conditional request failed")

        self.items[key] = item
        return {}


class ConditionalCheckFailedException(Exception):
    """Named to match the botocore exception the handler detects by name."""


class FakeSns:
    """SNS client double."""

    def __init__(self, *, fail: bool = False) -> None:
        self.published: list[dict[str, Any]] = []
        self._fail = fail

    def publish(self, **kwargs: Any) -> dict[str, Any]:
        """Record the publish, or raise when configured to fail."""
        if self._fail:
            raise RuntimeError("SNS unavailable")
        self.published.append(kwargs)
        return {"MessageId": "synthetic"}


@pytest.fixture
def handler_module(monkeypatch: pytest.MonkeyPatch):
    """Import the handler with a clean, fully-configured environment.

    Re-imported per test because the module reads its configuration into
    module-level constants at import time, exactly as it does on a Lambda cold
    start.
    """
    monkeypatch.setenv("DEDUP_TABLE_NAME", "synthetic-dedup")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:000000000000:synthetic")
    monkeypatch.setenv("NOTIFY_SEVERITIES", "critical,high")
    monkeypatch.setenv("DEDUP_TTL_HOURS", "24")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("LOG_LEVEL", "INFO")

    import handler

    module = importlib.reload(handler)

    table = FakeTable()
    sns = FakeSns()
    monkeypatch.setattr(module, "_dedup_table", lambda: table)
    monkeypatch.setattr(module, "_sns", lambda: sns)
    module.test_table = table  # type: ignore[attr-defined]
    module.test_sns = sns  # type: ignore[attr-defined]
    return module


@pytest.fixture
def asff_findings(sample_data_dir: Path) -> list[dict[str, Any]]:
    """The synthetic ASFF findings committed under sample-data/."""
    payload = json.loads((sample_data_dir / "securityhub-findings.json").read_text())
    return payload["findings"]


def eventbridge_event(*findings: dict[str, Any]) -> dict[str, Any]:
    """Wrap findings in the EventBridge envelope Security Hub produces."""
    return {
        "version": "0",
        "id": "synthetic-event-id",
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "account": "000000000000",
        "region": "us-east-1",
        "detail": {"findings": list(findings)},
    }


# ---------------------------------------------------------------------------
# Event extraction
# ---------------------------------------------------------------------------


def test_extracts_findings_from_the_eventbridge_envelope(handler_module, asff_findings) -> None:
    """The shape the rule actually delivers."""
    event = eventbridge_event(*asff_findings)
    assert len(handler_module.extract_findings(event)) == len(asff_findings)


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda f: {"detail": {"findings": [f]}}, id="eventbridge"),
        pytest.param(lambda f: {"findings": [f]}, id="bare-findings-key"),
        pytest.param(lambda f: {"Findings": [f]}, id="api-style-key"),
        pytest.param(lambda f: [f], id="bare-list"),
        pytest.param(lambda f: f, id="single-finding"),
        pytest.param(lambda f: {"detail": f}, id="detail-is-the-finding"),
    ],
)
def test_extraction_is_liberal_about_the_envelope(handler_module, asff_findings, build) -> None:
    """Accepting several shapes removes a class of test/prod mismatch."""
    assert len(handler_module.extract_findings(build(asff_findings[0]))) == 1


@pytest.mark.parametrize(
    "event",
    [{}, {"detail": {}}, {"detail": {"findings": []}}, [], None, "string", 42],
)
def test_extraction_returns_empty_for_junk(handler_module, event) -> None:
    """Junk must produce an empty list, not an exception."""
    assert handler_module.extract_findings(event) == []


# ---------------------------------------------------------------------------
# Triage behaviour
# ---------------------------------------------------------------------------


def test_high_severity_finding_is_notified(handler_module, asff_findings) -> None:
    """The headline path: a HIGH IAM finding pages someone."""
    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0]))

    assert result["processed"] == 1
    assert result["errors"] == 0
    assert result["notified"] == 1
    assert len(handler_module.test_sns.published) == 1

    published = handler_module.test_sns.published[0]
    assert "administrative privileges" in published["Subject"]
    assert "arn:aws:iam::000000000000:policy/synthetic-overbroad-policy" in published["Message"]
    assert "Runbook" in published["Message"]


def test_medium_severity_finding_is_logged_but_not_notified(handler_module, asff_findings) -> None:
    """Everything is scored and logged; only CRITICAL and HIGH wake anyone.

    Notifying on MEDIUM trains the on-call to ignore the topic, which is a
    worse outcome than not alerting at all.
    """
    result = handler_module.lambda_handler(eventbridge_event(asff_findings[1]))

    assert result["processed"] == 1
    assert result["notified"] == 0
    assert handler_module.test_sns.published == []


def test_resolved_finding_is_not_notified(handler_module, asff_findings) -> None:
    """An ARCHIVED/RESOLVED finding is not outstanding work."""
    result = handler_module.lambda_handler(eventbridge_event(asff_findings[4]))
    assert result["processed"] == 1
    assert result["notified"] == 0


def test_notification_payload_carries_risk_and_owner(handler_module, asff_findings) -> None:
    """The responder needs score and owner before they open the console."""
    handler_module.lambda_handler(eventbridge_event(asff_findings[3]))
    message = handler_module.test_sns.published[0]["Message"]

    assert "Risk score" in message
    assert "Owner" in message
    assert "cloud-security-engineering" in message


def test_notification_does_not_carry_the_full_finding_body(handler_module, asff_findings) -> None:
    """The message names the resource; it does not dump the ASFF document."""
    handler_module.lambda_handler(eventbridge_event(asff_findings[0]))
    message = handler_module.test_sns.published[0]["Message"]

    assert "ProductArn" not in message
    assert "SchemaVersion" not in message
    assert len(message) < 1500


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_repeated_finding_is_notified_only_once(handler_module, asff_findings) -> None:
    """Security Hub re-imports findings on every evaluation cycle.

    Without deduplication one unremediated misconfiguration pages the on-call
    twice a day forever, until they mute the topic -- at which point the
    alerting looks like it works and does not.
    """
    event = eventbridge_event(asff_findings[0])

    first = handler_module.lambda_handler(event)
    second = handler_module.lambda_handler(event)

    assert first["notified"] == 1
    assert first["duplicates"] == 0
    assert second["notified"] == 0
    assert second["duplicates"] == 1
    assert len(handler_module.test_sns.published) == 1


def test_duplicate_detection_records_a_ttl(handler_module, asff_findings) -> None:
    """The dedup record must expire, or a recurrence is never re-reported."""
    handler_module.lambda_handler(eventbridge_event(asff_findings[0]))

    item = handler_module.test_table.put_calls[0]["Item"]
    assert "expires_at" in item
    assert isinstance(item["expires_at"], int)
    assert item["fingerprint"]


def test_dedup_uses_a_conditional_write(handler_module, asff_findings) -> None:
    """Check-and-record must be atomic.

    Two concurrent invocations for the same finding must not both decide they
    are first and both notify.
    """
    handler_module.lambda_handler(eventbridge_event(asff_findings[0]))
    assert "attribute_not_exists" in handler_module.test_table.put_calls[0]["ConditionExpression"]


def test_dedup_failure_fails_open(handler_module, asff_findings, monkeypatch) -> None:
    """If the dedup table is unavailable, notify anyway.

    A duplicate email is a far better failure than a missed critical finding,
    so this control is deliberately fail-open.
    """
    monkeypatch.setattr(
        handler_module, "_dedup_table", lambda: FakeTable(fail_with=RuntimeError("table gone"))
    )

    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0]))

    assert result["errors"] == 0
    assert result["notified"] == 1


def test_dedup_disabled_when_no_table_configured(
    handler_module, asff_findings, monkeypatch
) -> None:
    """With no table the pipeline still works, just without suppression."""
    monkeypatch.setattr(handler_module, "_dedup_table", lambda: None)
    assert handler_module.is_duplicate("any-fingerprint") is False


def test_different_findings_are_not_deduplicated(handler_module, asff_findings) -> None:
    """Suppression must not be so eager that it hides a second problem."""
    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0], asff_findings[3]))
    assert result["processed"] == 2
    assert result["duplicates"] == 0
    assert result["notified"] == 2


# ---------------------------------------------------------------------------
# Failure handling -- the handler must never raise
# ---------------------------------------------------------------------------


def test_malformed_finding_is_counted_not_raised(handler_module, asff_findings) -> None:
    """The deliberately-malformed fixture must be survivable."""
    result = handler_module.lambda_handler(eventbridge_event(asff_findings[2]))
    assert result["processed"] == 1
    assert result["errors"] == 0


def test_one_bad_finding_does_not_stop_the_batch(handler_module, asff_findings) -> None:
    """Raising would make EventBridge retry and dead-letter the whole batch."""
    event = eventbridge_event(asff_findings[0], "not-a-dict", asff_findings[3])
    # A non-dict is filtered out during extraction, so both real findings run.
    result = handler_module.lambda_handler(event)

    assert result["processed"] == 2
    assert result["notified"] == 2


def test_finding_that_raises_during_triage_is_counted(
    handler_module, asff_findings, monkeypatch
) -> None:
    """An unexpected exception becomes an error count, never a raise."""
    calls = {"n": 0}
    original = handler_module.triage_finding

    def flaky(raw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("synthetic triage failure")
        return original(raw)

    monkeypatch.setattr(handler_module, "triage_finding", flaky)

    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0], asff_findings[3]))

    assert result["errors"] == 1
    assert result["processed"] == 1


def test_empty_event_is_reported_as_an_error_not_raised(handler_module) -> None:
    """An event with no findings is a malformed event worth counting."""
    result = handler_module.lambda_handler({})
    assert result["processed"] == 0
    assert result["errors"] == 1


def test_sns_failure_does_not_stall_triage(handler_module, asff_findings, monkeypatch) -> None:
    """A failed publish must still leave the finding logged and scored."""
    monkeypatch.setattr(handler_module, "_sns", lambda: FakeSns(fail=True))

    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0]))

    assert result["errors"] == 0
    assert result["processed"] == 1
    assert result["notified"] == 0


def test_no_sns_topic_configured_is_handled(handler_module, asff_findings, monkeypatch) -> None:
    """The pipeline is useful (and testable) without a topic."""
    monkeypatch.setattr(handler_module, "_sns", lambda: None)

    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0]))

    assert result["processed"] == 1
    assert result["notified"] == 0


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_every_log_line_is_single_line_json(handler_module, asff_findings, capsys) -> None:
    """One JSON object per line, so CloudWatch Insights can query fields."""
    handler_module.lambda_handler(eventbridge_event(*asff_findings))
    output = capsys.readouterr().out

    lines = [line for line in output.splitlines() if line.strip()]
    assert lines
    for line in lines:
        payload = json.loads(line)
        assert payload["component"] == "security-hub-triage"
        assert "event_type" in payload
        assert "outcome" in payload


def test_logs_carry_the_fields_the_metric_filters_need(
    handler_module, asff_findings, capsys
) -> None:
    """The triage event is what a dashboard and an alarm key off."""
    handler_module.lambda_handler(eventbridge_event(asff_findings[0]))
    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]

    triaged = [p for p in payloads if p["event_type"] == "security_hub_finding_triaged"]
    assert triaged
    for key in ("finding_id", "resource_id", "priority", "risk_score", "owner", "duplicate"):
        assert key in triaged[0], f"{key} missing from the triage log event"


def test_logs_do_not_contain_the_finding_description(handler_module, asff_findings, capsys) -> None:
    """Only identifiers and classification are logged, never the body.

    ASFF descriptions and ProductFields can carry configuration values; the
    log is a second data store with its own retention and readership.
    """
    handler_module.lambda_handler(eventbridge_event(asff_findings[0]))
    output = capsys.readouterr().out

    assert "A customer managed IAM policy grants full administrative" not in output
    assert "aws/securehub/annotation" not in output
    assert "ProductArn" not in output


def test_batch_summary_is_logged(handler_module, asff_findings, capsys) -> None:
    """One summary line per invocation makes throughput observable."""
    handler_module.lambda_handler(eventbridge_event(*asff_findings))
    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]

    summaries = [p for p in payloads if p["event_type"] == "triage_batch_complete"]
    assert len(summaries) == 1
    assert summaries[0]["processed"] == len(asff_findings)


def test_malformed_event_is_logged_as_an_error(handler_module, capsys) -> None:
    """A malformed event must be visible, not silently dropped."""
    handler_module.lambda_handler({})
    payloads = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]

    assert any(p["event_type"] == "malformed_event" for p in payloads)


# ---------------------------------------------------------------------------
# Shared risk model
# ---------------------------------------------------------------------------


def test_handler_uses_the_same_risk_model_as_the_cli(handler_module, asff_findings) -> None:
    """The Lambda and the CLI must score the same finding identically.

    The build copies `finding_triage.py` into the deployment package rather
    than reimplementing the model, precisely so these two cannot drift into
    disagreeing about a priority.
    """
    import finding_triage as triage

    result = handler_module.lambda_handler(eventbridge_event(asff_findings[0]))
    lambda_result = result["results"][0]

    config = triage.TriageConfig.load()
    record = triage.normalize_asff(asff_findings[0])
    finding, _ = triage.normalize_finding(record, config, default_source="securityhub")
    expected = triage.assign_owner(triage.score_finding(finding, config), config)

    assert lambda_result["risk_score"] == expected.risk_score
    assert lambda_result["priority"] == expected.priority
    assert lambda_result["owner"] == expected.owner
    assert lambda_result["fingerprint"] == expected.fingerprint


def test_notify_severities_is_configurable(monkeypatch, asff_findings) -> None:
    """Turning the notification threshold down must actually work."""
    monkeypatch.setenv("DEDUP_TABLE_NAME", "")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:000000000000:synthetic")
    monkeypatch.setenv("NOTIFY_SEVERITIES", "critical,high,medium")
    monkeypatch.setenv("ENVIRONMENT", "test")

    import handler

    module = importlib.reload(handler)
    sns = FakeSns()
    monkeypatch.setattr(module, "_sns", lambda: sns)

    # asff_findings[1] is MEDIUM; it is suppressed by default and notified here.
    result = module.lambda_handler(eventbridge_event(asff_findings[1]))
    assert result["notified"] == 1
