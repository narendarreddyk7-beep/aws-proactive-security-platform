"""Security Hub finding triage Lambda.

    Security Hub CSPM
           |
      EventBridge  ("Security Hub Findings - Imported")
           |
      THIS FUNCTION  -- normalize, score, assign an owner, deduplicate
           |
    CloudWatch Logs (always)  +  SNS (high severity only)

WHY A LAMBDA AND NOT JUST AN SNS SUBSCRIPTION
---------------------------------------------
Subscribing SNS directly to the EventBridge rule would email the raw ASFF
document, which is several kilobytes of JSON per finding, carries no risk
context of its own, and arrives once per re-evaluation. In practice that means
the inbox gets ignored within a week.

This function does four things that make the difference between an alert and a
page worth reading:

1. **Normalizes and scores** using the same risk model as the CLI tool
   (``security-automation/finding_triage.py``), so a Security Hub finding and a
   Checkov finding are comparable and prioritised on one scale.
2. **Deduplicates** against a DynamoDB table with a TTL. Security Hub
   re-imports a finding on every evaluation cycle; without this, one
   unremediated misconfiguration pages the on-call every twelve hours
   indefinitely until they mute the topic.
3. **Notifies selectively.** Everything is logged and scored; only CRITICAL and
   HIGH notify. Paging on MEDIUM trains people to ignore the channel, which is
   worse than not alerting at all.
4. **Fails safe and never crashes the pipeline.** A malformed event is logged
   and counted, not raised. An exception here would make EventBridge retry and
   then dead-letter, so one bad finding would stall triage for all of them.

DATA HANDLING
-------------
``normalize_asff`` keeps only identifiers, classification and remediation text.
It deliberately drops ``ProductFields`` and the resource ``Details`` blob,
which can carry configuration values and tag contents. Nothing from a finding's
body is written to the log beyond its title and resource id.

COST
----
EventBridge rule: free. This function: a few invocations per finding import.
The dedup table: on-demand, a few hundred bytes per finding, TTL-expired.
Negligible. **Security Hub itself is the chargeable part and is not enabled by
this module** -- see ``infrastructure/terraform/security_hub.tf``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# The deployment package places `finding_triage.py`, `triage_config.json` and
# `schemas/` alongside this handler. See scripts/build_lambda_package.sh.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from finding_triage import (  # noqa: E402  (path setup must precede the import)
    TriageConfig,
    assign_owner,
    normalize_asff,
    normalize_finding,
    score_finding,
)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
DEDUP_TABLE_NAME = os.environ.get("DEDUP_TABLE_NAME", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
DEDUP_TTL_HOURS = int(os.environ.get("DEDUP_TTL_HOURS", "24"))
NOTIFY_SEVERITIES = {
    item.strip().lower()
    for item in os.environ.get("NOTIFY_SEVERITIES", "critical,high").split(",")
    if item.strip()
}
ENVIRONMENT = os.environ.get("ENVIRONMENT", "unknown")


class _StdoutHandler(logging.StreamHandler):
    """A StreamHandler that resolves ``sys.stdout`` at emit time.

    ``logging.StreamHandler(stream=sys.stdout)`` captures the stream object
    when the handler is constructed. In Lambda that is harmless, but it makes
    the output impossible to capture in a test (and silently wrong if anything
    ever replaces ``sys.stdout``). Resolving late costs nothing and keeps the
    handler honest about where "stdout" is.
    """

    def __init__(self) -> None:
        super().__init__()

    @property
    def stream(self) -> Any:  # type: ignore[override]
        """The current standard output stream."""
        return sys.stdout

    @stream.setter
    def stream(self, _value: Any) -> None:
        """Ignore assignment; the stream is always resolved from ``sys``."""


logger = logging.getLogger("security_hub_triage")
if not logger.handlers:
    _handler = _StdoutHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
logger.setLevel(LOG_LEVEL)
# The Lambda runtime's root handler would add its own prefix to every line and
# break single-line-JSON parsing, so this logger does not propagate.
logger.propagate = False

#: Cached across invocations: the config file read and the boto3 client
#: construction are both cold-start costs worth paying once.
_CONFIG: TriageConfig | None = None
_DEDUP_TABLE: Any = None
_SNS_CLIENT: Any = None


def _log(event_type: str, outcome: str, **fields: Any) -> None:
    """Emit one structured JSON log line.

    Same shape as the application's logger so one CloudWatch Insights query
    works across both log groups. Fields are passed explicitly -- there is no
    path by which a finding's body can be logged wholesale.
    """
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "severity": "warning" if outcome in {"denied", "error"} else "info",
        "component": "security-hub-triage",
        "event_type": event_type,
        "outcome": outcome,
        "environment": ENVIRONMENT,
    }
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.info(json.dumps(payload, default=str))


def _config() -> TriageConfig:
    """Return the cached triage configuration."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = TriageConfig.load()
    return _CONFIG


def _dedup_table() -> Any:
    """Return the cached DynamoDB table resource, or ``None`` when disabled."""
    global _DEDUP_TABLE
    if not DEDUP_TABLE_NAME:
        return None
    if _DEDUP_TABLE is None:
        import boto3

        _DEDUP_TABLE = boto3.resource("dynamodb").Table(DEDUP_TABLE_NAME)
    return _DEDUP_TABLE


def _sns() -> Any:
    """Return the cached SNS client, or ``None`` when no topic is configured."""
    global _SNS_CLIENT
    if not SNS_TOPIC_ARN:
        return None
    if _SNS_CLIENT is None:
        import boto3

        _SNS_CLIENT = boto3.client("sns")
    return _SNS_CLIENT


def extract_findings(event: Any) -> list[dict[str, Any]]:
    """Pull the ASFF findings out of whatever envelope arrived.

    EventBridge delivers ``{"detail": {"findings": [...]}}``, but the same
    handler is used in tests with a bare finding or a bare list. Being liberal
    here costs nothing and removes a whole class of "works in test, fails in
    prod" mismatch.
    """
    if isinstance(event, dict):
        detail = event.get("detail")
        if isinstance(detail, dict):
            findings = detail.get("findings")
            if isinstance(findings, list):
                return [f for f in findings if isinstance(f, dict)]
            if "SchemaVersion" in detail or "Id" in detail:
                return [detail]

        findings = event.get("findings") or event.get("Findings")
        if isinstance(findings, list):
            return [f for f in findings if isinstance(f, dict)]

        if "SchemaVersion" in event or "ProductArn" in event:
            return [event]

    if isinstance(event, list):
        return [f for f in event if isinstance(f, dict)]

    return []


def is_duplicate(fingerprint: str) -> bool:
    """Record the fingerprint and report whether it was already seen.

    Uses a conditional write, so the check and the record are one atomic
    operation: two concurrent invocations for the same finding cannot both
    decide they are first and both notify.

    Fails OPEN on any error -- if the dedup table is unavailable we would
    rather send a duplicate notification than drop a real one. A missed
    critical finding is a worse outcome than a repeated email.
    """
    table = _dedup_table()
    if table is None:
        return False

    expires_at = int((datetime.now(tz=UTC) + timedelta(hours=DEDUP_TTL_HOURS)).timestamp())
    try:
        table.put_item(
            Item={
                "fingerprint": fingerprint,
                "first_notified_at": datetime.now(tz=UTC).isoformat(),
                "expires_at": expires_at,
            },
            ConditionExpression="attribute_not_exists(fingerprint)",
        )
        return False
    except Exception as exc:  # noqa: BLE001 - must never break the pipeline
        name = type(exc).__name__
        if "ConditionalCheckFailed" in name or "ConditionalCheckFailed" in str(exc):
            return True
        _log("dedup_check_failed", "error", reason=name)
        return False


def build_notification(finding: Any) -> str:
    """Build the SNS message body.

    Deliberately terse and actionable. It names the resource, the score and
    the owner, and points at the runbook -- the three things the responder
    needs before they open the console. It does not include the finding's full
    description or any resource detail.
    """
    return "\n".join(
        [
            f"[{finding.priority}] {finding.severity.upper()} — {finding.title}",
            "",
            f"Resource   : {finding.resource}",
            f"Category   : {finding.category}",
            f"Risk score : {finding.risk_score}",
            f"Owner      : {finding.owner}",
            f"Finding ID : {finding.finding_id}",
            f"Environment: {ENVIRONMENT}",
            "",
            f"Remediation: {finding.remediation[:500]}" if finding.remediation else "",
            "",
            "Runbook: runbooks/cloud-security-finding-response.md",
        ]
    ).strip()


def notify(finding: Any) -> bool:
    """Publish a notification, returning whether it was sent."""
    client = _sns()
    if client is None:
        _log(
            "notification_skipped",
            "allowed",
            reason="no_sns_topic_configured",
            resource_id=finding.resource,
        )
        return False

    try:
        client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{finding.priority}] Security Hub: {finding.title}"[:100],
            Message=build_notification(finding),
        )
        return True
    except Exception as exc:  # noqa: BLE001 - a failed publish must not stall triage
        _log("notification_failed", "error", reason=type(exc).__name__)
        return False


def triage_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize, score and (if warranted) notify for one ASFF finding."""
    adapted = normalize_asff(raw)
    finding, warnings = normalize_finding(adapted, _config(), default_source="securityhub")
    finding = assign_owner(score_finding(finding, _config()), _config())

    for warning in warnings:
        _log("normalization_warning", "allowed", reason=warning)

    duplicate = is_duplicate(finding.fingerprint)
    should_notify = finding.severity in NOTIFY_SEVERITIES and finding.is_open and not duplicate

    _log(
        "security_hub_finding_triaged",
        "allowed",
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        resource_id=finding.resource,
        category=finding.category,
        finding_severity=finding.severity,
        priority=finding.priority,
        risk_score=finding.risk_score,
        owner=finding.owner,
        status=finding.status,
        duplicate=duplicate,
        notified=should_notify,
    )

    notified = notify(finding) if should_notify else False

    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "severity": finding.severity,
        "priority": finding.priority,
        "risk_score": finding.risk_score,
        "owner": finding.owner,
        "status": finding.status,
        "duplicate": duplicate,
        "notified": notified,
    }


def lambda_handler(event: Any, context: Any = None) -> dict[str, Any]:  # noqa: ARG001
    """Entry point.

    Always returns a summary and never raises. EventBridge retries a failed
    invocation and then dead-letters it, so raising on one malformed finding
    would stall triage for every other finding in the same batch.
    """
    findings = extract_findings(event)

    if not findings:
        _log("malformed_event", "error", reason="no_findings_in_event")
        return {"processed": 0, "notified": 0, "duplicates": 0, "errors": 1, "results": []}

    results: list[dict[str, Any]] = []
    errors = 0

    for raw in findings:
        try:
            results.append(triage_finding(raw))
        except Exception as exc:  # noqa: BLE001 - deliberate: see docstring
            errors += 1
            _log(
                "finding_triage_failed",
                "error",
                reason=type(exc).__name__,
                # The generator id is safe to log; the finding body is not.
                generator_id=str(raw.get("GeneratorId", "<unknown>"))[:200],
            )

    summary = {
        "processed": len(results),
        "notified": sum(1 for r in results if r["notified"]),
        "duplicates": sum(1 for r in results if r["duplicate"]),
        "errors": errors,
        "results": results,
    }

    _log(
        "triage_batch_complete",
        "allowed",
        processed=summary["processed"],
        notified=summary["notified"],
        duplicates=summary["duplicates"],
        errors=summary["errors"],
    )
    return summary
