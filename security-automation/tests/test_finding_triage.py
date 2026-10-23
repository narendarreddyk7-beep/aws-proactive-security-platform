"""Unit tests for the Security Finding Triage engine.

Covers the five behaviours that justify the tool existing: normalization,
scoring, deduplication, owner assignment and cross-run status tracking --
plus the input handling that keeps one bad record from discarding a batch.

All data is synthetic.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finding_triage as triage

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def config() -> triage.TriageConfig:
    """The project's default triage configuration."""
    return triage.TriageConfig.load()


def make_record(**overrides: object) -> dict:
    """A minimal valid raw record."""
    record = {
        "source": "manual-review",
        "resource": "application/app/security/identity.py:88",
        "category": "authentication",
        "severity": "high",
        "title": "Identity accepted from client-controlled headers",
    }
    record.update(overrides)
    return record


def normalized(config: triage.TriageConfig, **overrides: object) -> triage.Finding:
    """Normalize, score and assign an owner in one step."""
    finding, _ = triage.normalize_finding(make_record(**overrides), config, now=NOW)
    return triage.assign_owner(triage.score_finding(finding, config), config)


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", "critical"),
        ("CRITICAL", "critical"),
        ("  High  ", "high"),
        ("ERROR", "high"),
        ("warning", "medium"),
        ("moderate", "medium"),
        ("minor", "low"),
        ("INFORMATIONAL", "info"),
        ("blocker", "critical"),
    ],
)
def test_severity_labels_are_mapped(config: triage.TriageConfig, raw: str, expected: str) -> None:
    """Tool-specific labels land on one comparable scale."""
    severity, warning = triage.normalize_severity(raw, config)
    assert severity == expected
    assert warning is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (9.8, "critical"),
        (9.0, "critical"),
        (7.5, "high"),
        (7.0, "high"),
        (5.0, "medium"),
        (4.0, "medium"),
        (2.1, "low"),
        (0, "info"),
        (70, "high"),  # 0-100 scale, as Security Hub's Normalized field uses
        (95, "critical"),
    ],
)
def test_numeric_severities_are_mapped(
    config: triage.TriageConfig, score: float, expected: str
) -> None:
    """CVSS-like scores map onto the same scale, on either 0-10 or 0-100."""
    severity, warning = triage.normalize_severity(score, config)
    assert severity == expected
    assert warning is None


def test_unknown_severity_warns_rather_than_silently_downgrading(
    config: triage.TriageConfig,
) -> None:
    """A silent downgrade would put a real defect in the wrong priority band."""
    severity, warning = triage.normalize_severity("SOMEWHAT_BAD", config)
    assert severity == "medium"
    assert warning is not None
    assert "SOMEWHAT_BAD" in warning


def test_missing_severity_warns(config: triage.TriageConfig) -> None:
    """Absence is also a data-quality problem worth surfacing."""
    severity, warning = triage.normalize_severity(None, config)
    assert severity == "medium"
    assert warning is not None


# ---------------------------------------------------------------------------
# Category and status normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("iam", "iam"),
        ("access-control", "authorization"),
        ("Access Control", "authorization"),
        ("identity", "iam"),
        ("crypto", "encryption"),
        ("supply_chain", "dependency"),
        ("audit", "logging"),
        ("credentials", "secrets"),
        ("completely-made-up", "other"),
    ],
)
def test_categories_and_synonyms_are_mapped(raw: str, expected: str) -> None:
    """Scanners disagree about category names; the report must not."""
    category, _ = triage.normalize_category(raw)
    assert category == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("open", "open"),
        ("NEW", "open"),
        ("triaged", "in_progress"),
        ("suppressed", "accepted_risk"),
        ("wontfix", "accepted_risk"),
        ("fixed", "resolved"),
        ("fp", "false_positive"),
        (None, "open"),
    ],
)
def test_statuses_and_synonyms_are_mapped(raw: str | None, expected: str) -> None:
    """Status drives the open-risk statistics, so it has to be canonical."""
    status, _ = triage.normalize_status(raw)
    assert status == expected


# ---------------------------------------------------------------------------
# Identity and fingerprints
# ---------------------------------------------------------------------------


def test_fingerprint_is_stable_across_runs(config: triage.TriageConfig) -> None:
    """The same defect keeps the same id, so a ticket reference stays valid."""
    first = normalized(config)
    second = normalized(config)
    assert first.fingerprint == second.fingerprint
    assert first.finding_id == second.finding_id


def test_fingerprint_ignores_severity_and_timestamps(config: triage.TriageConfig) -> None:
    """Re-rating a finding must not make it look like a new one.

    If severity were part of the fingerprint, a re-rate would break
    deduplication and reset the finding's age -- destroying exactly the
    history the report exists to show.
    """
    high = normalized(config, severity="high")
    critical = normalized(config, severity="critical", first_observed="2020-01-01T00:00:00Z")
    assert high.fingerprint == critical.fingerprint


def test_fingerprint_changes_with_resource(config: triage.TriageConfig) -> None:
    """The same defect class on two files is two findings."""
    first = normalized(config, resource="a.py:1")
    second = normalized(config, resource="b.py:1")
    assert first.fingerprint != second.fingerprint


def test_explicit_finding_id_is_preserved(config: triage.TriageConfig) -> None:
    """A human-assigned id (from a ticket) must survive triage."""
    finding = normalized(config, finding_id="SEC-1234")
    assert finding.finding_id == "SEC-1234"


def test_missing_title_raises(config: triage.TriageConfig) -> None:
    """A finding with no title cannot be triaged or assigned."""
    with pytest.raises(triage.TriageInputError, match="no title"):
        triage.normalize_finding(make_record(title=""), config, now=NOW)


def test_non_object_record_raises(config: triage.TriageConfig) -> None:
    """Clear error over a confusing attribute error."""
    with pytest.raises(triage.TriageInputError, match="must be an object"):
        triage.normalize_finding("not-a-dict", config, now=NOW)


def test_missing_resource_is_recorded_not_fatal(config: triage.TriageConfig) -> None:
    """A finding without a resource is still worth reporting."""
    finding, warnings = triage.normalize_finding(make_record(resource=""), config, now=NOW)
    assert finding.resource == "<unspecified>"
    assert any("resource missing" in w for w in warnings)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_score_rises_with_severity(config: triage.TriageConfig) -> None:
    """The ordering the whole queue depends on."""
    scores = [
        normalized(config, severity=severity).risk_score
        for severity in ("info", "low", "medium", "high", "critical")
    ]
    assert scores == sorted(scores)


def test_context_tags_scale_the_score(config: triage.TriageConfig) -> None:
    """Context must change priority, not merely annotate it.

    This is the whole argument for the tool: the same 'high' label on an
    internet-facing production resource holding customer data is a different
    piece of work from the same label in a sandbox.
    """
    plain = normalized(config, resource="unmatched-resource")
    contextual = normalized(
        config,
        resource="unmatched-resource",
        tags=["internet_facing", "production", "customer_data"],
    )
    assert contextual.risk_score > plain.risk_score * 1.5


def test_sandbox_tag_reduces_the_score(config: triage.TriageConfig) -> None:
    """A finding in a throwaway environment should not outrank production."""
    production = normalized(config, resource="x", tags=["production"])
    sandbox = normalized(config, resource="x", tags=["sandbox"])
    assert sandbox.risk_score < production.risk_score


def test_resource_criticality_is_applied(config: triage.TriageConfig) -> None:
    """An IAM role is weighted above an uncategorised resource."""
    iam_resource = normalized(config, resource="aws_iam_role.lambda_execution")
    plain = normalized(config, resource="some/unmatched/path.txt")
    assert iam_resource.risk_score > plain.risk_score


def test_resource_weight_reports_its_reason(config: triage.TriageConfig) -> None:
    """A priority a developer cannot explain is a priority they will ignore."""
    weight, reason = triage.resource_weight("aws_dynamodb_table.main", config)
    assert weight > 1.0
    assert "customer data" in reason.lower()


def test_unmatched_resource_gets_the_default_weight(config: triage.TriageConfig) -> None:
    """No rule matching must be neutral, not a penalty or a bonus."""
    weight, reason = triage.resource_weight("totally/unrelated/thing", config)
    assert weight == config.resource_default_weight
    assert "no resource rule matched" in reason


def test_score_factors_are_recorded(config: triage.TriageConfig) -> None:
    """Every multiplier must be visible, so the config can be argued with."""
    finding = normalized(config, resource="aws_iam_role.x", category="iam", tags=["production"])
    factor_names = [name for name, _ in finding.score_factors]
    assert any(name.startswith("severity:") for name in factor_names)
    assert any(name.startswith("category:") for name in factor_names)
    assert any(name.startswith("resource:") for name in factor_names)
    assert "tag:production" in factor_names


def test_severity_alone_does_not_reach_p0(config: triage.TriageConfig) -> None:
    """P0 must require severity AND context.

    If a quarter of the queue is P0 then P0 means nothing, and the on-call
    learns to ignore it.
    """
    finding = normalized(
        config, severity="critical", category="other", resource="unmatched", tags=[]
    )
    assert finding.priority != "P0"


def test_critical_with_full_context_reaches_p0(config: triage.TriageConfig) -> None:
    """The band must still be reachable for genuinely urgent work."""
    finding = normalized(
        config,
        severity="critical",
        category="authorization",
        resource="application/app/security/authorization.py",
        tags=["internet_facing", "production", "customer_data", "cross_tenant"],
    )
    assert finding.priority == "P0"


def test_score_is_capped(config: triage.TriageConfig) -> None:
    """Stacked multipliers must not produce an unbounded number."""
    finding = normalized(
        config,
        severity="critical",
        category="secrets",
        resource="aws_iam_role.x",
        tags=[
            "internet_facing",
            "production",
            "customer_data",
            "exploit_available",
            "cross_tenant",
        ],
    )
    assert finding.risk_score <= 300.0


def test_invalid_regex_in_config_does_not_crash(config: triage.TriageConfig) -> None:
    """A bad pattern in config must degrade, not take the tool down."""
    broken = triage.TriageConfig(
        raw={
            **config.raw,
            "resource_criticality": {
                "rules": [{"pattern": "[unclosed", "weight": 9.0}],
                "default_weight": 1.0,
            },
        }
    )
    weight, _ = triage.resource_weight("anything", broken)
    assert weight == 1.0


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_same_defect_from_two_tools_is_one_finding(config: triage.TriageConfig) -> None:
    """Two scanners reporting one misconfiguration is one piece of work."""
    checkov = normalized(
        config,
        source="checkov",
        category="iam",
        resource="aws_iam_role.x",
        title="Wildcard IAM action",
    )
    own_tool = normalized(
        config,
        source="iam-policy-checker",
        category="iam",
        resource="aws_iam_role.x",
        title="Wildcard IAM action",
    )

    merged, duplicates = triage.deduplicate([checkov, own_tool])

    assert duplicates == 1
    assert len(merged) == 1
    assert set(merged[0].merged_sources) == {"checkov", "iam-policy-checker"}
    assert merged[0].occurrence_count == 2


def test_merge_keeps_the_highest_severity(config: triage.TriageConfig) -> None:
    """An under-rated duplicate must not lower a correct rating.

    Keeping the maximum is the safe direction: the cost of over-prioritising
    is wasted attention; the cost of under-prioritising is an unfixed defect.
    """
    low = normalized(config, source="a", severity="low", title="Same defect")
    critical = normalized(config, source="b", severity="critical", title="Same defect")

    for order in ([low, critical], [critical, low]):
        merged, _ = triage.deduplicate(order)
        assert merged[0].severity == "critical"


def test_merge_keeps_the_earliest_first_observed(config: triage.TriageConfig) -> None:
    """Age must reflect when the defect appeared, not which tool noticed last."""
    old = normalized(
        config, source="a", first_observed="2026-01-01T00:00:00+00:00", title="Same defect"
    )
    new = normalized(
        config, source="b", first_observed="2026-03-01T00:00:00+00:00", title="Same defect"
    )

    merged, _ = triage.deduplicate([new, old])
    assert merged[0].first_observed.startswith("2026-01-01")


def test_merge_unions_tags_and_references(config: triage.TriageConfig) -> None:
    """Context from either tool must survive the merge."""
    first = normalized(
        config, source="a", title="Same", tags=["production"], references=["CWE-732"]
    )
    second = normalized(
        config, source="b", title="Same", tags=["internet_facing"], references=["CKV_AWS_1"]
    )

    merged, _ = triage.deduplicate([first, second])
    assert set(merged[0].tags) == {"production", "internet_facing"}
    assert set(merged[0].references) == {"CWE-732", "CKV_AWS_1"}


def test_different_defects_are_not_merged(config: triage.TriageConfig) -> None:
    """Deduplication must not be so eager that it hides work."""
    first = normalized(config, title="Defect one")
    second = normalized(config, title="Defect two")
    merged, duplicates = triage.deduplicate([first, second])
    assert duplicates == 0
    assert len(merged) == 2


def test_deduplication_is_order_independent(config: triage.TriageConfig) -> None:
    """Result must not depend on which file was read first."""
    findings = [
        normalized(config, source="a", title="X", severity="low"),
        normalized(config, source="b", title="X", severity="high"),
        normalized(config, source="c", title="Y"),
    ]
    forward, _ = triage.deduplicate(findings)
    reverse, _ = triage.deduplicate(list(reversed(findings)))

    assert {f.fingerprint for f in forward} == {f.fingerprint for f in reverse}
    assert sorted(f.severity for f in forward) == sorted(f.severity for f in reverse)


def test_deduplicating_an_empty_list_is_safe() -> None:
    """Empty input is a valid state, not an error."""
    merged, duplicates = triage.deduplicate([])
    assert merged == []
    assert duplicates == 0


# ---------------------------------------------------------------------------
# Owner assignment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "source", "expected"),
    [
        ("iam", "manual-review", "cloud-security-engineering"),
        ("authorization", "manual-review", "application-security"),
        ("authentication", "manual-review", "application-security"),
        ("secrets", "manual-review", "cloud-security-engineering"),
        ("configuration", "checkov", "platform-engineering"),
        ("application", "bandit", "application-security"),
        ("dependency", "pip-audit", "platform-engineering"),
        ("logging", "manual-review", "platform-engineering"),
    ],
)
def test_owner_rules_assign_as_documented(
    config: triage.TriageConfig, category: str, source: str, expected: str
) -> None:
    """An unowned finding is an unfixed finding."""
    finding = normalized(config, category=category, source=source)
    assert finding.owner == expected


def test_unmatched_finding_falls_back_to_the_default_owner(
    config: triage.TriageConfig,
) -> None:
    """Nothing may be left unassigned."""
    finding = normalized(config, category="availability", source="unknown-tool")
    assert finding.owner == config.default_owner


def test_explicit_owner_is_not_overridden(config: triage.TriageConfig) -> None:
    """A human assignment beats a rule. Reassigning it would be rude and wrong."""
    finding = normalized(config, owner="platform-oncall", category="iam")
    assert finding.owner == "platform-oncall"


def test_rule_with_no_criteria_does_not_match_everything(
    config: triage.TriageConfig,
) -> None:
    """A criteria-less rule is a config mistake, not a catch-all."""
    assert not triage._rule_matches({"owner": "someone"}, normalized(config))


def test_resource_pattern_rules_are_honoured(config: triage.TriageConfig) -> None:
    """Rules can target a path as well as a category."""
    custom = triage.TriageConfig(
        raw={
            **config.raw,
            "owner_rules": {
                "rules": [
                    {
                        "name": "identity-code",
                        "resource_pattern": r"app/security/",
                        "owner": "identity-team",
                    }
                ],
                "default_owner": "fallback",
            },
        }
    )
    finding, _ = triage.normalize_finding(
        make_record(resource="application/app/security/identity.py:88"), custom, now=NOW
    )
    assert triage.assign_owner(finding, custom).owner == "identity-team"


# ---------------------------------------------------------------------------
# Status tracking across runs
# ---------------------------------------------------------------------------


def _report_from(findings: list[triage.Finding], config: triage.TriageConfig) -> dict:
    """Build a report, as a previous run would have written it."""
    return triage.build_report(
        findings,
        [],
        sources=["previous"],
        duplicates_removed=0,
        warnings=[],
        schema_violations=[],
        now=NOW,
        config=config,
    )


def test_findings_are_new_on_the_first_run(config: triage.TriageConfig) -> None:
    """With no previous report, everything is news."""
    current, resolved = triage.apply_previous_state(
        [normalized(config)], None, now=NOW, config=config
    )
    assert current[0].is_new is True
    assert resolved == []


def test_recurring_finding_is_not_new_and_keeps_its_age(
    config: triage.TriageConfig,
) -> None:
    """Age must be real, not reset by the next scan."""
    original = normalized(config, first_observed="2026-01-01T00:00:00+00:00")
    previous = _report_from([original], config)

    rescanned = normalized(config, first_observed="2026-03-20T12:00:00+00:00")
    current, _ = triage.apply_previous_state([rescanned], previous, now=NOW, config=config)

    assert current[0].is_new is False
    assert current[0].first_observed.startswith("2026-01-01")
    assert current[0].age_days == 78


@pytest.mark.parametrize("human_status", ["in_progress", "accepted_risk", "false_positive"])
def test_human_decisions_survive_the_next_scan(
    config: triage.TriageConfig, human_status: str
) -> None:
    """A scanner must not undo a human triage decision.

    Without this, marking something 'accepted_risk' lasts exactly until the
    next CI run, and the whole workflow is theatre.
    """
    previous = _report_from([normalized(config, status=human_status)], config)
    current, _ = triage.apply_previous_state(
        [normalized(config, status="open")], previous, now=NOW, config=config
    )
    assert current[0].status == human_status


def test_automated_status_is_not_sticky(config: triage.TriageConfig) -> None:
    """A previously-'open' finding stays driven by the current scan."""
    previous = _report_from([normalized(config, status="open")], config)
    current, _ = triage.apply_previous_state(
        [normalized(config, status="resolved")], previous, now=NOW, config=config
    )
    assert current[0].status == "resolved"


def test_disappeared_finding_is_reported_as_resolved(config: triage.TriageConfig) -> None:
    """A finding that stops being reported is information, not a deletion."""
    previous = _report_from(
        [normalized(config, title="Was here"), normalized(config, title="Still here")], config
    )
    current, resolved = triage.apply_previous_state(
        [normalized(config, title="Still here")], previous, now=NOW, config=config
    )

    assert len(current) == 1
    assert len(resolved) == 1
    assert resolved[0].title == "Was here"
    assert resolved[0].status == "resolved"


def test_already_resolved_findings_are_not_re_reported(
    config: triage.TriageConfig,
) -> None:
    """A resolution is announced once, not on every subsequent run."""
    previous = _report_from([normalized(config, title="Old news", status="resolved")], config)
    _, resolved = triage.apply_previous_state([], previous, now=NOW, config=config)
    assert resolved == []


def test_overdue_flag_uses_the_priority_sla(config: triage.TriageConfig) -> None:
    """A P0 open for a month must be visibly overdue."""
    original = normalized(
        config,
        severity="critical",
        category="authorization",
        resource="application/app/security/authorization.py",
        tags=["internet_facing", "production", "customer_data", "cross_tenant"],
        first_observed="2026-01-01T00:00:00+00:00",
    )
    previous = _report_from([original], config)
    current, _ = triage.apply_previous_state([original], previous, now=NOW, config=config)

    assert current[0].priority == "P0"
    assert current[0].overdue is True


def test_resolved_finding_is_never_overdue(config: triage.TriageConfig) -> None:
    """Only outstanding work can be late."""
    original = normalized(config, status="resolved", first_observed="2020-01-01T00:00:00+00:00")
    previous = _report_from([original], config)
    current, _ = triage.apply_previous_state([original], previous, now=NOW, config=config)
    assert current[0].overdue is False


def test_malformed_first_observed_does_not_crash(config: triage.TriageConfig) -> None:
    """A bad timestamp must not take the report down."""
    finding = normalized(config, first_observed="not-a-timestamp")
    current, _ = triage.apply_previous_state([finding], None, now=NOW, config=config)
    assert current[0].age_days == 0


# ---------------------------------------------------------------------------
# Security Hub ASFF transformation
# ---------------------------------------------------------------------------


@pytest.fixture
def asff_finding() -> dict:
    """One synthetic ASFF finding."""
    return {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:000000000000:subscription/synthetic/finding/0001",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
        "AwsAccountId": "000000000000",
        "Region": "us-east-1",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
        "CreatedAt": "2026-03-01T08:00:00.000Z",
        "FirstObservedAt": "2026-03-01T08:00:00.000Z",
        "Severity": {"Label": "HIGH", "Normalized": 70},
        "Title": "IAM policies should not allow full administrative privileges",
        "Description": "A policy grants all actions on all resources.",
        "Remediation": {
            "Recommendation": {
                "Text": "Scope the policy.",
                "Url": "https://docs.aws.amazon.com/synthetic",
            }
        },
        "Resources": [{"Type": "AwsIamPolicy", "Id": "arn:aws:iam::000000000000:policy/synthetic"}],
        "Compliance": {"Status": "FAILED"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "ProductFields": {
            "aws/securityhub/annotation": "configuration detail that should not be copied"
        },
    }


def test_asff_core_fields_are_mapped(asff_finding: dict) -> None:
    """The fields triage needs, and only those."""
    record = triage.normalize_asff(asff_finding)

    assert record["source"] == "securityhub"
    assert record["severity"] == "HIGH"
    assert record["resource"] == "arn:aws:iam::000000000000:policy/synthetic"
    assert record["category"] == "iam"
    assert record["status"] == "open"
    assert record["first_observed"] == "2026-03-01T08:00:00.000Z"
    assert "Scope the policy." in record["remediation"]


def test_asff_product_fields_are_not_copied(asff_finding: dict) -> None:
    """ProductFields and resource Details can carry configuration values.

    Copying them into a triage report would widen where that data lives for
    no triage benefit, so the adapter drops them.
    """
    record = triage.normalize_asff(asff_finding)
    serialized = json.dumps(record)
    assert "should not be copied" not in serialized
    assert "ProductFields" not in record


def test_asff_workflow_status_overrides_compliance_status(asff_finding: dict) -> None:
    """The human decision beats the machine result."""
    asff_finding["Workflow"]["Status"] = "SUPPRESSED"
    assert triage.normalize_asff(asff_finding)["status"] == "accepted_risk"


def test_asff_archived_record_is_resolved(asff_finding: dict) -> None:
    """An archived finding is one Security Hub no longer observes."""
    asff_finding["RecordState"] = "ARCHIVED"
    assert triage.normalize_asff(asff_finding)["status"] == "resolved"


def test_asff_id_is_stable_but_not_the_raw_arn(asff_finding: dict) -> None:
    """ASFF ids are long ARNs that change when a resource is recreated."""
    first = triage.normalize_asff(asff_finding)["finding_id"]
    second = triage.normalize_asff(dict(asff_finding))["finding_id"]
    assert first == second
    assert first.startswith("SH-")
    assert "arn:aws" not in first


def test_asff_malformed_finding_degrades_gracefully(config: triage.TriageConfig) -> None:
    """A finding with no resource and no severity must still triage."""
    record = triage.normalize_asff({"Id": "x", "GeneratorId": "g", "Title": "Malformed finding"})
    finding, warnings = triage.normalize_finding(record, config, now=NOW)

    assert finding.resource == "<unspecified>"
    assert finding.severity == "medium"
    assert warnings


def test_asff_non_object_raises() -> None:
    """Clear error over an attribute error deep in the adapter."""
    with pytest.raises(triage.TriageInputError, match="must be an object"):
        triage.normalize_asff(["not", "an", "object"])


@pytest.mark.parametrize(
    ("types", "resource_type", "expected"),
    [
        ([], "AwsIamRole", "iam"),
        (["Effects/Data Exposure"], "AwsS3Bucket", "data_protection"),
        (["Software and Configuration Checks/Vulnerabilities/CVE"], "", "dependency"),
        ([], "AwsCloudTrailTrail", "logging"),
        ([], "AwsEc2SecurityGroup", "network"),
        ([], "AwsSomethingUnknown", "configuration"),
    ],
)
def test_asff_category_inference(types: list[str], resource_type: str, expected: str) -> None:
    """The ASFF type taxonomy is far more useful than the product name."""
    assert triage._category_from_asff_types(types, resource_type) == expected


# ---------------------------------------------------------------------------
# Source-format adapters
# ---------------------------------------------------------------------------


def test_checkov_output_is_adapted() -> None:
    """Checkov's failed_checks become normalized records."""
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_119",
                    "check_name": "Ensure DynamoDB tables are encrypted with a CMK",
                    "resource": "aws_dynamodb_table.main",
                    "file_path": "/dynamodb.tf",
                    "file_line_range": [20, 40],
                    "guideline": "https://docs.example.invalid/ckv-aws-119",
                }
            ]
        },
    }
    records = triage._normalize_checkov(payload)
    assert len(records) == 1
    assert records[0]["source"] == "checkov"
    assert records[0]["resource"] == "aws_dynamodb_table.main"
    assert records[0]["category"] == "encryption"


def test_bandit_output_is_adapted() -> None:
    """Bandit results become normalized records with a file:line resource."""
    payload = {
        "metrics": {},
        "results": [
            {
                "filename": "application/app/main.py",
                "line_number": 85,
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible binding to all interfaces.",
                "test_id": "B104",
                "test_name": "hardcoded_bind_all_interfaces",
                "issue_cwe": {"id": 605},
                "more_info": "https://bandit.example.invalid/b104",
            }
        ],
    }
    records = triage._normalize_bandit(payload)
    assert len(records) == 1
    assert records[0]["resource"] == "application/app/main.py:85"
    assert records[0]["category"] == "application"
    assert "CWE-605" in records[0]["references"]


def test_iam_checker_output_is_adapted() -> None:
    """The project's own tool feeds the triage engine."""
    payload = {
        "tool": "iam-policy-checker",
        "findings": [
            {
                "rule_id": "IAM002",
                "title": "Service-level wildcard action: dynamodb:*",
                "severity": "high",
                "confidence": "confirmed",
                "source": "policies/lambda-execution.json",
                "statement_sid": "AllDynamo",
                "description": "d",
                "remediation": "r",
                "references": ["CWE-732"],
            }
        ],
    }
    records = triage._normalize_iam_checker(payload)
    assert len(records) == 1
    assert records[0]["category"] == "iam"
    assert records[0]["severity"] == "high"


def test_needs_context_iam_findings_are_down_weighted() -> None:
    """A review prompt must not outrank a confirmed defect."""
    payload = {
        "tool": "iam-policy-checker",
        "findings": [
            {
                "rule_id": "IAM003",
                "title": "Unscoped resource",
                "severity": "high",
                "confidence": "needs_context",
                "source": "p.json",
                "statement_sid": "S",
            }
        ],
    }
    assert "compensating_control" in triage._normalize_iam_checker(payload)[0]["tags"]


def test_pip_audit_output_is_adapted() -> None:
    """Dependency advisories become normalized records."""
    payload = {
        "dependencies": [
            {
                "name": "synthetic-lib",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "SYNTHETIC-0001",
                        "description": "Synthetic advisory.",
                        "fix_versions": ["1.0.1"],
                        "aliases": ["GHSA-synthetic"],
                    }
                ],
            },
            {"name": "clean-lib", "version": "2.0.0", "vulns": []},
        ]
    }
    records = triage._normalize_pip_audit(payload)
    assert len(records) == 1
    assert records[0]["resource"] == "synthetic-lib==1.0.0"
    assert "Upgrade synthetic-lib to 1.0.1" in records[0]["remediation"]


def test_advisory_without_a_fix_is_tagged_exploit_available() -> None:
    """No published fix means the exposure cannot simply be patched away."""
    payload = {
        "dependencies": [{"name": "x", "version": "1", "vulns": [{"id": "A", "fix_versions": []}]}]
    }
    assert "exploit_available" in triage._normalize_pip_audit(payload)[0]["tags"]


@pytest.mark.parametrize(
    "payload",
    [
        {"tool": "iam-policy-checker", "findings": []},
        {"metrics": {}, "results": []},
        {"results": {"failed_checks": []}},
        {"dependencies": []},
        {"findings": []},
        [],
    ],
)
def test_auto_detection_handles_empty_inputs(payload: object) -> None:
    """A clean scan is a valid input, not an error."""
    assert triage.detect_and_adapt(payload, "auto", "test") == []


def test_auto_detection_identifies_asff() -> None:
    """A bare ASFF list must be recognised without --format."""
    payload = [
        {
            "SchemaVersion": "2018-10-08",
            "Id": "x",
            "GeneratorId": "g",
            "Title": "t",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "r", "Type": "AwsIamRole"}],
        }
    ]
    records = triage.detect_and_adapt(payload, "auto", "test")
    assert records[0]["source"] == "securityhub"


def test_auto_detection_handles_an_eventbridge_envelope() -> None:
    """The shape the Lambda receives must also work from the CLI."""
    payload = {
        "detail": {
            "findings": [
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": "x",
                    "GeneratorId": "g",
                    "Title": "t",
                    "Severity": {"Label": "CRITICAL"},
                    "Resources": [{"Id": "r", "Type": "AwsIamRole"}],
                }
            ]
        }
    }
    records = triage.detect_and_adapt(payload, "auto", "test")
    assert len(records) == 1


def test_unrecognisable_input_raises_with_guidance() -> None:
    """The error must name the available --format values."""
    with pytest.raises(triage.TriageInputError, match="--format"):
        triage.detect_and_adapt("a bare string", "auto", "test")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def test_report_summary_counts_are_consistent(config: triage.TriageConfig) -> None:
    """The headline numbers must agree with the finding list."""
    findings = [
        normalized(config, title="A", severity="critical", status="open"),
        normalized(config, title="B", severity="high", status="in_progress"),
        normalized(config, title="C", severity="low", status="accepted_risk"),
        normalized(config, title="D", severity="medium", status="resolved"),
    ]
    report = _report_from(findings, config)
    summary = report["summary"]

    assert summary["total_findings"] == 4
    assert summary["open_findings"] == 2  # open + in_progress
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_status"]["accepted_risk"] == 1
    assert sum(summary["by_severity"].values()) == 4


def test_report_is_sorted_by_risk(config: triage.TriageConfig) -> None:
    """The report IS the work queue, so order is the product."""
    findings = [
        normalized(config, title="low", severity="low"),
        normalized(config, title="crit", severity="critical"),
        normalized(config, title="med", severity="medium"),
    ]
    report = _report_from(findings, config)
    scores = [f["risk_score"] for f in report["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_report_always_states_its_limitations(config: triage.TriageConfig) -> None:
    """Scoring weights are judgement calls and the report must say so."""
    report = _report_from([], config)
    limitations = report["methodology"]["limitations"]
    assert limitations
    assert any("judgement" in item or "not derived" in item for item in limitations)


def test_empty_report_is_valid(config: triage.TriageConfig) -> None:
    """No findings must produce a well-formed report, not a crash."""
    report = _report_from([], config)
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["highest_open_risk"] == 0.0
    assert report["findings"] == []


def test_markdown_report_contains_the_work_queue(config: triage.TriageConfig) -> None:
    """The Markdown is what a developer actually reads."""
    findings = [
        normalized(
            config,
            title="Cross-tenant read possible",
            severity="critical",
            category="authorization",
            tags=["production", "cross_tenant", "customer_data", "internet_facing"],
        )
    ]
    markdown = triage.render_markdown(_report_from(findings, config))

    assert "# Security Finding Triage Report" in markdown
    assert "Cross-tenant read possible" in markdown
    assert "Work queue" in markdown
    assert "Score breakdown" in markdown
    assert "Methodology and limitations" in markdown


def test_markdown_handles_an_empty_report(config: triage.TriageConfig) -> None:
    """A clean run must render cleanly."""
    markdown = triage.render_markdown(_report_from([], config))
    assert "No open findings" in markdown


def test_markdown_lists_accepted_risks_separately(config: triage.TriageConfig) -> None:
    """An accepted risk must not be quietly forgotten."""
    findings = [normalized(config, title="Known gap", status="accepted_risk")]
    markdown = triage.render_markdown(_report_from(findings, config))
    assert "Accepted risks" in markdown
    assert "Known gap" in markdown


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_normalized_output_satisfies_the_schema(config: triage.TriageConfig) -> None:
    """The tool's own output must be canonical.

    A violation here is a bug in an adapter -- the more useful validation
    point than checking raw input, which deliberately carries tool-specific
    labels the adapters exist to translate.
    """
    findings = [
        normalized(config, severity="critical", category="iam"),
        normalized(config, title="B", severity="low", category="logging", status="resolved"),
    ]
    assert triage.validate_normalized_output(findings) == []


def test_schema_validation_catches_a_bad_record() -> None:
    """The validator must actually reject something."""
    violations = triage.validate_records(
        [
            {
                "source": "x",
                "resource": "y",
                "category": "not-a-category",
                "severity": "high",
                "title": "t",
            }
        ],
        label="input record",
    )
    assert violations
    assert any("category" in v for v in violations)


def test_schema_validation_accepts_a_good_record() -> None:
    """And accept a valid one."""
    assert triage.validate_records([make_record()], label="input record") == []


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def test_config_override_is_merged_not_replaced(tmp_path: Path) -> None:
    """Overriding one section must not wipe the scoring weights.

    Otherwise changing an owner rule silently resets every weight to nothing,
    and the priorities quietly become meaningless.
    """
    override = tmp_path / "custom.json"
    override.write_text(json.dumps({"owner_rules": {"default_owner": "my-team"}}), encoding="utf-8")
    config = triage.TriageConfig.load(override)

    assert config.default_owner == "my-team"
    assert config.severity_base_score["critical"] == 100
    assert config.category_weights["iam"] > 1.0


def test_missing_config_file_raises(tmp_path: Path) -> None:
    """A typo'd config path must be an error, not a silent default."""
    with pytest.raises(triage.TriageInputError, match="cannot read configuration"):
        triage.TriageConfig.load(tmp_path / "nope.json")


def test_non_object_config_raises(tmp_path: Path) -> None:
    """A JSON array is not a configuration."""
    path = tmp_path / "bad.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(triage.TriageInputError, match="must be a JSON object"):
        triage.TriageConfig.load(path)


def test_comment_keys_are_excluded_from_config_values(
    config: triage.TriageConfig,
) -> None:
    """`_comment` keys document the config; they are not data."""
    assert "_comment" not in config.severity_base_score
    assert "_comment" not in config.category_weights
    assert "_comment" not in config.tag_modifiers


# ---------------------------------------------------------------------------
# CLI contract
# ---------------------------------------------------------------------------


def test_cli_runs_against_the_sample_fixture(sample_data_dir: Path, tmp_path: Path) -> None:
    """The documented command in the README must work."""
    output = tmp_path / "triage.json"
    markdown = tmp_path / "triage.md"

    exit_code = triage.main(
        [
            "--input",
            str(sample_data_dir / "findings.json"),
            "--output",
            str(output),
            "--markdown",
            str(markdown),
            "--print",
            "none",
            "--now",
            "2026-03-20T12:00:00Z",
        ]
    )

    assert exit_code == 0
    assert output.exists() and markdown.exists()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["tool"] == "finding-triage"
    assert report["summary"]["total_findings"] > 0
    assert report["scan"]["duplicates_removed"] == 1


def test_cli_output_is_byte_identical_across_runs(sample_data_dir: Path, tmp_path: Path) -> None:
    """Determinism: a CI job that diffs reports needs stable output."""
    paths = []
    for name in ("first.json", "second.json"):
        destination = tmp_path / name
        triage.main(
            [
                "--input",
                str(sample_data_dir / "findings.json"),
                "--output",
                str(destination),
                "--print",
                "none",
                "--now",
                "2026-03-20T12:00:00Z",
            ]
        )
        paths.append(destination)

    assert paths[0].read_text(encoding="utf-8") == paths[1].read_text(encoding="utf-8")


def test_cli_securityhub_format(sample_data_dir: Path, tmp_path: Path) -> None:
    """The ASFF path end to end, including the malformed record."""
    output = tmp_path / "sh.json"
    exit_code = triage.main(
        [
            "--input",
            str(sample_data_dir / "securityhub-findings.json"),
            "--format",
            "securityhub",
            "--output",
            str(output),
            "--print",
            "none",
            "--now",
            "2026-03-20T12:00:00Z",
        ]
    )

    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["total_findings"] == 5
    assert report["normalization_warnings"], "the malformed record should have warned"


def test_cli_filters_by_severity(sample_data_dir: Path, tmp_path: Path) -> None:
    """Filtering is what makes the output usable for one team."""
    output = tmp_path / "filtered.json"
    triage.main(
        [
            "--input",
            str(sample_data_dir / "findings.json"),
            "--min-severity",
            "critical",
            "--output",
            str(output),
            "--print",
            "none",
            "--now",
            "2026-03-20T12:00:00Z",
        ]
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert all(f["severity"] == "critical" for f in report["findings"])


def test_cli_filters_by_owner(sample_data_dir: Path, tmp_path: Path) -> None:
    """A team should be able to see only its own queue."""
    output = tmp_path / "owned.json"
    triage.main(
        [
            "--input",
            str(sample_data_dir / "findings.json"),
            "--owner",
            "application-security",
            "--output",
            str(output),
            "--print",
            "none",
            "--now",
            "2026-03-20T12:00:00Z",
        ]
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["findings"]
    assert all(f["owner"] == "application-security" for f in report["findings"])


def test_cli_fail_on_gates(sample_data_dir: Path) -> None:
    """--fail-on must actually be able to fail."""
    args = [
        "--input",
        str(sample_data_dir / "findings.json"),
        "--print",
        "none",
        "--now",
        "2026-03-20T12:00:00Z",
    ]
    assert triage.main([*args, "--fail-on", "critical"]) == 0  # no OPEN criticals
    assert triage.main([*args, "--fail-on", "low"]) == 1


def test_cli_returns_two_with_no_input() -> None:
    """Exit 2 means "could not run" and must not be treated as a pass."""
    assert triage.main([]) == 2


def test_cli_returns_two_for_a_missing_file(tmp_path: Path) -> None:
    """A typo'd path must not look like a clean report."""
    assert triage.main(["--input", str(tmp_path / "nope.json"), "--print", "none"]) == 2


def test_cli_returns_two_for_invalid_json(tmp_path: Path) -> None:
    """Truncated JSON must not look like a clean report."""
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    assert triage.main(["--input", str(path), "--print", "none"]) == 2


def test_cli_returns_two_for_an_invalid_now_value(sample_data_dir: Path) -> None:
    """Bad arguments are usage errors."""
    assert (
        triage.main(["--input", str(sample_data_dir / "findings.json"), "--now", "yesterday"]) == 2
    )


def test_cli_validate_only_accepts_canonical_input(tmp_path: Path) -> None:
    """--validate-only is for asserting your input is already canonical."""
    path = tmp_path / "clean.json"
    path.write_text(json.dumps({"findings": [make_record()]}), encoding="utf-8")
    assert triage.main(["--input", str(path), "--validate-only"]) == 0


def test_cli_validate_only_rejects_bad_input(tmp_path: Path) -> None:
    """And must reject input that is not."""
    path = tmp_path / "dirty.json"
    path.write_text(json.dumps({"findings": [make_record(severity="ERROR")]}), encoding="utf-8")
    assert triage.main(["--input", str(path), "--validate-only"]) == 2


def test_cli_skips_one_bad_record_and_keeps_the_rest(tmp_path: Path) -> None:
    """One malformed row must not discard the batch.

    A triage tool that refuses to run because of one bad record is a triage
    tool nobody uses. The skip is recorded in the report's warnings.
    """
    path = tmp_path / "mixed.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    make_record(title="Good one"),
                    {"source": "x", "resource": "y", "category": "iam", "severity": "high"},
                    make_record(title="Another good one"),
                ]
            }
        ),
        encoding="utf-8",
    )

    output = tmp_path / "out.json"
    exit_code = triage.main(["--input", str(path), "--output", str(output), "--print", "none"])

    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["total_findings"] == 2
    assert any("skipped" in w for w in report["normalization_warnings"])


def test_cli_missing_previous_report_is_a_warning_not_an_error(
    sample_data_dir: Path, tmp_path: Path
) -> None:
    """The first run has no previous report; that is normal."""
    output = tmp_path / "out.json"
    exit_code = triage.main(
        [
            "--input",
            str(sample_data_dir / "findings.json"),
            "--previous",
            str(tmp_path / "no-such-report.json"),
            "--output",
            str(output),
            "--print",
            "none",
        ]
    )

    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert any("not found" in w for w in report["normalization_warnings"])
