"""Unit tests for the IAM Policy Security Analyzer.

Structure mirrors the tool: a group per detection rule, then input handling,
then the CLI contract (exit codes, output formats).

Every policy in this file is synthetic. Account id 000000000000 is a
placeholder.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import iam_policy_checker as checker

pytestmark = pytest.mark.unit

TABLE_ARN = "arn:aws:dynamodb:us-east-1:000000000000:table/support-platform-dev"
LOG_ARN = "arn:aws:logs:us-east-1:000000000000:log-group:/aws/lambda/support-api:*"


def policy(*statements: dict) -> dict:
    """Wrap statements in a well-formed policy document."""
    return {"Version": "2012-10-17", "Statement": list(statements)}


def analyze(*statements: dict, source: str = "test") -> list[checker.Finding]:
    """Run every rule against a policy built from the given statements."""
    document = checker.PolicyDocument(source=source, document=policy(*statements))
    return checker.analyze_document(document)


def rule_ids(findings: list[checker.Finding]) -> set[str]:
    """Rule ids present in a finding list."""
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# IAM001: administrative wildcard
# ---------------------------------------------------------------------------


def test_admin_wildcard_is_critical_and_confirmed() -> None:
    """Action:* with Resource:* is the canonical worst case."""
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"})

    matched = [f for f in findings if f.rule_id == "IAM001"]
    assert len(matched) == 1
    assert matched[0].severity is checker.Severity.CRITICAL
    assert matched[0].confidence is checker.Confidence.CONFIRMED
    assert matched[0].is_blocking


def test_admin_wildcard_detected_with_list_syntax() -> None:
    """The wildcard may arrive inside a list, not only as a scalar."""
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": ["*"], "Resource": ["*"]})
    assert "IAM001" in rule_ids(findings)


def test_admin_wildcard_detected_when_resource_is_absent() -> None:
    """An absent Resource in an identity policy is effectively Resource:*."""
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": "*"})
    assert "IAM001" in rule_ids(findings)


def test_deny_statements_are_not_flagged() -> None:
    """A Deny with a wildcard is a security control, not a defect.

    This matters for real policies: the project's own Lambda policy uses
    exactly this pattern to pin dangerous actions shut.
    """
    findings = analyze({"Sid": "DenyAll", "Effect": "Deny", "Action": "*", "Resource": "*"})
    assert not rule_ids(findings) & {"IAM001", "IAM002", "IAM003", "IAM004", "IAM005"}


# ---------------------------------------------------------------------------
# IAM002: service-level wildcard action
# ---------------------------------------------------------------------------


def test_service_wildcard_is_flagged_even_with_a_scoped_resource() -> None:
    """dynamodb:* on one table is still every action on that table.

    This is the exact shape of finding F-005 in this project's own review:
    the resource was correctly scoped, which made the statement look careful
    while still granting DeleteTable and Scan.
    """
    findings = analyze(
        {"Sid": "AllDynamo", "Effect": "Allow", "Action": "dynamodb:*", "Resource": TABLE_ARN}
    )

    matched = [f for f in findings if f.rule_id == "IAM002"]
    assert len(matched) == 1
    assert matched[0].severity is checker.Severity.HIGH
    assert matched[0].is_blocking
    # The finding must name what the wildcard actually implies -- that is the
    # part that persuades a reviewer.
    assert "dynamodb:scan" in matched[0].evidence["implied_data_access_actions"]
    assert "dynamodb:deletetable" in matched[0].evidence["implied_destructive_actions"]


def test_enumerated_actions_are_not_flagged_as_wildcards() -> None:
    """The remediated form must come back clean."""
    findings = analyze(
        {
            "Sid": "ScopedDynamo",
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"],
            "Resource": [TABLE_ARN, f"{TABLE_ARN}/index/GSI1"],
        }
    )
    assert "IAM002" not in rule_ids(findings)
    assert "IAM003" not in rule_ids(findings)


def test_prefix_wildcard_expands_against_the_catalogue() -> None:
    """iam:Put* must be recognised as granting iam:PutRolePolicy."""
    findings = analyze(
        {"Sid": "PrefixWildcard", "Effect": "Allow", "Action": "iam:Put*", "Resource": "*"}
    )
    matched = [f for f in findings if f.rule_id == "IAM004"]
    assert matched
    assert any("iam:putrolepolicy" in f.evidence["matched_escalation_actions"] for f in matched)


# ---------------------------------------------------------------------------
# IAM003: unscoped resource
# ---------------------------------------------------------------------------


def test_unscoped_resource_is_high_without_a_condition() -> None:
    """Resource:* on a scopable action is a confirmed defect."""
    findings = analyze(
        {
            "Sid": "UnscopedLogs",
            "Effect": "Allow",
            "Action": ["logs:PutLogEvents"],
            "Resource": "*",
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM003"]
    assert len(matched) == 1
    assert matched[0].severity is checker.Severity.HIGH
    assert matched[0].confidence is checker.Confidence.CONFIRMED


def test_unscoped_resource_severity_drops_when_a_condition_is_present() -> None:
    """A restricting condition narrows the grant, so the severity drops.

    It does not disappear: this tool cannot evaluate condition semantics, and
    the finding says so.
    """
    findings = analyze(
        {
            "Sid": "ConditionalDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": "*",
            "Condition": {"StringEquals": {"kms:ViaService": "dynamodb.us-east-1.amazonaws.com"}},
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM003"]
    assert matched
    assert matched[0].severity is checker.Severity.MEDIUM


def test_actions_without_resource_support_are_needs_context_not_a_defect() -> None:
    """xray:PutTraceSegments has no resource-level permissions.

    Reporting this as a defect would be noise, and noise is what teaches
    people to ignore a scanner. It is reported as INFO/needs_context and does
    not block.
    """
    findings = analyze(
        {
            "Sid": "XRay",
            "Effect": "Allow",
            "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
            "Resource": "*",
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM003"]
    assert len(matched) == 1
    assert matched[0].severity is checker.Severity.INFO
    assert matched[0].confidence is checker.Confidence.NEEDS_CONTEXT
    assert not matched[0].is_blocking


def test_admin_wildcard_does_not_also_emit_iam003() -> None:
    """One defect, one finding. IAM001 already covers Action:* + Resource:*."""
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"})
    assert "IAM003" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# IAM004: privilege escalation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    [
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
        "lambda:UpdateFunctionCode",
        "ec2:RunInstances",
    ],
)
def test_privilege_escalation_actions_are_detected(action: str) -> None:
    """Each catalogue entry must actually be detected."""
    findings = analyze({"Sid": "Escalate", "Effect": "Allow", "Action": action, "Resource": "*"})
    matched = [f for f in findings if f.rule_id == "IAM004"]
    assert matched, f"{action} was not detected as a privilege-escalation action"
    assert matched[0].severity is checker.Severity.CRITICAL


def test_scoped_privilege_escalation_is_lower_severity_and_needs_context() -> None:
    """A CI role that must pass one specific role is a legitimate pattern."""
    findings = analyze(
        {
            "Sid": "ScopedPassRole",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::000000000000:role/specific-task-role",
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM004"]
    assert matched
    assert matched[0].severity is checker.Severity.HIGH
    assert matched[0].confidence is checker.Confidence.NEEDS_CONTEXT
    assert not matched[0].is_blocking


def test_full_wildcard_does_not_explode_into_one_finding_per_catalogue_entry() -> None:
    """Action:* must produce one IAM001, not 40 IAM004s.

    Otherwise the single most important finding is buried under its own
    consequences.
    """
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"})
    assert len([f for f in findings if f.rule_id == "IAM004"]) == 0
    assert len([f for f in findings if f.rule_id == "IAM001"]) == 1


# ---------------------------------------------------------------------------
# IAM005 / IAM009: data access and destructive actions
# ---------------------------------------------------------------------------


def test_unscoped_secret_read_is_detected() -> None:
    """secretsmanager:GetSecretValue on * is account-wide secret access."""
    findings = analyze(
        {
            "Sid": "ReadAllSecrets",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "*",
        }
    )
    assert "IAM005" in rule_ids(findings)


def test_scoped_data_access_is_not_flagged() -> None:
    """A read scoped to one resource is the correct pattern."""
    findings = analyze(
        {
            "Sid": "ReadOneSecret",
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-abc123",
        }
    )
    assert "IAM005" not in rule_ids(findings)


def test_audit_disabling_actions_are_detected_as_destructive() -> None:
    """Stopping CloudTrail removes the evidence of everything else."""
    findings = analyze(
        {
            "Sid": "DisableAudit",
            "Effect": "Allow",
            "Action": ["cloudtrail:StopLogging", "guardduty:DeleteDetector"],
            "Resource": "*",
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM009"]
    assert len(matched) == 2
    assert all(f.severity is checker.Severity.HIGH for f in matched)


# ---------------------------------------------------------------------------
# IAM006: inverted matching
# ---------------------------------------------------------------------------


def test_allow_with_not_action_is_flagged() -> None:
    """An Allow + NotAction grant widens itself as AWS ships new actions."""
    findings = analyze(
        {"Sid": "Inverted", "Effect": "Allow", "NotAction": ["iam:DeleteUser"], "Resource": "*"}
    )
    assert "IAM006" in rule_ids(findings)


def test_deny_with_not_action_is_not_flagged() -> None:
    """NotAction in a Deny is a legitimate and common guardrail pattern."""
    findings = analyze(
        {
            "Sid": "RegionLock",
            "Effect": "Deny",
            "NotAction": ["iam:*", "sts:*"],
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        }
    )
    assert "IAM006" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# IAM007 / IAM008: principals
# ---------------------------------------------------------------------------


def test_wildcard_principal_without_condition_is_critical() -> None:
    """Principal:* with no condition is open to every AWS account."""
    findings = analyze(
        {"Sid": "AnyPrincipal", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
    )
    matched = [f for f in findings if f.rule_id == "IAM007"]
    assert matched
    assert matched[0].severity is checker.Severity.CRITICAL
    assert matched[0].is_blocking


def test_wildcard_principal_with_org_condition_is_needs_context() -> None:
    """aws:PrincipalOrgID narrows it to one organization."""
    findings = analyze(
        {
            "Sid": "OrgOnly",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::synthetic-bucket/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-synthetic00"}},
        }
    )
    matched = [f for f in findings if f.rule_id == "IAM007"]
    assert matched
    assert matched[0].confidence is checker.Confidence.NEEDS_CONTEXT
    assert not matched[0].is_blocking


def test_service_trust_without_source_condition_is_flagged() -> None:
    """The confused-deputy case."""
    findings = analyze(
        {
            "Sid": "ServiceTrust",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    )
    assert "IAM008" in rule_ids(findings)


def test_service_trust_with_source_account_is_not_flagged() -> None:
    """The remediated form -- what this project's own trust policy uses."""
    findings = analyze(
        {
            "Sid": "ServiceTrust",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": "000000000000"}},
        }
    )
    assert "IAM008" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# IAM010 / IAM011: hygiene
# ---------------------------------------------------------------------------


def test_missing_sid_is_info_only() -> None:
    """Worth reporting, never worth failing a build over."""
    findings = analyze({"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN})
    matched = [f for f in findings if f.rule_id == "IAM010"]
    assert matched
    assert matched[0].severity is checker.Severity.INFO


def test_legacy_policy_version_is_flagged() -> None:
    """The 2008 version silently disables policy variables in conditions."""
    document = checker.PolicyDocument(
        source="test",
        document={
            "Version": "2008-10-17",
            "Statement": [
                {"Sid": "S", "Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": TABLE_ARN}
            ],
        },
    )
    findings = checker.analyze_document(document)
    assert "IAM011" in rule_ids(findings)


def test_missing_policy_version_is_flagged() -> None:
    """A missing Version defaults to the 2008 behaviour."""
    document = checker.PolicyDocument(
        source="test",
        document={
            "Statement": [
                {"Sid": "S", "Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": TABLE_ARN}
            ]
        },
    )
    assert "IAM011" in rule_ids(checker.analyze_document(document))


# ---------------------------------------------------------------------------
# Terraform template placeholders
# ---------------------------------------------------------------------------


def test_terraform_placeholders_are_not_mistaken_for_wildcards() -> None:
    """``${table_arn}`` becomes a concrete ARN at apply time.

    The project's policy templates are checked in this form, so treating a
    placeholder as a wildcard would make every clean policy look broken.
    """
    findings = analyze(
        {
            "Sid": "Templated",
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem"],
            "Resource": ["${table_arn}", "${table_arn}/index/GSI1"],
        }
    )
    assert "IAM003" not in rule_ids(findings)
    assert checker._contains_placeholder("${table_arn}")
    assert not checker._is_wildcard("${table_arn}")


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


def test_statement_as_a_single_object_is_accepted() -> None:
    """IAM permits a single statement object rather than a list."""
    document = checker.PolicyDocument(
        source="test",
        document={
            "Version": "2012-10-17",
            "Statement": {"Sid": "S", "Effect": "Allow", "Action": "*", "Resource": "*"},
        },
    )
    assert "IAM001" in rule_ids(checker.analyze_document(document))


def test_document_without_statement_raises() -> None:
    """A clear error beats a silent clean result."""
    document = checker.PolicyDocument(source="test", document={"Version": "2012-10-17"})
    with pytest.raises(checker.PolicyParseError, match="no 'Statement'"):
        checker.analyze_document(document)


def test_non_object_statement_raises() -> None:
    """Malformed input must be an error, not an exception traceback."""
    document = checker.PolicyDocument(
        source="test", document={"Version": "2012-10-17", "Statement": ["not-an-object"]}
    )
    with pytest.raises(checker.PolicyParseError, match="expected an object"):
        checker.analyze_document(document)


def test_get_role_policy_wrapper_is_unwrapped() -> None:
    """`aws iam get-role-policy` output nests the document."""
    payload = {
        "RoleName": "synthetic",
        "PolicyName": "synthetic",
        "PolicyDocument": policy({"Sid": "S", "Effect": "Allow", "Action": "*", "Resource": "*"}),
    }
    documents = checker._coerce_to_documents(payload, "test")
    assert len(documents) == 1
    assert "IAM001" in rule_ids(checker.analyze_document(documents[0]))


def test_terraform_style_policy_string_is_unwrapped() -> None:
    """A Terraform attribute carries the document as a JSON string."""
    payload = {
        "policy": json.dumps(
            policy({"Sid": "S", "Effect": "Allow", "Action": "*", "Resource": "*"})
        )
    }
    documents = checker._coerce_to_documents(payload, "test")
    assert len(documents) == 1


def test_unrecognised_payload_raises_with_guidance() -> None:
    """The error must say what was expected."""
    with pytest.raises(checker.PolicyParseError, match="no policy document found"):
        checker._coerce_to_documents({"unrelated": "object"}, "test")


def test_unreadable_file_raises_parse_error(tmp_path: Path) -> None:
    """A missing file is an input error (exit 2), not a clean scan."""
    with pytest.raises(checker.PolicyParseError, match="cannot read file"):
        checker.load_policy_file(tmp_path / "does-not-exist.json")


def test_invalid_json_raises_parse_error(tmp_path: Path) -> None:
    """Truncated JSON must not be reported as "no findings"."""
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(checker.PolicyParseError, match="not valid JSON"):
        checker.load_policy_file(path)


def test_terraform_plan_extraction(tmp_path: Path) -> None:
    """Policies are pulled out of `terraform show -json` output."""
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_iam_role_policy.lambda",
                        "values": {
                            "policy": json.dumps(
                                policy(
                                    {
                                        "Sid": "Admin",
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                )
                            )
                        },
                    }
                ],
                "child_modules": [
                    {
                        "resources": [
                            {
                                "address": "module.x.aws_iam_role.y",
                                "values": {
                                    "assume_role_policy": json.dumps(
                                        policy(
                                            {
                                                "Sid": "Trust",
                                                "Effect": "Allow",
                                                "Principal": {"Service": "lambda.amazonaws.com"},
                                                "Action": "sts:AssumeRole",
                                            }
                                        )
                                    )
                                },
                            }
                        ]
                    }
                ],
            }
        }
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")

    documents = checker.load_terraform_plan(path)
    assert len(documents) == 2

    findings = [f for d in documents for f in checker.analyze_document(d)]
    assert {"IAM001", "IAM008"} <= rule_ids(findings)


def test_terraform_plan_without_policies_raises(tmp_path: Path) -> None:
    """A plan with no IAM resources is an input problem worth reporting."""
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"planned_values": {"root_module": {"resources": []}}}), "utf-8")
    with pytest.raises(checker.PolicyParseError, match="no IAM policy documents"):
        checker.load_terraform_plan(path)


# ---------------------------------------------------------------------------
# Determinism and reporting
# ---------------------------------------------------------------------------


def test_findings_are_sorted_most_severe_first() -> None:
    """Deterministic ordering is what makes report diffing possible."""
    findings = analyze(
        {"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN},
        {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"},
    )
    ordered = checker.sort_findings(findings)
    assert ordered[0].severity is checker.Severity.CRITICAL
    assert ordered[-1].severity is checker.Severity.INFO


def test_sorting_is_a_total_order_independent_of_list_order() -> None:
    """The sort must fully determine the output, with no ties left to chance.

    Note this shuffles the *finding list*, not the policy: statement index is
    a genuine property of a document, so reordering statements legitimately
    produces different findings. What must not vary is the report produced
    from one set of findings.
    """
    import random

    findings = analyze(
        {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "B", "Effect": "Allow", "Action": "dynamodb:*", "Resource": TABLE_ARN},
        {"Sid": "C", "Effect": "Allow", "Action": ["logs:PutLogEvents"], "Resource": "*"},
        {"Sid": "D", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
    )
    reference = [(f.rule_id, f.statement_sid, f.severity) for f in checker.sort_findings(findings)]

    rng = random.Random(1234)  # noqa: S311 - shuffling test data, not cryptography
    for _ in range(25):
        shuffled = list(findings)
        rng.shuffle(shuffled)
        assert [
            (f.rule_id, f.statement_sid, f.severity) for f in checker.sort_findings(shuffled)
        ] == reference


def test_report_counts_blocking_findings_by_severity_floor() -> None:
    """--fail-on must actually change what counts as blocking."""
    findings = analyze(
        {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": TABLE_ARN},
    )

    critical_only = checker.build_report(
        findings, sources=["t"], fail_on=checker.Severity.CRITICAL, documents_scanned=1
    )
    everything = checker.build_report(
        findings, sources=["t"], fail_on=checker.Severity.INFO, documents_scanned=1
    )

    assert critical_only["summary"]["blocking_findings"] == 1
    assert everything["summary"]["blocking_findings"] > 1


def test_report_always_states_its_limitations() -> None:
    """A clean result must not be mistaken for a proof of least privilege."""
    report = checker.build_report(
        [], sources=["t"], fail_on=checker.Severity.HIGH, documents_scanned=1
    )
    assert report["limitations"]
    assert any("Access Analyzer" in item for item in report["limitations"])


def test_needs_context_findings_never_block() -> None:
    """The gate must only fire on confirmed defects."""
    findings = analyze(
        {
            "Sid": "XRay",
            "Effect": "Allow",
            "Action": ["xray:PutTraceSegments"],
            "Resource": "*",
        }
    )
    report = checker.build_report(
        findings, sources=["t"], fail_on=checker.Severity.INFO, documents_scanned=1
    )
    assert report["summary"]["total_findings"] >= 1
    assert report["summary"]["blocking_findings"] == 0


def test_text_rendering_includes_source_and_remediation() -> None:
    """Console output has to be usable on its own in a CI log."""
    findings = analyze({"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"})
    report = checker.build_report(
        findings, sources=["policy.json"], fail_on=checker.Severity.HIGH, documents_scanned=1
    )
    text = checker.render_text(report)

    assert "IAM001" in text
    assert "policy.json" in text
    assert "Enumerate the specific actions" in text
    assert "Limitations" in text


# ---------------------------------------------------------------------------
# CLI contract
# ---------------------------------------------------------------------------


def test_cli_returns_zero_for_the_compliant_fixture(sample_data_dir: Path) -> None:
    """The least-privilege sample must pass the gate."""
    assert checker.main(["--input", str(sample_data_dir / "sample-policy.json"), "--quiet"]) == 0


def test_cli_returns_one_for_the_insecure_fixture(sample_data_dir: Path) -> None:
    """The insecure sample must fail the gate -- otherwise the gate is fake."""
    assert checker.main(["--input", str(sample_data_dir / "insecure-policy.json"), "--quiet"]) == 1


def test_cli_returns_zero_for_the_real_terraform_policies(repo_root: Path) -> None:
    """The policies this project actually deploys must pass their own checker.

    If someone widens a permission in `infrastructure/terraform/policies/`,
    this test fails before CI even runs the scanner.
    """
    exit_code = checker.main(
        [
            "--input-dir",
            str(repo_root / "infrastructure" / "terraform" / "policies"),
            "--fail-on",
            "high",
            "--quiet",
        ]
    )
    assert exit_code == 0


def test_cli_returns_two_with_no_input() -> None:
    """Exit 2 means "could not run", which CI must not treat as a pass."""
    assert checker.main([]) == 2


def test_cli_returns_two_for_a_missing_file(tmp_path: Path) -> None:
    """A typo'd path must not look like a clean scan."""
    assert checker.main(["--input", str(tmp_path / "nope.json"), "--quiet"]) == 2


def test_cli_returns_two_for_invalid_json(tmp_path: Path) -> None:
    """Malformed input must not look like a clean scan."""
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    assert checker.main(["--input", str(path), "--quiet"]) == 2


def test_cli_writes_a_json_report(tmp_path: Path, sample_data_dir: Path) -> None:
    """The machine-readable artifact CI uploads."""
    output = tmp_path / "nested" / "iam-findings.json"
    checker.main(
        [
            "--input",
            str(sample_data_dir / "insecure-policy.json"),
            "--output",
            str(output),
            "--quiet",
        ]
    )
    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["tool"] == "iam-policy-checker"
    assert report["summary"]["total_findings"] > 0
    assert report["findings"][0]["rule_id"]


def test_cli_list_rules_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """The rule catalogue must be discoverable without reading the source."""
    assert checker.main(["--list-rules"]) == 0
    captured = capsys.readouterr().out
    for rule in checker.RULES_DOCUMENTATION:
        assert rule["id"] in captured


def test_every_documented_rule_is_implemented() -> None:
    """Documentation and implementation must not drift.

    The catalogue printed by --list-rules is what a user trusts; a documented
    rule that does not exist is worse than an undocumented one.
    """
    documented = {rule["id"] for rule in checker.RULES_DOCUMENTATION}
    implemented = {
        "IAM001",
        "IAM002",
        "IAM003",
        "IAM004",
        "IAM005",
        "IAM006",
        "IAM007",
        "IAM008",
        "IAM009",
        "IAM010",
        "IAM011",
    }
    assert documented == implemented


def test_empty_statement_list_raises() -> None:
    """A policy with an empty Statement array is malformed, not clean."""
    document = checker.PolicyDocument(
        source="test", document={"Version": "2012-10-17", "Statement": []}
    )
    with pytest.raises(checker.PolicyParseError):
        checker.analyze_document(document)
