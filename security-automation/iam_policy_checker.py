#!/usr/bin/env python3
"""IAM Policy Security Analyzer.

Finds risky patterns in IAM policy documents: local JSON files, the policy
templates under ``infrastructure/terraform/policies/``, and policy strings
extracted from ``terraform show -json`` output.

WHAT THIS IS
------------
A deterministic, offline, pattern-based linter for IAM policy *documents*. It
reads JSON, applies a documented set of rules, and emits structured findings.
It needs no AWS credentials and makes no network calls, so it runs in a pull
request before anything is deployed.

WHAT THIS IS NOT
----------------
This is **not** an IAM policy evaluator and it is **not** equivalent to IAM
Access Analyzer. Specifically, it does not:

* resolve the *effective* permissions of a principal. That requires combining
  identity policies, resource policies, permissions boundaries, session
  policies, SCPs and RCPs, with the full AWS evaluation-order semantics;
* reason about ``Condition`` semantics. It notices whether a condition is
  present and flags some condition-less patterns, but it does not evaluate
  whether a given condition is actually restrictive. ``"Bool":
  {"aws:SecureTransport": "true"}`` and a condition that constrains nothing
  look the same to this tool;
* expand wildcards against the real IAM action catalogue. ``s3:Get*`` is
  matched as a prefix pattern, not resolved to the 40-odd actions it covers;
* know what your resources are. ``Resource: "*"`` on an action that genuinely
  has no resource-level permissions (``xray:PutTraceSegments``) is reported
  with ``confidence: needs_context`` rather than asserted as a defect.

Findings therefore carry an explicit ``confidence``:

``confirmed``
    The pattern is present in the document and is a defect in essentially any
    context -- ``"Action": "*"`` with ``"Resource": "*"``, for example.
``needs_context``
    The pattern is present but whether it is a defect depends on information
    this tool does not have. These are review prompts, not verdicts, and they
    never cause a non-zero exit on their own.

USAGE
-----
    # Single document, human-readable
    python security-automation/iam_policy_checker.py \\
        --input sample-data/sample-policy.json

    # Every policy document in the Terraform tree, JSON report, CI gating
    python security-automation/iam_policy_checker.py \\
        --input-dir infrastructure/terraform/policies \\
        --output reports/iam-findings.json \\
        --format both \\
        --fail-on high

    # Policies extracted from a Terraform plan
    terraform show -json tfplan > plan.json
    python security-automation/iam_policy_checker.py --terraform-plan plan.json

    # From a pipe
    aws iam get-role-policy --role-name r --policy-name p \\
        --query PolicyDocument --output json \\
      | python security-automation/iam_policy_checker.py --stdin

EXIT CODES
----------
0   No findings at or above the ``--fail-on`` severity.
1   One or more blocking findings (``confirmed`` only, at or above
    ``--fail-on``).
2   Usage or input error -- unreadable file, malformed JSON, no input.

Exit code 2 is distinct from 1 on purpose: a CI job must be able to tell
"this policy is bad" from "the scanner could not run", because treating a
broken scanner as a pass is how a gate silently stops gating.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

TOOL_NAME = "iam-policy-checker"


# ---------------------------------------------------------------------------
# Severity and confidence
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Finding severity, ordered by :data:`SEVERITY_RANK`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class Confidence(StrEnum):
    """How much interpretation a finding requires."""

    #: The pattern is a defect in essentially any context.
    CONFIRMED = "confirmed"
    #: Whether this is a defect depends on information the tool lacks.
    NEEDS_CONTEXT = "needs_context"


# ---------------------------------------------------------------------------
# Action catalogues
#
# These lists are deliberately short and curated rather than exhaustive. A
# 10,000-entry generated list would be unreviewable, and the point of these is
# that a human can read them and agree or disagree.
# ---------------------------------------------------------------------------

#: Actions that let a principal grant itself (or something else) more
#: permission. Any one of these is a privilege-escalation primitive.
PRIVILEGE_ESCALATION_ACTIONS: frozenset[str] = frozenset(
    {
        "iam:attachgrouppolicy",
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:createpolicyversion",
        "iam:createrole",
        "iam:createuser",
        "iam:deleterolepermissionsboundary",
        "iam:deleteuserpermissionsboundary",
        "iam:passrole",
        "iam:putgrouppolicy",
        "iam:putrolepolicy",
        "iam:putuserpolicy",
        "iam:setdefaultpolicyversion",
        "iam:updateassumerolepolicy",
        "iam:updateloginprofile",
        "sts:assumerole",
        "sts:getfederationtoken",
        # Changing function code or configuration runs arbitrary code as the
        # function's execution role, which is PassRole by another name.
        "lambda:updatefunctioncode",
        "lambda:updatefunctionconfiguration",
        "lambda:createfunction",
        "lambda:addpermission",
        "lambda:invokefunction",
        # Equivalent escalation paths through other compute.
        "glue:updatedevendpoint",
        "cloudformation:createstack",
        "codebuild:createproject",
        "ec2:runinstances",
        "ssm:sendcommand",
        "ssm:startsession",
    }
)

#: Actions that read data in bulk or read secrets. On ``Resource: "*"`` these
#: are a data-exfiltration capability.
DATA_ACCESS_ACTIONS: frozenset[str] = frozenset(
    {
        "s3:getobject",
        "s3:listbucket",
        "dynamodb:scan",
        "dynamodb:getitem",
        "dynamodb:batchgetitem",
        "dynamodb:query",
        "dynamodb:exporttablepointintime",
        "secretsmanager:getsecretvalue",
        "ssm:getparameter",
        "ssm:getparameters",
        "ssm:getparametersbypath",
        "kms:decrypt",
        "rds:downloaddblogfileportion",
        "logs:getlogevents",
        "logs:filterlogevents",
        "cognito-idp:listusers",
        "cognito-idp:adminGetUser".lower(),
    }
)

#: Actions that destroy data or disable the ability to investigate.
DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset(
    {
        "dynamodb:deletetable",
        "dynamodb:deleteitem",
        "dynamodb:deletebackup",
        "s3:deleteobject",
        "s3:deletebucket",
        "kms:scheduleKeyDeletion".lower(),
        "kms:disablekey",
        # Disabling or deleting the audit trail. Treated as destructive
        # because it removes the evidence of everything else.
        "cloudtrail:deletetrail",
        "cloudtrail:stoplogging",
        "cloudtrail:updatetrail",
        "logs:deleteloggroup",
        "logs:deletelogstream",
        "logs:putretentionpolicy",
        "config:deleteconfigurationrecorder",
        "config:stopconfigurationrecorder",
        "guardduty:deletedetector",
        "securityhub:disablesecurityhub",
        "ec2:terminateinstances",
        "rds:deletedbinstance",
    }
)

#: Actions that genuinely do not support resource-level permissions, so
#: ``Resource: "*"`` is the only possible value. Flagging these as a wildcard
#: defect produces noise that trains people to ignore the tool.
ACTIONS_WITHOUT_RESOURCE_SCOPE: frozenset[str] = frozenset(
    {
        "xray:puttracesegments",
        "xray:puttelemetryrecords",
        "cloudwatch:putmetricdata",
        "logs:describeloggroups",
        "logs:createloggroup",
        "sts:getcalleridentity",
        "ec2:describeinstances",
        "ec2:describeregions",
        "ec2:describenetworkinterfaces",
        "dynamodb:listtables",
        "s3:listallmybuckets",
        "kms:listaliases",
        "iam:listroles",
    }
)

#: Service principals for which a condition-less trust policy is a
#: confused-deputy risk: the service acts on behalf of *any* customer, so
#: without an ``aws:SourceAccount``/``aws:SourceArn`` condition another
#: account can induce it to assume your role.
CONFUSED_DEPUTY_SERVICES: frozenset[str] = frozenset(
    {
        "s3.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "sns.amazonaws.com",
        "sqs.amazonaws.com",
        "events.amazonaws.com",
        "config.amazonaws.com",
        "cloudwatch.amazonaws.com",
        "logs.amazonaws.com",
        "lambda.amazonaws.com",
        "apigateway.amazonaws.com",
        "secretsmanager.amazonaws.com",
    }
)

#: Condition keys that meaningfully narrow a wildcard principal.
RESTRICTING_CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principalaccount",
        "aws:principalarn",
        "aws:sourceip",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "kms:viaservice",
        "aws:resourceaccount",
        "aws:userid",
    }
)

#: Matches a Terraform ``templatefile``/``${}`` placeholder. These appear in
#: the policy templates under `infrastructure/terraform/policies/`; they are
#: concrete ARNs at apply time, so they must not be mistaken for wildcards.
TEMPLATE_PLACEHOLDER = re.compile(r"\$\{[^}]+\}")


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule match against one policy statement."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    source: str
    statement_sid: str
    statement_index: int
    description: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        payload = asdict(self)
        payload["severity"] = str(self.severity)
        payload["confidence"] = str(self.confidence)
        return payload

    @property
    def is_blocking(self) -> bool:
        """Only ``confirmed`` findings can fail a build.

        A ``needs_context`` finding is a review prompt. Gating on those would
        force engineers to suppress things to ship, and a tool whose output is
        routinely suppressed has stopped being a control.
        """
        return self.confidence is Confidence.CONFIRMED


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """A policy document plus where it came from."""

    source: str
    document: dict[str, Any]


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    """Coerce an IAM field that may be a scalar or a list into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _strings(value: Any) -> list[str]:
    """Coerce a field into a list of strings, dropping non-strings."""
    return [item for item in _as_list(value) if isinstance(item, str)]


def _normalise_action(action: str) -> str:
    """Lower-case an action for comparison against the catalogues."""
    return action.strip().lower()


def _is_wildcard(value: str) -> bool:
    """True when the value is a bare ``*``."""
    return value.strip() == "*"


def _contains_placeholder(value: str) -> bool:
    """True when the value contains a Terraform interpolation placeholder."""
    return bool(TEMPLATE_PLACEHOLDER.search(value))


def _action_matches_catalogue(action: str, catalogue: frozenset[str]) -> list[str]:
    """Return catalogue entries an action grants.

    Handles three shapes:

    * exact match -- ``iam:PassRole``;
    * service wildcard -- ``iam:*`` grants every ``iam:`` entry;
    * prefix wildcard -- ``iam:Put*`` grants ``iam:PutRolePolicy`` etc.

    Full wildcard (``*``) is handled by its own rule, so it is not expanded
    here -- otherwise one ``"Action": "*"`` would emit a finding for every
    catalogue entry and bury the real one.
    """
    normalised = _normalise_action(action)
    if normalised == "*":
        return []

    if normalised.endswith(":*"):
        service = normalised[:-1]
        return sorted(entry for entry in catalogue if entry.startswith(service))

    if normalised.endswith("*"):
        prefix = normalised[:-1]
        return sorted(entry for entry in catalogue if entry.startswith(prefix))

    return [normalised] if normalised in catalogue else []


def _condition_keys(statement: dict[str, Any]) -> set[str]:
    """Return every condition key referenced by a statement, lower-cased."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return set()

    keys: set[str] = set()
    for operands in condition.values():
        if isinstance(operands, dict):
            keys.update(key.lower() for key in operands)
    return keys


def _has_restricting_condition(statement: dict[str, Any]) -> bool:
    """True when the statement carries a condition that narrows scope.

    Presence-based, not semantic: this tool cannot tell a genuinely
    restrictive condition from a decorative one.
    """
    return bool(_condition_keys(statement) & RESTRICTING_CONDITION_KEYS)


# ---------------------------------------------------------------------------
# Rules
#
# Every rule is a function taking (statement, index, source) and yielding
# Findings. Keeping them separate and pure makes each one individually
# testable and makes adding a rule a self-contained change.
# ---------------------------------------------------------------------------

RULES_DOCUMENTATION: list[dict[str, str]] = [
    {
        "id": "IAM001",
        "title": "Administrative wildcard (Action:* on Resource:*)",
        "severity": "critical",
        "summary": "Allow of every action on every resource -- equivalent to AdministratorAccess.",
    },
    {
        "id": "IAM002",
        "title": "Service-level wildcard action",
        "severity": "high",
        "summary": (
            "Allow of e.g. dynamodb:* grants destructive and "
            "bulk-read actions the workload does not use."
        ),
    },
    {
        "id": "IAM003",
        "title": "Unscoped resource",
        "severity": "high",
        "summary": "Resource:* on actions that do support resource-level permissions.",
    },
    {
        "id": "IAM004",
        "title": "Privilege-escalation action granted",
        "severity": "high",
        "summary": (
            "Actions such as iam:PassRole or lambda:UpdateFunctionCode "
            "let the principal acquire more permission."
        ),
    },
    {
        "id": "IAM005",
        "title": "Bulk data or secret access on an unscoped resource",
        "severity": "high",
        "summary": (
            "Read actions such as s3:GetObject or secretsmanager:GetSecretValue with Resource:*."
        ),
    },
    {
        "id": "IAM006",
        "title": "Allow combined with NotAction or NotResource",
        "severity": "medium",
        "summary": (
            "Inverted matching grants everything except a list, "
            "so new AWS actions are granted by default."
        ),
    },
    {
        "id": "IAM007",
        "title": "Wildcard principal without a restricting condition",
        "severity": "critical",
        "summary": (
            "Principal:* in a resource or trust policy exposes the resource to every AWS account."
        ),
    },
    {
        "id": "IAM008",
        "title": "Service trust without a confused-deputy condition",
        "severity": "medium",
        "summary": "A service principal may be induced by another customer to assume the role.",
    },
    {
        "id": "IAM009",
        "title": "Destructive or audit-disabling action granted",
        "severity": "medium",
        "summary": (
            "Delete/Stop actions, including those that disable CloudTrail or delete log groups."
        ),
    },
    {
        "id": "IAM010",
        "title": "Statement has no Sid",
        "severity": "info",
        "summary": "An unnamed statement is harder to review, reference in an incident, or test.",
    },
    {
        "id": "IAM011",
        "title": "Missing or unexpected policy Version",
        "severity": "low",
        "summary": (
            "Version must be 2012-10-17; the 2008 version does not support policy variables."
        ),
    },
]


def rule_admin_wildcard(statement: dict[str, Any], index: int, source: str) -> Iterator[Finding]:
    """IAM001: ``Action: *`` together with ``Resource: *`` on an Allow."""
    if statement.get("Effect") != "Allow":
        return

    actions = _strings(statement.get("Action"))
    resources = _strings(statement.get("Resource"))

    if any(_is_wildcard(a) for a in actions) and (
        not resources or any(_is_wildcard(r) for r in resources)
    ):
        yield Finding(
            rule_id="IAM001",
            title="Administrative wildcard permission",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                "This statement allows every action on every resource. It is equivalent to "
                "attaching AdministratorAccess. Any compromise of this principal is a total "
                "compromise of everything it can reach, and the policy provides no information "
                "about what the workload actually needs."
            ),
            evidence={"Effect": "Allow", "Action": actions, "Resource": resources or ["<absent>"]},
            remediation=(
                "Enumerate the specific actions the workload calls and the specific ARNs it "
                "calls them on. Start from the application's own data-access code, not from a "
                "managed policy. If the set is genuinely unknown, run in a non-production "
                "account with CloudTrail and build the policy from observed calls."
            ),
            references=[
                "CWE-732: Incorrect Permission Assignment for Critical Resource",
                "CWE-250: Execution with Unnecessary Privileges",
                "AWS IAM best practices: apply least-privilege permissions",
            ],
        )


def rule_service_wildcard_action(
    statement: dict[str, Any], index: int, source: str
) -> Iterator[Finding]:
    """IAM002: a service-level wildcard such as ``dynamodb:*``."""
    if statement.get("Effect") != "Allow":
        return

    for action in _strings(statement.get("Action")):
        normalised = _normalise_action(action)
        if normalised == "*" or not normalised.endswith(":*"):
            continue

        service = normalised.split(":", 1)[0]
        implied_destructive = _action_matches_catalogue(action, DESTRUCTIVE_ACTIONS)
        implied_bulk_read = _action_matches_catalogue(action, DATA_ACCESS_ACTIONS)

        yield Finding(
            rule_id="IAM002",
            title=f"Service-level wildcard action: {action}",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                f"'{action}' grants every current and future action in the {service} service. "
                "That includes actions the workload does not use today and actions AWS has not "
                "shipped yet -- the grant silently widens with every service release. "
                + (
                    f"It currently implies destructive actions: {', '.join(implied_destructive)}. "
                    if implied_destructive
                    else ""
                )
                + (
                    f"It currently implies bulk-read actions: {', '.join(implied_bulk_read)}."
                    if implied_bulk_read
                    else ""
                )
            ),
            evidence={
                "Action": action,
                "implied_destructive_actions": implied_destructive,
                "implied_data_access_actions": implied_bulk_read,
            },
            remediation=(
                f"Replace '{action}' with the individual {service} actions the code calls. "
                "For this project's support API that is GetItem, PutItem and Query -- nothing "
                "else. Any action not listed fails with AccessDenied, which forces a new "
                "permission through review instead of letting it arrive silently."
            ),
            references=["CWE-732", "OWASP ASVS V1.4 Access Control Architecture"],
        )


def rule_unscoped_resource(statement: dict[str, Any], index: int, source: str) -> Iterator[Finding]:
    """IAM003: ``Resource: "*"`` where resource-level scoping is possible."""
    if statement.get("Effect") != "Allow":
        return

    resources = _strings(statement.get("Resource"))
    if not any(_is_wildcard(r) for r in resources):
        return

    actions = _strings(statement.get("Action"))
    # IAM001 already covers Action:* with Resource:*.
    if any(_is_wildcard(a) for a in actions):
        return

    scopable: list[str] = []
    unscopable: list[str] = []
    for action in actions:
        if _normalise_action(action) in ACTIONS_WITHOUT_RESOURCE_SCOPE:
            unscopable.append(action)
        else:
            scopable.append(action)

    if not scopable:
        # Every action genuinely requires Resource:*. Report it so a reviewer
        # can confirm, but do not assert a defect and do not block.
        yield Finding(
            rule_id="IAM003",
            title="Unscoped resource on actions that do not support scoping",
            severity=Severity.INFO,
            confidence=Confidence.NEEDS_CONTEXT,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                "This statement uses Resource:*, but every action listed is one that AWS does "
                "not support resource-level permissions for, so there is no narrower value. "
                "Confirm the action list is minimal and consider adding an aws:SourceAccount or "
                "similar condition to bound the grant."
            ),
            evidence={"Action": actions, "actions_without_resource_scope": unscopable},
            remediation=(
                "No resource scoping is available. Constrain with a Condition instead "
                "(aws:SourceAccount, aws:SourceArn, or a service-specific key) and keep the "
                "action list as short as possible."
            ),
            references=["AWS service authorization reference: resource-level permissions"],
        )
        return

    has_condition = _has_restricting_condition(statement)
    yield Finding(
        rule_id="IAM003",
        title="Unscoped resource (Resource:*)",
        severity=Severity.MEDIUM if has_condition else Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        source=source,
        statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
        statement_index=index,
        description=(
            "This statement allows the listed actions on every resource in the account, and at "
            "least one of those actions does support resource-level permissions. For a "
            "multi-tenant data store this is the difference between 'can read its own table' "
            "and 'can read every table'. "
            + (
                "A condition is present, which narrows the grant, so the severity is reduced -- "
                "but this tool does not evaluate condition semantics, so confirm it is "
                "genuinely restrictive."
                if has_condition
                else "No restricting condition is present."
            )
        ),
        evidence={
            "Action": actions,
            "scopable_actions": scopable,
            "Resource": resources,
            "condition_keys": sorted(_condition_keys(statement)),
        },
        remediation=(
            "Replace '*' with the specific ARNs. Remember that a DynamoDB index is a separate "
            "resource from its table ('<table-arn>/index/<name>'), and that omitting it causes "
            "a runtime AccessDenied rather than a deploy-time error."
        ),
        references=["CWE-732", "CWE-284: Improper Access Control"],
    )


def rule_privilege_escalation(
    statement: dict[str, Any], index: int, source: str
) -> Iterator[Finding]:
    """IAM004: actions that let a principal acquire more permission."""
    if statement.get("Effect") != "Allow":
        return

    resources = _strings(statement.get("Resource"))
    unscoped = not resources or any(_is_wildcard(r) for r in resources)

    for action in _strings(statement.get("Action")):
        matched = _action_matches_catalogue(action, PRIVILEGE_ESCALATION_ACTIONS)
        if not matched:
            continue

        yield Finding(
            rule_id="IAM004",
            title=f"Privilege-escalation action granted: {action}",
            severity=Severity.CRITICAL if unscoped else Severity.HIGH,
            confidence=Confidence.CONFIRMED if unscoped else Confidence.NEEDS_CONTEXT,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                f"'{action}' grants {len(matched)} privilege-escalation primitive(s): "
                f"{', '.join(matched)}. These let the principal obtain permissions beyond the "
                "ones in this policy, which makes any least-privilege analysis of the rest of "
                "the document meaningless. "
                + (
                    "The grant is unscoped (Resource:*), so it applies to every role, function "
                    "or user in the account."
                    if unscoped
                    else "The grant is scoped to specific resources; confirm each one is "
                    "intentional and that none of them can be used to reach a more "
                    "privileged role."
                )
            ),
            evidence={
                "Action": action,
                "matched_escalation_actions": matched,
                "Resource": resources or ["<absent>"],
                "resource_unscoped": unscoped,
            },
            remediation=(
                "Remove the action if the workload does not need it. If it does -- a CI role "
                "that must pass a role, for example -- scope it to the exact target ARNs and "
                "add an iam:PassedToService condition. Consider an explicit Deny for these "
                "actions on any role that should never hold them: an explicit Deny cannot be "
                "overridden by an Allow in another policy."
            ),
            references=[
                "CWE-269: Improper Privilege Management",
                "CWE-250: Execution with Unnecessary Privileges",
            ],
        )


def rule_unscoped_data_access(
    statement: dict[str, Any], index: int, source: str
) -> Iterator[Finding]:
    """IAM005: bulk-read or secret-read actions on an unscoped resource."""
    if statement.get("Effect") != "Allow":
        return

    resources = _strings(statement.get("Resource"))
    if resources and not any(_is_wildcard(r) for r in resources):
        return

    for action in _strings(statement.get("Action")):
        if _is_wildcard(action):
            continue
        matched = _action_matches_catalogue(action, DATA_ACCESS_ACTIONS)
        if not matched:
            continue

        has_condition = _has_restricting_condition(statement)
        yield Finding(
            rule_id="IAM005",
            title=f"Unscoped data or secret access: {action}",
            severity=Severity.MEDIUM if has_condition else Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                f"'{action}' reads data or secrets, and is granted on every resource in the "
                "account. A code-execution bug in this principal becomes an account-wide data "
                "exfiltration capability rather than access to one table or bucket. "
                f"Matched: {', '.join(matched)}."
            ),
            evidence={
                "Action": action,
                "matched_data_actions": matched,
                "Resource": resources or ["<absent>"],
                "condition_keys": sorted(_condition_keys(statement)),
            },
            remediation=(
                "Scope to the specific table, bucket, secret or key ARNs. For kms:Decrypt add a "
                "kms:ViaService condition so the grant only applies to decryption performed by "
                "the intended service. For dynamodb:Scan, consider whether the action is needed "
                "at all -- a key-scoped Query is almost always the right access pattern and is "
                "what keeps tenant isolation a property of the data model."
            ),
            references=["CWE-732", "CWE-200: Exposure of Sensitive Information"],
        )


def rule_inverted_matching(statement: dict[str, Any], index: int, source: str) -> Iterator[Finding]:
    """IAM006: ``Allow`` combined with ``NotAction`` or ``NotResource``."""
    if statement.get("Effect") != "Allow":
        return

    inverted = {key: statement[key] for key in ("NotAction", "NotResource") if key in statement}
    if not inverted:
        return

    yield Finding(
        rule_id="IAM006",
        title=f"Allow with inverted matching ({', '.join(inverted)})",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        source=source,
        statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
        statement_index=index,
        description=(
            "An Allow with NotAction or NotResource grants everything *except* an explicit "
            "list. The grant therefore widens automatically every time AWS ships a new action "
            "or the account gains a new resource, with no policy change and no review. It is "
            "also genuinely hard to reason about during an incident: answering 'can this "
            "principal do X?' requires enumerating everything AWS offers."
        ),
        evidence=inverted,
        remediation=(
            "Rewrite as an Allow listing what is permitted. NotAction is defensible in a Deny "
            "statement (for example, deny everything except a region), but an Allow should "
            "always be an allow-list."
        ),
        references=["CWE-183: Permissive List of Allowed Inputs"],
    )


def rule_wildcard_principal(
    statement: dict[str, Any], index: int, source: str
) -> Iterator[Finding]:
    """IAM007: ``Principal: "*"`` with no restricting condition."""
    if statement.get("Effect") != "Allow":
        return

    principal = statement.get("Principal")
    if principal is None:
        return

    wildcard = False
    if isinstance(principal, str):
        wildcard = _is_wildcard(principal)
    elif isinstance(principal, dict):
        wildcard = any(
            _is_wildcard(value)
            for values in principal.values()
            for value in _as_list(values)
            if isinstance(value, str)
        )

    if not wildcard:
        return

    has_condition = _has_restricting_condition(statement)
    yield Finding(
        rule_id="IAM007",
        title="Wildcard principal in a resource or trust policy",
        severity=Severity.MEDIUM if has_condition else Severity.CRITICAL,
        confidence=Confidence.NEEDS_CONTEXT if has_condition else Confidence.CONFIRMED,
        source=source,
        statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
        statement_index=index,
        description=(
            "This statement allows any AWS principal. In a resource policy that makes the "
            "resource reachable from every AWS account; in a trust policy it means any account "
            "can assume the role. "
            + (
                "A condition is present, which may narrow it to an organization or account -- "
                "but this tool does not evaluate condition semantics, so verify the condition "
                "actually restricts the principal set."
                if has_condition
                else "No restricting condition is present, so the grant really is open to everyone."
            )
        ),
        evidence={
            "Principal": principal,
            "condition_keys": sorted(_condition_keys(statement)),
        },
        remediation=(
            "Name the exact account, role or service principal. If a wildcard is genuinely "
            "required (a public read-only asset, say), constrain it with aws:PrincipalOrgID, "
            "aws:SourceAccount or aws:SourceArn and keep the action list minimal."
        ),
        references=["CWE-284", "CWE-732"],
    )


def rule_confused_deputy(statement: dict[str, Any], index: int, source: str) -> Iterator[Finding]:
    """IAM008: service trust with no ``aws:SourceAccount``/``SourceArn``."""
    if statement.get("Effect") != "Allow":
        return

    actions = {_normalise_action(a) for a in _strings(statement.get("Action"))}
    if not actions & {"sts:assumerole", "sts:assumerolewithwebidentity", "*"}:
        return

    principal = statement.get("Principal")
    if not isinstance(principal, dict):
        return

    services = {
        value.lower()
        for value in _strings(principal.get("Service"))
        if value.lower() in CONFUSED_DEPUTY_SERVICES
    }
    if not services or _has_restricting_condition(statement):
        return

    yield Finding(
        rule_id="IAM008",
        title=f"Service trust without a confused-deputy condition: {', '.join(sorted(services))}",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        source=source,
        statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
        statement_index=index,
        description=(
            "This trust policy lets an AWS service assume the role with no condition tying the "
            "assumption to your account or resource. These services act on behalf of every "
            "customer, so without such a condition another customer may be able to induce the "
            "service to assume this role on their behalf -- the confused-deputy problem."
        ),
        evidence={
            "trusted_services": sorted(services),
            "condition_keys": sorted(_condition_keys(statement)),
        },
        remediation=(
            'Add a condition such as {"StringEquals": {"aws:SourceAccount": "<account-id>"}} '
            'or, better, {"ArnLike": {"aws:SourceArn": "<specific-resource-arn>"}}. '
            "This project's Lambda trust policy in infrastructure/terraform/iam.tf uses "
            "aws:SourceAccount for exactly this reason."
        ),
        references=[
            "CWE-441: Unintended Proxy or Intermediary (Confused Deputy)",
            "AWS: cross-service confused deputy prevention",
        ],
    )


def rule_destructive_actions(
    statement: dict[str, Any], index: int, source: str
) -> Iterator[Finding]:
    """IAM009: destructive or audit-disabling actions."""
    if statement.get("Effect") != "Allow":
        return

    resources = _strings(statement.get("Resource"))
    unscoped = not resources or any(_is_wildcard(r) for r in resources)

    for action in _strings(statement.get("Action")):
        if _is_wildcard(action):
            continue
        matched = _action_matches_catalogue(action, DESTRUCTIVE_ACTIONS)
        if not matched:
            continue

        yield Finding(
            rule_id="IAM009",
            title=f"Destructive or audit-disabling action granted: {action}",
            severity=Severity.HIGH if unscoped else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED if unscoped else Confidence.NEEDS_CONTEXT,
            source=source,
            statement_sid=str(statement.get("Sid", f"<unnamed #{index}>")),
            statement_index=index,
            description=(
                f"'{action}' permits data destruction or disabling of audit infrastructure: "
                f"{', '.join(matched)}. Actions in the second group (CloudTrail, CloudWatch "
                "Logs retention, GuardDuty, Config) are especially significant because they "
                "remove the evidence of everything else an attacker does."
            ),
            evidence={
                "Action": action,
                "matched_destructive_actions": matched,
                "Resource": resources or ["<absent>"],
                "resource_unscoped": unscoped,
            },
            remediation=(
                "Remove the action unless the workload genuinely deletes data. An application "
                "role almost never needs Delete permissions -- deletion is usually an "
                "administrative operation that belongs to a separate, audited role. For "
                "audit-disabling actions, add an explicit Deny so no future policy can "
                "re-enable them."
            ),
            references=["CWE-732", "CWE-778: Insufficient Logging"],
        )


def rule_missing_sid(statement: dict[str, Any], index: int, source: str) -> Iterator[Finding]:
    """IAM010: statement with no ``Sid``."""
    if statement.get("Sid"):
        return

    yield Finding(
        rule_id="IAM010",
        title="Policy statement has no Sid",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        source=source,
        statement_sid=f"<unnamed #{index}>",
        statement_index=index,
        description=(
            "The statement has no Sid. Unnamed statements are harder to review in a pull "
            "request diff, impossible to reference precisely in an incident ticket, and give "
            "tools like this one nothing meaningful to report against."
        ),
        evidence={"statement_index": index},
        remediation=(
            "Add a Sid that states the intent, e.g. 'TicketAndMembershipDataAccess' rather "
            "than 'Statement1'. The Sid is the one place in a policy to record *why* a "
            "permission exists."
        ),
        references=[],
    )


#: Statement-level rules, applied in order.
STATEMENT_RULES = (
    rule_admin_wildcard,
    rule_service_wildcard_action,
    rule_unscoped_resource,
    rule_privilege_escalation,
    rule_unscoped_data_access,
    rule_inverted_matching,
    rule_wildcard_principal,
    rule_confused_deputy,
    rule_destructive_actions,
    rule_missing_sid,
)


def rule_policy_version(document: dict[str, Any], source: str) -> Iterator[Finding]:
    """IAM011: document-level ``Version`` check."""
    version = document.get("Version")
    if version == "2012-10-17":
        return

    yield Finding(
        rule_id="IAM011",
        title=f"Unexpected policy Version: {version!r}",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        source=source,
        statement_sid="<document>",
        statement_index=-1,
        description=(
            "IAM policy documents should declare Version '2012-10-17'. The older "
            "'2008-10-17' version does not support policy variables, which means a condition "
            "written with ${aws:username} silently matches a literal string instead of the "
            "caller -- a condition that looks restrictive and is not. A missing Version "
            "defaults to the 2008 behaviour."
        ),
        evidence={"Version": version},
        remediation='Set "Version": "2012-10-17".',
        references=["AWS IAM JSON policy elements: Version"],
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


class PolicyParseError(ValueError):
    """Raised when input cannot be interpreted as an IAM policy document."""


def analyze_document(policy: PolicyDocument) -> list[Finding]:
    """Run every rule against one policy document."""
    document = policy.document
    findings: list[Finding] = list(rule_policy_version(document, policy.source))

    statements = _as_list(document.get("Statement"))
    if not statements:
        raise PolicyParseError(
            f"{policy.source}: no 'Statement' element found; this does not look like an "
            "IAM policy document."
        )

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise PolicyParseError(
                f"{policy.source}: statement #{index} is {type(statement).__name__}, "
                "expected an object."
            )
        for rule in STATEMENT_RULES:
            findings.extend(rule(statement, index, policy.source))

    return findings


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Order findings most severe first, then deterministically.

    Determinism matters: a CI job that diffs reports between runs needs stable
    ordering, or every run looks like a change.
    """
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK[f.severity],
            f.confidence is not Confidence.CONFIRMED,
            f.source,
            f.statement_index,
            f.rule_id,
            f.title,
        ),
    )


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------


def _coerce_to_documents(payload: Any, source: str) -> list[PolicyDocument]:
    """Interpret parsed JSON as one or more policy documents.

    Accepts the shapes that show up in practice:

    * a policy document;
    * ``{"PolicyDocument": {...}}`` -- ``aws iam get-role-policy`` output;
    * ``{"policy": "<json string>"}`` -- a Terraform state/plan attribute;
    * a list of any of the above.
    """
    documents: list[PolicyDocument] = []

    if isinstance(payload, list):
        for index, item in enumerate(payload):
            documents.extend(_coerce_to_documents(item, f"{source}[{index}]"))
        return documents

    if not isinstance(payload, dict):
        raise PolicyParseError(
            f"{source}: expected an object or array, got {type(payload).__name__}."
        )

    if "Statement" in payload:
        return [PolicyDocument(source=source, document=payload)]

    for wrapper in ("PolicyDocument", "policy_document", "Document"):
        if wrapper in payload:
            return _coerce_to_documents(payload[wrapper], f"{source}:{wrapper}")

    for wrapper in ("policy", "assume_role_policy"):
        value = payload.get(wrapper)
        if isinstance(value, str):
            try:
                return _coerce_to_documents(json.loads(value), f"{source}:{wrapper}")
            except json.JSONDecodeError as exc:
                raise PolicyParseError(f"{source}:{wrapper}: not valid JSON: {exc}") from exc
        if isinstance(value, dict):
            return _coerce_to_documents(value, f"{source}:{wrapper}")

    raise PolicyParseError(
        f"{source}: no policy document found. Expected a 'Statement' element, or a "
        "'PolicyDocument'/'policy' wrapper."
    )


def load_policy_file(path: Path) -> list[PolicyDocument]:
    """Load one JSON file containing one or more policy documents."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyParseError(f"{path}: cannot read file: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"{path}: not valid JSON: {exc}") from exc

    return _coerce_to_documents(payload, str(path))


def load_terraform_plan(path: Path) -> list[PolicyDocument]:
    """Extract IAM policy documents from ``terraform show -json`` output.

    Walks planned values for the attributes that carry a policy document, so
    the checker can gate a plan before it is applied.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyParseError(f"{path}: cannot read Terraform plan JSON: {exc}") from exc

    documents: list[PolicyDocument] = []
    policy_attributes = ("policy", "assume_role_policy", "json")

    def walk_module(module: dict[str, Any]) -> None:
        for resource in module.get("resources", []):
            if not isinstance(resource, dict):
                continue
            address = resource.get("address", resource.get("name", "<unknown>"))
            values = resource.get("values") or {}
            if not isinstance(values, dict):
                continue
            for attribute in policy_attributes:
                raw = values.get(attribute)
                if not isinstance(raw, str) or "Statement" not in raw:
                    continue
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                documents.extend(_coerce_to_documents(parsed, f"{path.name}:{address}.{attribute}"))
        for child in module.get("child_modules", []):
            if isinstance(child, dict):
                walk_module(child)

    root = payload.get("planned_values", {}).get("root_module")
    if isinstance(root, dict):
        walk_module(root)

    prior_root = payload.get("prior_state", {}).get("values", {}).get("root_module")
    if isinstance(prior_root, dict):
        walk_module(prior_root)

    if not documents:
        raise PolicyParseError(
            f"{path}: no IAM policy documents found in the plan. Confirm the plan contains "
            "aws_iam_role_policy / aws_iam_policy resources and was produced with "
            "`terraform show -json`."
        )
    return documents


def discover_policy_files(directory: Path) -> list[Path]:
    """Return every ``*.json`` file in a directory tree, sorted."""
    if not directory.is_dir():
        raise PolicyParseError(f"{directory}: not a directory.")
    return sorted(directory.rglob("*.json"))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def build_report(
    findings: Sequence[Finding],
    *,
    sources: Sequence[str],
    fail_on: Severity,
    documents_scanned: int,
) -> dict[str, Any]:
    """Assemble the machine-readable report."""
    ordered = sort_findings(findings)
    blocking = [
        f for f in ordered if f.is_blocking and SEVERITY_RANK[f.severity] >= SEVERITY_RANK[fail_on]
    ]

    by_severity = {str(s): 0 for s in Severity}
    for finding in ordered:
        by_severity[str(finding.severity)] += 1

    by_rule: dict[str, int] = {}
    for finding in ordered:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1

    return {
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "scan": {
            "sources": list(sources),
            "documents_scanned": documents_scanned,
            "fail_on_severity": str(fail_on),
        },
        "summary": {
            "total_findings": len(ordered),
            "blocking_findings": len(blocking),
            "by_severity": by_severity,
            "by_confidence": {
                "confirmed": sum(1 for f in ordered if f.confidence is Confidence.CONFIRMED),
                "needs_context": sum(
                    1 for f in ordered if f.confidence is Confidence.NEEDS_CONTEXT
                ),
            },
            "by_rule": dict(sorted(by_rule.items())),
        },
        "findings": [f.to_dict() for f in ordered],
        "limitations": [
            "Pattern-based document analysis only; does not compute effective permissions.",
            "Does not combine identity policies, resource policies, permissions boundaries, "
            "session policies, SCPs or RCPs.",
            "Detects the presence of Condition blocks but does not evaluate their semantics.",
            "Does not expand action wildcards against the real AWS action catalogue.",
            "Not a substitute for AWS IAM Access Analyzer or a policy simulator.",
        ],
    }


_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH    ",
    Severity.MEDIUM: "MEDIUM  ",
    Severity.LOW: "LOW     ",
    Severity.INFO: "INFO    ",
}


def render_text(report: dict[str, Any], *, verbose: bool = False) -> str:
    """Render the report for a human reading CI output."""
    lines: list[str] = []
    summary = report["summary"]
    scan = report["scan"]

    lines.append("=" * 78)
    lines.append(f"IAM Policy Security Analyzer v{report['tool_version']}")
    lines.append("=" * 78)
    lines.append(f"Documents scanned : {scan['documents_scanned']}")
    lines.append(f"Sources           : {', '.join(scan['sources']) or '<stdin>'}")
    lines.append(f"Gating severity   : {scan['fail_on_severity']}")
    lines.append("")

    counts = summary["by_severity"]
    lines.append(
        "Findings: "
        + "  ".join(
            f"{name}={counts[name]}"
            for name in ("critical", "high", "medium", "low", "info")
            if counts[name]
        )
        or "Findings: none"
    )
    lines.append(
        f"Confirmed: {summary['by_confidence']['confirmed']}   "
        f"Needs context: {summary['by_confidence']['needs_context']}   "
        f"Blocking: {summary['blocking_findings']}"
    )
    lines.append("")

    if not report["findings"]:
        lines.append("No findings. Every statement enumerated its actions and scoped its")
        lines.append("resources, and no privilege-escalation or wildcard pattern was present.")
        lines.append("")
        return "\n".join(lines)

    for finding in report["findings"]:
        severity = Severity(finding["severity"])
        marker = "!" if finding["confidence"] == "confirmed" else "?"
        lines.append(
            f"[{_SEVERITY_LABEL[severity]}] {marker} {finding['rule_id']}  {finding['title']}"
        )
        lines.append(f"    source     : {finding['source']}")
        lines.append(f"    statement  : {finding['statement_sid']}")
        lines.append(f"    confidence : {finding['confidence']}")
        lines.append(f"    issue      : {_wrap(finding['description'], 70, 17)}")
        lines.append(f"    fix        : {_wrap(finding['remediation'], 70, 17)}")
        if verbose:
            lines.append(f"    evidence   : {json.dumps(finding['evidence'], indent=2)[:1200]}")
            for reference in finding["references"]:
                lines.append(f"    reference  : {reference}")
        lines.append("")

    lines.append("-" * 78)
    lines.append("Legend: '!' = confirmed pattern (can fail the build)")
    lines.append("        '?' = needs context (review prompt, never blocks)")
    lines.append("")
    lines.append("Limitations (read these before trusting a clean result):")
    for limitation in report["limitations"]:
        lines.append(f"  - {_wrap(limitation, 72, 4)}")
    lines.append("")

    return "\n".join(lines)


def _wrap(text: str, width: int, indent: int) -> str:
    """Wrap text to ``width``, continuing lines at ``indent`` spaces."""
    import textwrap

    wrapped = textwrap.wrap(text, width=width)
    if not wrapped:
        return ""
    pad = " " * indent
    return ("\n" + pad).join(wrapped)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="iam_policy_checker.py",
        description=(
            "Find risky patterns in IAM policy documents. Offline, deterministic, no AWS "
            "credentials required. NOT an IAM policy evaluator -- see --list-rules and the "
            "'limitations' section of the JSON report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  no blocking findings\n"
            "  1  one or more confirmed findings at or above --fail-on\n"
            "  2  usage or input error (unreadable file, bad JSON, no input)\n"
        ),
    )

    source = parser.add_argument_group("input (choose at least one)")
    source.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="FILE",
        help="Policy JSON file. Repeatable.",
    )
    source.add_argument(
        "--input-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="Directory to scan recursively for *.json. Repeatable.",
    )
    source.add_argument(
        "--terraform-plan",
        metavar="FILE",
        help="Extract policies from `terraform show -json` output.",
    )
    source.add_argument(
        "--stdin",
        action="store_true",
        help="Read a policy document from standard input.",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--output",
        metavar="FILE",
        help="Write the JSON report here (parent directories are created).",
    )
    output.add_argument(
        "--format",
        choices=("text", "json", "both"),
        default="text",
        help="Console output format. Default: text.",
    )
    output.add_argument(
        "--verbose",
        action="store_true",
        help="Include evidence and references in text output.",
    )
    output.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output; useful with --output.",
    )

    gating = parser.add_argument_group("gating")
    gating.add_argument(
        "--fail-on",
        choices=[str(s) for s in Severity],
        default="high",
        help=(
            "Lowest severity that causes exit 1. Only 'confirmed' findings ever block. "
            "Default: high."
        ),
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print the rule catalogue and exit.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")

    return parser


def _print_rules() -> None:
    """Print the rule catalogue."""
    print(f"{TOOL_NAME} {__version__} -- rule catalogue\n")
    for rule in RULES_DOCUMENTATION:
        print(f"  {rule['id']}  [{rule['severity'].upper():<8}] {rule['title']}")
        print(f"          {_wrap(rule['summary'], 68, 10)}")
        print()


def collect_documents(args: argparse.Namespace) -> tuple[list[PolicyDocument], list[str]]:
    """Load every policy document named by the arguments."""
    documents: list[PolicyDocument] = []
    sources: list[str] = []

    for raw_path in args.input:
        path = Path(raw_path)
        documents.extend(load_policy_file(path))
        sources.append(str(path))

    for raw_dir in args.input_dir:
        directory = Path(raw_dir)
        files = discover_policy_files(directory)
        if not files:
            raise PolicyParseError(f"{directory}: contains no .json files.")
        for path in files:
            documents.extend(load_policy_file(path))
        sources.append(f"{directory}/**/*.json ({len(files)} files)")

    if args.terraform_plan:
        path = Path(args.terraform_plan)
        documents.extend(load_terraform_plan(path))
        sources.append(f"{path} (terraform plan)")

    if args.stdin:
        raw = sys.stdin.read()
        if not raw.strip():
            raise PolicyParseError("stdin: no input received.")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyParseError(f"stdin: not valid JSON: {exc}") from exc
        documents.extend(_coerce_to_documents(payload, "<stdin>"))
        sources.append("<stdin>")

    return documents, sources


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _print_rules()
        return 0

    if not (args.input or args.input_dir or args.terraform_plan or args.stdin):
        parser.print_usage(sys.stderr)
        print(
            "error: no input. Use --input, --input-dir, --terraform-plan or --stdin.",
            file=sys.stderr,
        )
        return 2

    fail_on = Severity(args.fail_on)

    try:
        documents, sources = collect_documents(args)
        findings: list[Finding] = []
        for document in documents:
            findings.extend(analyze_document(document))
    except PolicyParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(
        findings,
        sources=sources,
        fail_on=fail_on,
        documents_scanned=len(documents),
    )

    if args.output:
        destination = Path(args.output)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write report to {destination}: {exc}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"Report written to {destination}")

    if not args.quiet:
        if args.format in ("text", "both"):
            print(render_text(report, verbose=args.verbose))
        if args.format in ("json", "both"):
            print(json.dumps(report, indent=2))

    return 1 if report["summary"]["blocking_findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
