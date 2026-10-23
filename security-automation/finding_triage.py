#!/usr/bin/env python3
"""Security Finding Triage and Risk Prioritization Engine.

Takes findings from several tools, normalizes them into one shape, scores them
against a configurable risk model, deduplicates, assigns an owner, tracks
status across runs, and emits a JSON report plus a Markdown report a developer
will actually read.

THE PROBLEM THIS SOLVES
-----------------------
Four scanners produce four schemas and four incompatible severity scales. A
"HIGH" from Bandit (a pattern match in one file) and a "HIGH" from Checkov (an
unencrypted data store) are not the same risk, and a long list sorted by a
tool's own label is not a work queue. Worse, the same defect reported by two
tools looks like two problems, and nobody can tell what is new since last
week.

So this tool does five things that a raw scanner dump cannot:

1. **Normalizes** every input to one schema (``schemas/normalized-finding.schema.json``)
   with one severity scale.
2. **Scores** risk from severity, risk category, resource criticality and
   context tags, with every weight in a reviewable config file rather than in
   someone's head.
3. **Deduplicates** on a stable fingerprint, so the same defect found by two
   tools is one item with two sources.
4. **Assigns an owner** from first-match-wins rules, because an unowned
   finding is an unfixed finding.
5. **Tracks status across runs** via ``--previous``, so a report can say what
   is new, what is still open and how long it has been open -- and findings
   that have disappeared are marked resolved rather than silently dropped.

DETERMINISM
-----------
Given the same inputs and config, the output is byte-identical apart from the
``generated_at`` timestamp (use ``--now`` to pin that too). Fingerprints are
content-derived, not positional, so adding a finding does not renumber the
others. This matters because a CI job that diffs reports between runs needs
stable output, or every run looks like a change.

USAGE
-----
    # Hand-written or previously-normalized findings
    python security-automation/finding_triage.py \\
        --input sample-data/findings.json \\
        --output reports/triage-report.json \\
        --markdown reports/triage-report.md

    # Aggregate several scanners, auto-detecting each format
    python security-automation/finding_triage.py \\
        --input reports/checkov.json \\
        --input reports/bandit.json \\
        --input reports/iam-findings.json \\
        --output reports/triage-report.json

    # Track status across runs
    python security-automation/finding_triage.py \\
        --input reports/current.json \\
        --previous reports/triage-report.json \\
        --output reports/triage-report.json

    # Filter: only open P0/P1 owned by application-security
    python security-automation/finding_triage.py \\
        --input sample-data/findings.json \\
        --min-severity high --status open --owner application-security

    # Transform Security Hub ASFF
    python security-automation/finding_triage.py \\
        --input sample-data/securityhub-findings.json --format securityhub

EXIT CODES
----------
0   Ran successfully; no findings at or above ``--fail-on`` (default: never
    fails, because triage is a reporting step, not a gate).
1   Findings at or above ``--fail-on`` are present.
2   Usage or input error -- unreadable file, malformed JSON, schema violation
    with ``--strict``.

Exit 2 is distinct from 1 on purpose: CI must be able to tell "there is risk"
from "the tool could not run".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

TOOL_NAME = "finding-triage"

_MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = _MODULE_DIR / "triage_config.json"
SCHEMA_PATH = _MODULE_DIR / "schemas" / "normalized-finding.schema.json"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(reversed(SEVERITIES), 1)}

VALID_STATUSES = frozenset({"open", "in_progress", "resolved", "accepted_risk", "false_positive"})
#: Statuses that represent work still outstanding.
OPEN_STATUSES = frozenset({"open", "in_progress"})

VALID_CATEGORIES = frozenset(
    {
        "iam",
        "authentication",
        "authorization",
        "data_protection",
        "encryption",
        "network",
        "logging",
        "monitoring",
        "configuration",
        "dependency",
        "application",
        "secrets",
        "availability",
        "other",
    }
)

PRIORITY_ORDER = ("P0", "P1", "P2", "P3", "P4")


class TriageInputError(ValueError):
    """Raised when input cannot be interpreted as findings."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into ``base``, returning a new dict."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass(frozen=True)
class TriageConfig:
    """Resolved configuration for scoring and owner assignment."""

    raw: dict[str, Any]

    @classmethod
    def load(cls, path: Path | None = None) -> TriageConfig:
        """Load the default config, merging an override file over it."""
        try:
            defaults = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TriageInputError(
                f"{DEFAULT_CONFIG_PATH}: default configuration is missing or invalid: {exc}"
            ) from exc

        if path is None:
            return cls(raw=defaults)

        try:
            override = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TriageInputError(f"{path}: cannot read configuration: {exc}") from exc

        if not isinstance(override, dict):
            raise TriageInputError(f"{path}: configuration must be a JSON object.")

        return cls(raw=_deep_merge(defaults, override))

    # -- accessors ----------------------------------------------------------

    @property
    def severity_base_score(self) -> dict[str, float]:
        """Base score per normalized severity."""
        return {
            key: float(value)
            for key, value in self.raw.get("severity_base_score", {}).items()
            if not key.startswith("_")
        }

    @property
    def category_weights(self) -> dict[str, float]:
        """Multiplier per risk category."""
        return {
            key: float(value)
            for key, value in self.raw.get("category_weights", {}).items()
            if not key.startswith("_")
        }

    @property
    def tag_modifiers(self) -> dict[str, float]:
        """Multiplier per recognised context tag."""
        return {
            key: float(value)
            for key, value in self.raw.get("tag_modifiers", {}).items()
            if not key.startswith("_")
        }

    @property
    def resource_rules(self) -> list[dict[str, Any]]:
        """Resource-criticality rules, in evaluation order."""
        return list(self.raw.get("resource_criticality", {}).get("rules", []))

    @property
    def resource_default_weight(self) -> float:
        """Weight for a resource matching no rule."""
        return float(self.raw.get("resource_criticality", {}).get("default_weight", 1.0))

    @property
    def priority_thresholds(self) -> list[tuple[str, float]]:
        """Priority bands, highest threshold first."""
        raw = self.raw.get("priority_thresholds", {})
        bands = [
            (name, float(value))
            for name, value in raw.items()
            if not name.startswith("_") and name in PRIORITY_ORDER
        ]
        return sorted(bands, key=lambda item: item[1], reverse=True)

    @property
    def sla_days(self) -> dict[str, int]:
        """Target resolution window per priority, in days."""
        return {
            key: int(value)
            for key, value in self.raw.get("sla_days", {}).items()
            if not key.startswith("_")
        }

    @property
    def owner_rules(self) -> list[dict[str, Any]]:
        """Owner-assignment rules, in evaluation order."""
        return list(self.raw.get("owner_rules", {}).get("rules", []))

    @property
    def default_owner(self) -> str:
        """Owner for a finding matching no rule."""
        return str(
            self.raw.get("owner_rules", {}).get("default_owner", "security-engineering-triage")
        )

    @property
    def severity_aliases(self) -> dict[str, str]:
        """Tool-specific severity label -> normalized severity."""
        return {
            key.lower(): str(value)
            for key, value in self.raw.get("severity_aliases", {}).items()
            if not key.startswith("_")
        }


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalized, scored finding."""

    finding_id: str
    fingerprint: str
    source: str
    resource: str
    category: str
    severity: str
    title: str
    description: str = ""
    status: str = "open"
    first_observed: str = ""
    last_observed: str = ""
    remediation: str = ""
    owner: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    environment: str = ""

    # Derived during triage.
    risk_score: float = 0.0
    priority: str = "P4"
    score_factors: tuple[tuple[str, float], ...] = ()
    merged_sources: tuple[str, ...] = ()
    occurrence_count: int = 1
    is_new: bool = True
    age_days: int = 0
    overdue: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation with stable key order."""
        payload = asdict(self)
        for key in ("references", "tags", "merged_sources"):
            payload[key] = list(payload[key])
        payload["score_factors"] = dict(self.score_factors)
        return payload

    @property
    def is_open(self) -> bool:
        """True when the finding still represents outstanding work."""
        return self.status in OPEN_STATUSES


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_severity(raw: Any, config: TriageConfig) -> tuple[str, str | None]:
    """Map a tool's severity label onto the normalized scale.

    Returns ``(severity, warning)``. ``warning`` is non-None when the label was
    not recognised, so an unmapped label shows up in the report rather than
    being silently downgraded to medium.

    Numeric scores are treated as CVSS-like 0-10 (and 0-100 when above 10).
    """
    if raw is None:
        return "medium", "severity missing; defaulted to medium"

    if isinstance(raw, bool):
        return "medium", f"severity was a boolean ({raw}); defaulted to medium"

    if isinstance(raw, (int, float)):
        score = float(raw)
        if score > 10:
            score = score / 10.0
        if score >= 9.0:
            return "critical", None
        if score >= 7.0:
            return "high", None
        if score >= 4.0:
            return "medium", None
        if score > 0:
            return "low", None
        return "info", None

    if not isinstance(raw, str):
        return "medium", f"severity was {type(raw).__name__}; defaulted to medium"

    label = raw.strip().lower()
    if label in SEVERITIES:
        return label, None

    mapped = config.severity_aliases.get(label)
    if mapped in SEVERITIES:
        return mapped, None

    return "medium", f"unrecognised severity label {raw!r}; defaulted to medium"


def normalize_category(raw: Any) -> tuple[str, str | None]:
    """Map a category onto the allowed set, falling back to ``other``."""
    if not isinstance(raw, str) or not raw.strip():
        return "other", "category missing; defaulted to other"

    label = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if label in VALID_CATEGORIES:
        return label, None

    # Common synonyms seen in real scanner output.
    synonyms = {
        "access_control": "authorization",
        "identity": "iam",
        "permissions": "iam",
        "crypto": "encryption",
        "cryptography": "encryption",
        "kms": "encryption",
        "privacy": "data_protection",
        "data": "data_protection",
        "storage": "data_protection",
        "audit": "logging",
        "observability": "monitoring",
        "supply_chain": "dependency",
        "dependencies": "dependency",
        "vulnerability": "dependency",
        "code": "application",
        "general": "other",
        "backup_and_recovery": "availability",
        "resilience": "availability",
        "credentials": "secrets",
        "secret": "secrets",
    }
    if label in synonyms:
        return synonyms[label], None

    return "other", f"unrecognised category {raw!r}; defaulted to other"


def normalize_status(raw: Any) -> tuple[str, str | None]:
    """Map a status onto the allowed set, falling back to ``open``."""
    if not isinstance(raw, str) or not raw.strip():
        return "open", None

    label = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if label in VALID_STATUSES:
        return label, None

    synonyms = {
        "new": "open",
        "active": "open",
        "notified": "open",
        "failed": "open",
        "suppressed": "accepted_risk",
        "accepted": "accepted_risk",
        "risk_accepted": "accepted_risk",
        "wontfix": "accepted_risk",
        "fixed": "resolved",
        "passed": "resolved",
        "closed": "resolved",
        "benign_positive": "false_positive",
        "fp": "false_positive",
        "triaged": "in_progress",
        "in_review": "in_progress",
    }
    if label in synonyms:
        return synonyms[label], None

    return "open", f"unrecognised status {raw!r}; defaulted to open"


def _clean_text(value: Any, limit: int) -> str:
    """Coerce to a single-line string, collapsing whitespace and truncating."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def compute_fingerprint(source: str, category: str, resource: str, title: str) -> str:
    """Return a stable content-derived fingerprint.

    Deliberately excludes severity, status and timestamps: a finding whose
    severity is re-rated, or which is re-observed tomorrow, is the *same*
    finding. Including those would make a re-rating look like a new defect and
    break both deduplication and age tracking.

    ``source`` is included so the same defect reported by two tools produces
    two fingerprints -- the merge step then collapses them on the narrower
    (category, resource, title) key while remembering both sources.
    """
    material = "|".join(part.strip().lower() for part in (source, category, resource, title))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def compute_dedup_key(category: str, resource: str, title: str) -> str:
    """Return the cross-tool deduplication key (source-independent)."""
    material = "|".join(part.strip().lower() for part in (category, resource, title))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def normalize_finding(
    record: Any,
    config: TriageConfig,
    *,
    default_source: str = "unknown",
    now: datetime | None = None,
) -> tuple[Finding, list[str]]:
    """Normalize one raw record into a :class:`Finding`.

    Returns the finding plus any warnings raised during normalization, so a
    sloppy input is visible in the report instead of being silently coerced.
    """
    if not isinstance(record, dict):
        raise TriageInputError(f"finding must be an object, got {type(record).__name__}")

    warnings: list[str] = []
    timestamp = (now or datetime.now(tz=UTC)).isoformat()

    source = _clean_text(record.get("source") or default_source, 64) or default_source
    resource = _clean_text(record.get("resource"), 512)
    title = _clean_text(record.get("title"), 300)

    if not resource:
        resource = "<unspecified>"
        warnings.append("resource missing; recorded as <unspecified>")
    if not title:
        raise TriageInputError(f"finding for resource {resource!r} has no title")

    severity, severity_warning = normalize_severity(record.get("severity"), config)
    if severity_warning:
        warnings.append(f"{resource}: {severity_warning}")

    category, category_warning = normalize_category(record.get("category"))
    if category_warning:
        warnings.append(f"{resource}: {category_warning}")

    status, status_warning = normalize_status(record.get("status"))
    if status_warning:
        warnings.append(f"{resource}: {status_warning}")

    fingerprint = compute_fingerprint(source, category, resource, title)
    finding_id = _clean_text(record.get("finding_id"), 128) or f"FINDING-{fingerprint[:8].upper()}"

    references = tuple(
        _clean_text(item, 300)
        for item in (record.get("references") or [])
        if _clean_text(item, 300)
    )[:20]
    tags = tuple(
        _clean_text(item, 64).lower()
        for item in (record.get("tags") or [])
        if _clean_text(item, 64)
    )[:20]

    finding = Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        source=source,
        resource=resource,
        category=category,
        severity=severity,
        title=title,
        description=_clean_text(record.get("description"), 4000),
        status=status,
        first_observed=_clean_text(record.get("first_observed"), 64) or timestamp,
        last_observed=_clean_text(record.get("last_observed"), 64) or timestamp,
        remediation=_clean_text(record.get("remediation"), 2000),
        owner=_clean_text(record.get("owner"), 128),
        references=references,
        tags=tags,
        environment=_clean_text(record.get("environment"), 32),
        merged_sources=(source,),
    )
    return finding, warnings


# ---------------------------------------------------------------------------
# Source-format adapters
# ---------------------------------------------------------------------------


def normalize_asff(finding: dict[str, Any]) -> dict[str, Any]:
    """Transform one AWS Security Hub ASFF finding into the raw input shape.

    ASFF is large and much of it is irrelevant to triage. This deliberately
    keeps only identifiers, classification and remediation text. In
    particular it does NOT copy ``ProductFields`` or the raw resource
    ``Details`` blob, which can contain configuration values, tag contents and
    occasionally customer-identifying strings -- copying them into a triage
    report would widen where that data lives for no triage benefit.
    """
    if not isinstance(finding, dict):
        raise TriageInputError(f"ASFF finding must be an object, got {type(finding).__name__}")

    resources = finding.get("Resources") or []
    resource_id = ""
    resource_type = ""
    if resources and isinstance(resources[0], dict):
        resource_id = str(resources[0].get("Id", ""))
        resource_type = str(resources[0].get("Type", ""))

    severity_block = finding.get("Severity") or {}
    severity = (
        severity_block.get("Label")
        or severity_block.get("Normalized")
        or severity_block.get("Original")
    )

    # Prefer the AWS Foundational Security Best Practices category taxonomy in
    # `Types`, which is far more useful than the product name.
    types = [str(t) for t in (finding.get("Types") or []) if t]
    category = _category_from_asff_types(types, resource_type)

    # Workflow status is the human decision; Compliance status is the machine
    # result. The human decision wins when present.
    workflow_status = (finding.get("Workflow") or {}).get("Status")
    compliance_status = (finding.get("Compliance") or {}).get("Status")
    record_state = finding.get("RecordState")

    status = "open"
    if workflow_status:
        status = {
            "NEW": "open",
            "NOTIFIED": "open",
            "RESOLVED": "resolved",
            "SUPPRESSED": "accepted_risk",
        }.get(str(workflow_status).upper(), "open")
    elif compliance_status:
        status = {"PASSED": "resolved", "FAILED": "open", "WARNING": "open"}.get(
            str(compliance_status).upper(), "open"
        )
    if str(record_state).upper() == "ARCHIVED":
        status = "resolved"

    remediation = ((finding.get("Remediation") or {}).get("Recommendation") or {}).get("Text") or ""
    recommendation_url = ((finding.get("Remediation") or {}).get("Recommendation") or {}).get(
        "Url"
    ) or ""

    tags: list[str] = []
    if finding.get("Region"):
        tags.append(f"region:{finding['Region']}")
    if str(finding.get("Compliance", {}).get("Status", "")).upper() == "FAILED":
        tags.append("compliance_failed")

    return {
        "finding_id": _asff_stable_id(finding),
        "source": "securityhub",
        "resource": resource_id or "<unspecified>",
        "category": category,
        "severity": severity,
        "title": finding.get("Title") or "",
        "description": finding.get("Description") or "",
        "status": status,
        "first_observed": finding.get("FirstObservedAt") or finding.get("CreatedAt") or "",
        "last_observed": finding.get("LastObservedAt") or finding.get("UpdatedAt") or "",
        "remediation": remediation,
        "references": [u for u in [recommendation_url] if u] + types[:5],
        "tags": tags,
        "environment": str(finding.get("Region") or ""),
    }


def _asff_stable_id(finding: dict[str, Any]) -> str:
    """Derive a stable id for an ASFF finding.

    ASFF ``Id`` values are long ARNs that change when a resource is recreated,
    so they are hashed together with the generator rather than used directly.
    """
    generator = str(finding.get("GeneratorId", ""))
    raw_id = str(finding.get("Id", ""))
    digest = hashlib.sha256(f"{generator}|{raw_id}".encode()).hexdigest()[:8]
    return f"SH-{digest.upper()}"


def _category_from_asff_types(types: list[str], resource_type: str) -> str:
    """Infer a risk category from ASFF ``Types`` and the resource type."""
    blob = " ".join(types + [resource_type]).lower()

    ordered_checks = (
        ("iam", ("iam", "permission", "privilege", "accesskey")),
        ("secrets", ("secret", "credential", "password")),
        ("encryption", ("encryption", "kms", "cryptograph", "tls", "ssl")),
        ("data_protection", ("data protection", "s3", "dynamodb", "rds", "backup")),
        ("authentication", ("authentication", "mfa", "cognito", "password policy")),
        ("authorization", ("authorization", "access control")),
        ("network", ("network", "securitygroup", "vpc", "firewall", "ingress", "port")),
        ("logging", ("logging", "cloudtrail", "log")),
        ("monitoring", ("monitoring", "cloudwatch", "alarm", "guardduty")),
        ("dependency", ("vulnerabilit", "cve", "patch", "software package")),
        ("availability", ("availability", "resilience", "backup and recovery")),
    )
    for category, needles in ordered_checks:
        if any(needle in blob for needle in needles):
            return category
    return "configuration"


def _normalize_checkov(payload: Any) -> list[dict[str, Any]]:
    """Transform Checkov JSON output into raw input records."""
    # Checkov emits either one object or a list (one per framework).
    blocks = payload if isinstance(payload, list) else [payload]
    records: list[dict[str, Any]] = []

    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = (block.get("results") or {}).get("failed_checks") or []
        for check in results:
            if not isinstance(check, dict):
                continue
            guideline = check.get("guideline") or ""
            file_path = check.get("file_path") or ""
            line_range = check.get("file_line_range") or []
            location = f"{file_path}:{line_range[0]}" if line_range else file_path
            records.append(
                {
                    "source": "checkov",
                    "resource": check.get("resource") or location or "<unspecified>",
                    "category": _checkov_category(check),
                    # Checkov does not emit a severity in the community edition,
                    # so this is a deliberate project decision rather than a
                    # vendor rating: an IaC misconfiguration that reaches
                    # production is treated as medium until a human re-rates it.
                    "severity": check.get("severity") or "medium",
                    "title": check.get("check_name") or check.get("check_id") or "Checkov finding",
                    "description": (
                        f"Checkov {check.get('check_id', '')} failed at {location}."
                    ).strip(),
                    "remediation": guideline or "See the Checkov guideline for this check id.",
                    "references": [r for r in [check.get("check_id"), guideline] if r],
                    "tags": ["infrastructure_as_code"],
                }
            )
    return records


def _checkov_category(check: dict[str, Any]) -> str:
    """Infer a category from a Checkov check id and name."""
    blob = f"{check.get('check_id', '')} {check.get('check_name', '')}".lower()
    if "iam" in blob or "policy" in blob or "privilege" in blob:
        return "iam"
    if "encrypt" in blob or "kms" in blob:
        return "encryption"
    if "log" in blob or "trail" in blob:
        return "logging"
    if "public" in blob or "ingress" in blob or "security group" in blob or "vpc" in blob:
        return "network"
    if "backup" in blob or "versioning" in blob or "point in time" in blob:
        return "availability"
    if "secret" in blob or "password" in blob:
        return "secrets"
    return "configuration"


def _normalize_bandit(payload: Any) -> list[dict[str, Any]]:
    """Transform Bandit JSON output into raw input records."""
    if not isinstance(payload, dict):
        return []

    records: list[dict[str, Any]] = []
    for issue in payload.get("results") or []:
        if not isinstance(issue, dict):
            continue
        filename = issue.get("filename") or ""
        line = issue.get("line_number")
        records.append(
            {
                "source": "bandit",
                "resource": f"{filename}:{line}" if line else filename or "<unspecified>",
                "category": "application",
                "severity": issue.get("issue_severity") or "medium",
                "title": issue.get("issue_text") or issue.get("test_id") or "Bandit finding",
                "description": (
                    f"Bandit {issue.get('test_id', '')} ({issue.get('test_name', '')}), "
                    f"confidence {issue.get('issue_confidence', 'unknown')}."
                ),
                "remediation": issue.get("more_info") or "See the Bandit plugin documentation.",
                "references": [
                    r
                    for r in [
                        f"CWE-{issue.get('issue_cwe', {}).get('id')}"
                        if isinstance(issue.get("issue_cwe"), dict)
                        and issue.get("issue_cwe", {}).get("id")
                        else None,
                        issue.get("more_info"),
                    ]
                    if r
                ],
                "tags": ["static_analysis"],
            }
        )
    return records


def _normalize_iam_checker(payload: Any) -> list[dict[str, Any]]:
    """Transform this project's own IAM policy checker report."""
    if not isinstance(payload, dict):
        return []

    records: list[dict[str, Any]] = []
    for finding in payload.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        tags = ["infrastructure_as_code"]
        if finding.get("confidence") == "needs_context":
            # Carries through as a score reducer, because a review prompt
            # should not outrank a confirmed defect.
            tags.append("compensating_control")
        records.append(
            {
                "source": "iam-policy-checker",
                "resource": f"{finding.get('source', '')}#{finding.get('statement_sid', '')}",
                "category": "iam",
                "severity": finding.get("severity") or "medium",
                "title": finding.get("title") or finding.get("rule_id") or "IAM finding",
                "description": finding.get("description") or "",
                "remediation": finding.get("remediation") or "",
                "references": finding.get("references") or [],
                "tags": tags,
            }
        )
    return records


def _normalize_pip_audit(payload: Any) -> list[dict[str, Any]]:
    """Transform pip-audit JSON output into raw input records."""
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else payload
    if not isinstance(dependencies, list):
        return []

    records: list[dict[str, Any]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        name = dependency.get("name") or "<unknown>"
        version = dependency.get("version") or "?"
        for vuln in dependency.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            fix_versions = vuln.get("fix_versions") or []
            records.append(
                {
                    "source": "pip-audit",
                    "resource": f"{name}=={version}",
                    "category": "dependency",
                    # pip-audit does not emit a severity; advisories reaching a
                    # deployed runtime dependency are treated as high until
                    # triaged, which is the conservative default.
                    "severity": "high",
                    "title": f"{vuln.get('id', 'advisory')} affects {name} {version}",
                    "description": _clean_text(vuln.get("description"), 1000),
                    "remediation": (
                        f"Upgrade {name} to {', '.join(fix_versions)}."
                        if fix_versions
                        else (
                            f"No fixed version published for {name}; "
                            "evaluate mitigation or replacement."
                        )
                    ),
                    "references": [vuln.get("id")] + list(vuln.get("aliases") or []),
                    "tags": ["supply_chain"] + ([] if fix_versions else ["exploit_available"]),
                }
            )
    return records


def detect_and_adapt(payload: Any, source_hint: str, origin: str) -> list[dict[str, Any]]:
    """Detect the input format and return raw input records.

    Explicit ``--format`` always wins; auto-detection is a convenience for
    ``--input`` of a scanner report whose shape is recognisable.
    """
    adapters = {
        "checkov": _normalize_checkov,
        "bandit": _normalize_bandit,
        "iam-policy-checker": _normalize_iam_checker,
        "pip-audit": _normalize_pip_audit,
    }

    if source_hint in adapters:
        return adapters[source_hint](payload)

    if source_hint == "securityhub":
        return [normalize_asff(f) for f in _asff_findings(payload)]

    if source_hint == "normalized":
        return _normalized_records(payload, origin)

    # ---- auto-detect ---------------------------------------------------
    if isinstance(payload, dict):
        if payload.get("tool") == "iam-policy-checker":
            return _normalize_iam_checker(payload)
        if "results" in payload and "metrics" in payload:
            return _normalize_bandit(payload)
        if "dependencies" in payload and isinstance(payload.get("dependencies"), list):
            return _normalize_pip_audit(payload)
        if isinstance(payload.get("results"), dict) and "failed_checks" in payload["results"]:
            return _normalize_checkov(payload)
        if "findings" in payload and isinstance(payload["findings"], list):
            inner = payload["findings"]
            if inner and isinstance(inner[0], dict) and "SchemaVersion" in inner[0]:
                return [normalize_asff(f) for f in inner]
            return _normalized_records(payload, origin)
        if "detail" in payload and isinstance(payload.get("detail"), dict):
            # An EventBridge envelope wrapping Security Hub findings.
            return [normalize_asff(f) for f in _asff_findings(payload["detail"])]

    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict):
            if "SchemaVersion" in payload[0] or "ProductArn" in payload[0]:
                return [normalize_asff(f) for f in payload]
            if "results" in payload[0]:
                return _normalize_checkov(payload)
        return _normalized_records(payload, origin)

    raise TriageInputError(
        f"{origin}: could not determine the input format. Pass --format explicitly "
        "(normalized, checkov, bandit, iam-policy-checker, pip-audit, securityhub)."
    )


def _asff_findings(payload: Any) -> list[dict[str, Any]]:
    """Extract the ASFF finding list from the shapes Security Hub emits."""
    if isinstance(payload, list):
        return [f for f in payload if isinstance(f, dict)]
    if isinstance(payload, dict):
        for key in ("findings", "Findings"):
            if isinstance(payload.get(key), list):
                return [f for f in payload[key] if isinstance(f, dict)]
        if "SchemaVersion" in payload or "ProductArn" in payload:
            return [payload]
    raise TriageInputError("no Security Hub findings found in the input.")


def _normalized_records(payload: Any, origin: str) -> list[dict[str, Any]]:
    """Extract already-normalized records from a list or a wrapper object."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("findings", "items", "results"):
            if isinstance(payload.get(key), list):
                return [r for r in payload[key] if isinstance(r, dict)]
    raise TriageInputError(
        f"{origin}: expected an array of findings or an object with a 'findings' array."
    )


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


#: Properties the normalized-finding schema defines. Derived fields such as
#: ``risk_score`` are projected away before validation, because the schema
#: describes the *input contract*, not the enriched report row.
_SCHEMA_FIELDS = (
    "finding_id",
    "source",
    "resource",
    "category",
    "severity",
    "title",
    "description",
    "status",
    "first_observed",
    "last_observed",
    "remediation",
    "owner",
    "references",
    "tags",
    "environment",
)


def _load_schema() -> dict[str, Any] | str:
    """Load the normalized-finding schema, or return an error string."""
    try:
        return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"could not load {SCHEMA_PATH}: {exc}"


def validate_records(records: Sequence[dict[str, Any]], *, label: str) -> list[str]:
    """Validate records against the normalized-finding schema.

    ``jsonschema`` is a development dependency. When it is unavailable the tool
    still runs and says so: refusing to triage because a validator is missing
    would be a worse outcome than triaging without it.
    """
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema is not installed; schema validation skipped"]

    schema = _load_schema()
    if isinstance(schema, str):
        return [schema]

    validator = jsonschema.Draft202012Validator(schema)
    violations: list[str] = []
    for index, record in enumerate(records):
        for error in sorted(validator.iter_errors(record), key=lambda e: list(e.path)):
            location = ".".join(str(p) for p in error.path) or "<root>"
            violations.append(f"{label} #{index} ({location}): {error.message}")
    return violations


def validate_normalized_output(findings: Sequence[Finding]) -> list[str]:
    """Assert that the tool's own normalization produced canonical findings.

    This is the more useful of the two validation points. Validating raw input
    would report a violation for every tool-specific severity label the
    adapters exist to translate (``ERROR``, ``7.8``) -- noise that says
    nothing about correctness. Validating the *output* instead catches a real
    class of bug: an adapter that emits a category or status the schema does
    not define.
    """
    projected = [
        {
            key: value
            for key, value in finding.to_dict().items()
            if key in _SCHEMA_FIELDS and value not in ("", [], None)
        }
        for finding in findings
    ]
    return validate_records(projected, label="normalized finding")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def resource_weight(resource: str, config: TriageConfig) -> tuple[float, str]:
    """Return the criticality weight for a resource, and why."""
    for rule in config.resource_rules:
        pattern = rule.get("pattern")
        if not isinstance(pattern, str):
            continue
        try:
            if re.search(pattern, resource, re.IGNORECASE):
                return float(rule.get("weight", 1.0)), str(rule.get("reason", pattern))
        except re.error:
            # A bad pattern in config must not take the tool down.
            continue
    return config.resource_default_weight, "no resource rule matched"


def score_finding(finding: Finding, config: TriageConfig) -> Finding:
    """Compute the risk score and priority band for a finding.

    score = base(severity) x category_weight x resource_weight x product(tag modifiers)

    Multiplicative rather than additive so that context *scales* severity
    rather than nudging it: a critical IAM defect on an internet-facing
    production resource should land far above a critical logging gap in a
    sandbox, not two points above it.

    Every factor is recorded in ``score_factors`` so a developer who disagrees
    with a priority can see exactly which weight produced it and argue with
    the config rather than with the tool.
    """
    base = config.severity_base_score.get(finding.severity, 40.0)
    category = config.category_weights.get(finding.category, 1.0)
    res_weight, res_reason = resource_weight(finding.resource, config)

    factors: list[tuple[str, float]] = [
        (f"severity:{finding.severity}", base),
        (f"category:{finding.category}", category),
        (f"resource:{res_reason}", res_weight),
    ]

    score = base * category * res_weight
    modifiers = config.tag_modifiers
    for tag in finding.tags:
        modifier = modifiers.get(tag)
        if modifier is not None:
            score *= modifier
            factors.append((f"tag:{tag}", modifier))

    score = round(min(score, 300.0), 1)

    priority = "P4"
    for name, threshold in config.priority_thresholds:
        if score >= threshold:
            priority = name
            break

    return replace(finding, risk_score=score, priority=priority, score_factors=tuple(factors))


def assign_owner(finding: Finding, config: TriageConfig) -> Finding:
    """Assign an owner using first-match-wins rules.

    An explicit ``owner`` on the input always wins: a human who has already
    assigned a finding should not have it reassigned by a rule.
    """
    if finding.owner:
        return finding

    for rule in config.owner_rules:
        if _rule_matches(rule, finding):
            return replace(finding, owner=str(rule.get("owner", config.default_owner)))

    return replace(finding, owner=config.default_owner)


def _rule_matches(rule: dict[str, Any], finding: Finding) -> bool:
    """True when every criterion a rule specifies matches the finding."""
    if "category" in rule:
        allowed = {str(c).lower() for c in rule["category"]}
        if finding.category not in allowed:
            return False

    if "source" in rule:
        allowed = {str(s).lower() for s in rule["source"]}
        if finding.source.lower() not in allowed:
            return False

    if "severity" in rule:
        allowed = {str(s).lower() for s in rule["severity"]}
        if finding.severity not in allowed:
            return False

    pattern = rule.get("resource_pattern")
    if isinstance(pattern, str):
        try:
            if not re.search(pattern, finding.resource, re.IGNORECASE):
                return False
        except re.error:
            return False

    # A rule with no criteria would match everything, which is almost
    # certainly a config mistake rather than an intentional catch-all.
    return any(key in rule for key in ("category", "source", "severity", "resource_pattern"))


# ---------------------------------------------------------------------------
# Deduplication and status tracking
# ---------------------------------------------------------------------------


def deduplicate(findings: Sequence[Finding]) -> tuple[list[Finding], int]:
    """Collapse findings that describe the same defect.

    Two findings are the same defect when ``(category, resource, title)``
    match, even if different tools reported them. The survivor keeps the
    highest severity and score, the earliest ``first_observed``, the latest
    ``last_observed``, and the union of sources, tags and references.

    Keeping the *highest* severity is the safe direction: an under-rated
    duplicate must not be able to lower the priority of a correctly-rated one.
    """
    merged: dict[str, Finding] = {}
    duplicates = 0

    # Sort first so the result does not depend on input order.
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], f.source, f.resource, f.title),
    )

    for finding in ordered:
        key = compute_dedup_key(finding.category, finding.resource, finding.title)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue

        duplicates += 1
        merged[key] = replace(
            existing,
            severity=(
                finding.severity
                if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]
                else existing.severity
            ),
            risk_score=max(existing.risk_score, finding.risk_score),
            first_observed=min(
                filter(None, (existing.first_observed, finding.first_observed)),
                default=existing.first_observed,
            ),
            last_observed=max(
                filter(None, (existing.last_observed, finding.last_observed)),
                default=existing.last_observed,
            ),
            merged_sources=tuple(
                sorted(set(existing.merged_sources) | set(finding.merged_sources))
            ),
            tags=tuple(sorted(set(existing.tags) | set(finding.tags))),
            references=tuple(sorted(set(existing.references) | set(finding.references))),
            occurrence_count=existing.occurrence_count + finding.occurrence_count,
            remediation=existing.remediation or finding.remediation,
            description=existing.description or finding.description,
        )

    return list(merged.values()), duplicates


def apply_previous_state(
    findings: Sequence[Finding],
    previous_report: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    config: TriageConfig | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Carry status and age forward from a previous report.

    Returns ``(current_findings, resolved_findings)``.

    Three things happen here, and all three are what turn a scan into a
    workflow:

    * A finding present in both runs keeps its ``first_observed`` and its
      human-set ``status`` -- so marking something ``accepted_risk`` is not
      undone by the next scan, and age is real rather than reset.
    * A finding only in the current run is flagged ``is_new``.
    * A finding only in the previous run is returned as resolved rather than
      silently disappearing, because "it stopped being reported" is
      information somebody needs.
    """
    reference_time = now or datetime.now(tz=UTC)
    sla = (config or TriageConfig.load()).sla_days

    previous_by_key: dict[str, dict[str, Any]] = {}
    if previous_report:
        for record in previous_report.get("findings") or []:
            if not isinstance(record, dict):
                continue
            key = compute_dedup_key(
                str(record.get("category", "")),
                str(record.get("resource", "")),
                str(record.get("title", "")),
            )
            previous_by_key[key] = record

    current: list[Finding] = []
    seen_keys: set[str] = set()

    for finding in findings:
        key = compute_dedup_key(finding.category, finding.resource, finding.title)
        seen_keys.add(key)
        prior = previous_by_key.get(key)

        if prior is None:
            updated = replace(finding, is_new=True)
        else:
            prior_status = str(prior.get("status", "open"))
            # A human decision (accepted risk, false positive, in progress)
            # survives the next scan. An automated "open" does not override it.
            keep_status = (
                prior_status
                if prior_status in {"in_progress", "accepted_risk", "false_positive"}
                else finding.status
            )
            updated = replace(
                finding,
                is_new=False,
                status=keep_status,
                first_observed=str(prior.get("first_observed") or finding.first_observed),
            )

        updated = _annotate_age(updated, reference_time, sla)
        current.append(updated)

    resolved: list[Finding] = []
    for key, record in previous_by_key.items():
        if key in seen_keys:
            continue
        if str(record.get("status")) in {"resolved", "false_positive"}:
            continue
        resolved.append(
            Finding(
                finding_id=str(record.get("finding_id", "")),
                fingerprint=str(record.get("fingerprint", "")),
                source=str(record.get("source", "unknown")),
                resource=str(record.get("resource", "")),
                category=str(record.get("category", "other")),
                severity=str(record.get("severity", "info")),
                title=str(record.get("title", "")),
                description=str(record.get("description", "")),
                status="resolved",
                first_observed=str(record.get("first_observed", "")),
                last_observed=reference_time.isoformat(),
                owner=str(record.get("owner", "")),
                priority=str(record.get("priority", "P4")),
                risk_score=float(record.get("risk_score", 0.0) or 0.0),
                is_new=False,
            )
        )

    return current, resolved


def _annotate_age(finding: Finding, now: datetime, sla: dict[str, int]) -> Finding:
    """Compute age in days and whether the finding is past its SLA."""
    try:
        first = datetime.fromisoformat(finding.first_observed.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return finding

    if first.tzinfo is None:
        first = first.replace(tzinfo=UTC)

    age = max(0, (now - first).days)
    target = sla.get(finding.priority)
    overdue = bool(target is not None and finding.is_open and age > target)
    return replace(finding, age_days=age, overdue=overdue)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Order findings by risk, then deterministically."""
    return sorted(
        findings,
        key=lambda f: (
            -f.risk_score,
            PRIORITY_ORDER.index(f.priority) if f.priority in PRIORITY_ORDER else 99,
            -SEVERITY_RANK[f.severity],
            f.category,
            f.resource,
            f.title,
        ),
    )


def build_report(
    findings: Sequence[Finding],
    resolved: Sequence[Finding],
    *,
    sources: Sequence[str],
    duplicates_removed: int,
    warnings: Sequence[str],
    schema_violations: Sequence[str],
    now: datetime,
    config: TriageConfig,
) -> dict[str, Any]:
    """Assemble the machine-readable triage report."""
    ordered = sort_findings(findings)
    open_findings = [f for f in ordered if f.is_open]

    severity_counts = Counter(f.severity for f in ordered)
    priority_counts = Counter(f.priority for f in ordered)
    status_counts = Counter(f.status for f in ordered)
    category_counts = Counter(f.category for f in ordered)
    owner_counts = Counter(f.owner for f in open_findings)
    source_counts = Counter(source for f in ordered for source in f.merged_sources)

    scores = [f.risk_score for f in open_findings]

    return {
        "tool": TOOL_NAME,
        "tool_version": __version__,
        "generated_at": now.isoformat(),
        "scan": {
            "sources": list(sources),
            "duplicates_removed": duplicates_removed,
            "sla_days": config.sla_days,
        },
        "summary": {
            "total_findings": len(ordered),
            "open_findings": len(open_findings),
            "new_findings": sum(1 for f in ordered if f.is_new),
            "overdue_findings": sum(1 for f in ordered if f.overdue),
            "newly_resolved": len(resolved),
            "aggregate_open_risk": round(sum(scores), 1),
            "highest_open_risk": max(scores, default=0.0),
            "by_severity": {s: severity_counts.get(s, 0) for s in SEVERITIES},
            "by_priority": {p: priority_counts.get(p, 0) for p in PRIORITY_ORDER},
            "by_status": dict(sorted(status_counts.items())),
            "by_category": dict(sorted(category_counts.items())),
            "by_owner": dict(sorted(owner_counts.items())),
            "by_source": dict(sorted(source_counts.items())),
        },
        "findings": [f.to_dict() for f in ordered],
        "newly_resolved": [f.to_dict() for f in sort_findings(resolved)],
        "normalization_warnings": list(warnings),
        "schema_violations": list(schema_violations),
        "methodology": {
            "risk_score": (
                "base(severity) x category_weight x resource_criticality x product(tag modifiers). "
                "Multiplicative so context scales severity rather than nudging it. Every factor "
                "is recorded per finding in score_factors."
            ),
            "deduplication": (
                "Findings are collapsed on (category, resource, title), independent of the "
                "reporting tool. The survivor keeps the highest severity and score, the earliest "
                "first_observed, and the union of sources, tags and references."
            ),
            "status_tracking": (
                "With --previous, human-set statuses (in_progress, accepted_risk, "
                "false_positive) survive the next scan and first_observed is carried forward so "
                "age is real. Findings absent from the current run are reported as newly "
                "resolved rather than dropped."
            ),
            "limitations": [
                "Severity for tools that do not emit one (Checkov community, pip-audit) is a "
                "documented project default, not a vendor rating.",
                "Scoring weights are judgement calls recorded in triage_config.json; they are "
                "not derived from measured exploitability.",
                "Deduplication is title-sensitive: a tool that rewords a check name produces a "
                "new finding.",
                "No reachability or exploitability analysis is performed.",
            ],
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as Markdown aimed at the engineer who has to fix it."""
    summary = report["summary"]
    lines: list[str] = []

    lines.append("# Security Finding Triage Report")
    lines.append("")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Tool:** `{report['tool']}` v{report['tool_version']}  ")
    lines.append(f"**Inputs:** {', '.join(f'`{s}`' for s in report['scan']['sources'])}")
    lines.append("")

    # ---- At a glance ---------------------------------------------------
    lines.append("## At a glance")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Open findings | **{summary['open_findings']}** |")
    lines.append(f"| New since last run | {summary['new_findings']} |")
    lines.append(f"| Newly resolved | {summary['newly_resolved']} |")
    lines.append(f"| Past SLA | {summary['overdue_findings']} |")
    lines.append(f"| Duplicates collapsed | {report['scan']['duplicates_removed']} |")
    lines.append(f"| Highest single risk score | {summary['highest_open_risk']} |")
    lines.append(f"| Aggregate open risk | {summary['aggregate_open_risk']} |")
    lines.append("")

    lines.append("### By priority")
    lines.append("")
    lines.append("| Priority | Count | Target resolution |")
    lines.append("|---|---|---|")
    sla = report["scan"]["sla_days"]
    for priority in PRIORITY_ORDER:
        count = summary["by_priority"].get(priority, 0)
        if count:
            target = sla.get(priority)
            lines.append(f"| **{priority}** | {count} | {f'{target} days' if target else 'n/a'} |")
    lines.append("")

    lines.append("### By severity")
    lines.append("")
    severity_row = " | ".join(
        f"{name}: {summary['by_severity'][name]}"
        for name in SEVERITIES
        if summary["by_severity"][name]
    )
    lines.append(severity_row or "_No findings._")
    lines.append("")

    # ---- Ownership -----------------------------------------------------
    if summary["by_owner"]:
        lines.append("## Open findings by owner")
        lines.append("")
        lines.append("| Owner | Open findings |")
        lines.append("|---|---|")
        for owner, count in sorted(summary["by_owner"].items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{owner}` | {count} |")
        lines.append("")

    # ---- The work queue ------------------------------------------------
    open_findings = [f for f in report["findings"] if f["status"] in OPEN_STATUSES]

    if not open_findings:
        lines.append("## Work queue")
        lines.append("")
        lines.append("No open findings. Every item is resolved, accepted, or a false positive.")
        lines.append("")
    else:
        lines.append("## Work queue")
        lines.append("")
        for priority in PRIORITY_ORDER:
            bucket = [f for f in open_findings if f["priority"] == priority]
            if not bucket:
                continue

            lines.append(f"### {priority} — {len(bucket)} finding(s)")
            lines.append("")
            for finding in bucket:
                flags = []
                if finding["is_new"]:
                    flags.append("NEW")
                if finding["overdue"]:
                    flags.append(f"OVERDUE ({finding['age_days']}d)")
                if finding["occurrence_count"] > 1:
                    flags.append(f"{finding['occurrence_count']}x")
                flag_text = f" `{' | '.join(flags)}`" if flags else ""

                lines.append(f"#### {finding['finding_id']} — {finding['title']}{flag_text}")
                lines.append("")
                lines.append(f"- **Risk score:** {finding['risk_score']} ({finding['severity']})")
                lines.append(f"- **Resource:** `{finding['resource']}`")
                lines.append(f"- **Category:** {finding['category']}")
                lines.append(f"- **Owner:** `{finding['owner']}`")
                lines.append(f"- **Reported by:** {', '.join(finding['merged_sources'])}")
                lines.append(f"- **Status:** {finding['status']} (age {finding['age_days']}d)")
                if finding["description"]:
                    lines.append(f"- **Detail:** {finding['description']}")
                if finding["remediation"]:
                    lines.append(f"- **Fix:** {finding['remediation']}")
                if finding["references"]:
                    lines.append(f"- **References:** {', '.join(finding['references'][:6])}")
                lines.append(
                    "- **Score breakdown:** "
                    + ", ".join(f"{k} = {v}" for k, v in finding["score_factors"].items())
                )
                lines.append("")

    # ---- Accepted risks ------------------------------------------------
    accepted = [f for f in report["findings"] if f["status"] == "accepted_risk"]
    if accepted:
        lines.append("## Accepted risks")
        lines.append("")
        lines.append(
            "These are knowingly accepted. They stay in the report so an accepted risk "
            "cannot be quietly forgotten."
        )
        lines.append("")
        lines.append("| ID | Finding | Resource | Score |")
        lines.append("|---|---|---|---|")
        for finding in accepted:
            lines.append(
                f"| {finding['finding_id']} | {finding['title']} | "
                f"`{finding['resource']}` | {finding['risk_score']} |"
            )
        lines.append("")

    # ---- Newly resolved ------------------------------------------------
    if report["newly_resolved"]:
        lines.append("## Newly resolved since the previous run")
        lines.append("")
        lines.append("| ID | Finding | Resource |")
        lines.append("|---|---|---|")
        for finding in report["newly_resolved"]:
            lines.append(
                f"| {finding['finding_id']} | {finding['title']} | `{finding['resource']}` |"
            )
        lines.append("")

    # ---- Data quality --------------------------------------------------
    if report["normalization_warnings"] or report["schema_violations"]:
        lines.append("## Input data quality")
        lines.append("")
        lines.append(
            "Recorded rather than suppressed: a silently-coerced severity is a finding "
            "that lands in the wrong priority band."
        )
        lines.append("")
        for warning in report["normalization_warnings"][:40]:
            lines.append(f"- {warning}")
        for violation in report["schema_violations"][:40]:
            lines.append(f"- schema: {violation}")
        lines.append("")

    # ---- Methodology ---------------------------------------------------
    lines.append("## Methodology and limitations")
    lines.append("")
    methodology = report["methodology"]
    lines.append(f"**Risk score.** {methodology['risk_score']}")
    lines.append("")
    lines.append(f"**Deduplication.** {methodology['deduplication']}")
    lines.append("")
    lines.append(f"**Status tracking.** {methodology['status_tracking']}")
    lines.append("")
    lines.append("**Limitations.**")
    lines.append("")
    for limitation in methodology["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def apply_filters(findings: Sequence[Finding], args: argparse.Namespace) -> list[Finding]:
    """Apply the command-line filters."""
    result = list(findings)

    if args.min_severity:
        floor = SEVERITY_RANK[args.min_severity]
        result = [f for f in result if SEVERITY_RANK[f.severity] >= floor]

    if args.status:
        wanted = {s.lower() for s in args.status}
        result = [f for f in result if f.status in wanted]

    if args.category:
        wanted = {c.lower() for c in args.category}
        result = [f for f in result if f.category in wanted]

    if args.owner:
        wanted = {o.lower() for o in args.owner}
        result = [f for f in result if f.owner.lower() in wanted]

    if args.source:
        wanted = {s.lower() for s in args.source}
        result = [f for f in result if {s.lower() for s in f.merged_sources} & wanted]

    if args.priority:
        wanted = {p.upper() for p in args.priority}
        result = [f for f in result if f.priority in wanted]

    if args.new_only:
        result = [f for f in result if f.is_new]

    if args.overdue_only:
        result = [f for f in result if f.overdue]

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="finding_triage.py",
        description=(
            "Aggregate, normalize, score, deduplicate and prioritise security findings "
            "from multiple tools. Offline and deterministic; no AWS credentials required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  ran successfully, nothing at or above --fail-on\n"
            "  1  findings at or above --fail-on are present\n"
            "  2  usage or input error\n"
        ),
    )

    source = parser.add_argument_group("input")
    source.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="FILE",
        help="Findings file. Repeatable; formats are auto-detected per file.",
    )
    source.add_argument("--stdin", action="store_true", help="Read findings from standard input.")
    source.add_argument(
        "--format",
        choices=(
            "auto",
            "normalized",
            "checkov",
            "bandit",
            "iam-policy-checker",
            "pip-audit",
            "securityhub",
        ),
        default="auto",
        help="Force an input format instead of auto-detecting. Default: auto.",
    )
    source.add_argument(
        "--previous",
        metavar="FILE",
        help="A previous JSON report. Carries status and age forward and detects resolutions.",
    )
    source.add_argument(
        "--config",
        metavar="FILE",
        help="Config overriding security-automation/triage_config.json (merged over defaults).",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--output", metavar="FILE", help="Write the JSON report here.")
    output.add_argument("--markdown", metavar="FILE", help="Write the Markdown report here.")
    output.add_argument(
        "--print",
        dest="print_format",
        choices=("summary", "json", "markdown", "none"),
        default="summary",
        help="What to print to stdout. Default: summary.",
    )
    output.add_argument(
        "--now",
        metavar="ISO8601",
        help="Pin the report timestamp, for byte-identical output in tests.",
    )

    filters = parser.add_argument_group("filters")
    filters.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        help="Keep findings at or above this severity.",
    )
    filters.add_argument("--status", action="append", default=[], help="Keep these statuses.")
    filters.add_argument("--category", action="append", default=[], help="Keep these categories.")
    filters.add_argument("--owner", action="append", default=[], help="Keep these owners.")
    filters.add_argument("--source", action="append", default=[], help="Keep these sources.")
    filters.add_argument("--priority", action="append", default=[], help="Keep these priorities.")
    filters.add_argument("--new-only", action="store_true", help="Only findings new this run.")
    filters.add_argument("--overdue-only", action="store_true", help="Only findings past SLA.")

    behaviour = parser.add_argument_group("behaviour")
    behaviour.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="Exit 1 when an open finding at or above this severity exists.",
    )
    behaviour.add_argument(
        "--no-dedup", action="store_true", help="Skip deduplication (useful when debugging)."
    )
    behaviour.add_argument(
        "--strict",
        action="store_true",
        help="Treat schema violations as fatal (exit 2) instead of recording them.",
    )
    behaviour.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the input against the schema and exit without triaging.",
    )

    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def _load_json(path: Path) -> Any:
    """Read and parse a JSON file with a clear error on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TriageInputError(f"{path}: cannot read file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TriageInputError(f"{path}: not valid JSON: {exc}") from exc


def _collect_raw_records(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    """Load and adapt every input into raw normalized-shape records."""
    records: list[dict[str, Any]] = []
    sources: list[str] = []

    for raw_path in args.input:
        path = Path(raw_path)
        payload = _load_json(path)
        records.extend(detect_and_adapt(payload, args.format, str(path)))
        sources.append(str(path))

    if args.stdin:
        raw = sys.stdin.read()
        if not raw.strip():
            raise TriageInputError("stdin: no input received.")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TriageInputError(f"stdin: not valid JSON: {exc}") from exc
        records.extend(detect_and_adapt(payload, args.format, "<stdin>"))
        sources.append("<stdin>")

    return records, sources


def _render_summary(report: dict[str, Any]) -> str:
    """Render a compact console summary."""
    summary = report["summary"]
    lines = [
        "=" * 70,
        f"Security Finding Triage v{report['tool_version']}",
        "=" * 70,
        f"Inputs            : {', '.join(report['scan']['sources']) or '<none>'}",
        f"Total findings     : {summary['total_findings']}",
        f"Open               : {summary['open_findings']}"
        f"   New: {summary['new_findings']}"
        f"   Overdue: {summary['overdue_findings']}"
        f"   Newly resolved: {summary['newly_resolved']}",
        f"Duplicates removed : {report['scan']['duplicates_removed']}",
        f"Aggregate open risk: {summary['aggregate_open_risk']}"
        f"   (highest single: {summary['highest_open_risk']})",
        "",
        "By priority : "
        + "  ".join(
            f"{p}={summary['by_priority'][p]}" for p in PRIORITY_ORDER if summary["by_priority"][p]
        ),
        "By severity : "
        + "  ".join(
            f"{s}={summary['by_severity'][s]}" for s in SEVERITIES if summary["by_severity"][s]
        ),
        "By owner    : "
        + "  ".join(f"{owner}={count}" for owner, count in summary["by_owner"].items()),
        "",
    ]

    top = [f for f in report["findings"] if f["status"] in OPEN_STATUSES][:10]
    if top:
        lines.append("Top open findings by risk:")
        for finding in top:
            flag = " [NEW]" if finding["is_new"] else ""
            flag += " [OVERDUE]" if finding["overdue"] else ""
            lines.append(
                f"  {finding['priority']} {finding['risk_score']:>6}  "
                f"{finding['finding_id']}  {finding['title'][:52]}{flag}"
            )
        lines.append("")

    if report["normalization_warnings"]:
        lines.append(f"Normalization warnings: {len(report['normalization_warnings'])}")
        for warning in report["normalization_warnings"][:5]:
            lines.append(f"  - {warning}")
        lines.append("")

    if report["schema_violations"]:
        lines.append(f"Schema violations: {len(report['schema_violations'])}")
        for violation in report["schema_violations"][:5]:
            lines.append(f"  - {violation}")
        lines.append("")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.input or args.stdin):
        parser.print_usage(sys.stderr)
        print("error: no input. Use --input or --stdin.", file=sys.stderr)
        return 2

    try:
        now = (
            datetime.fromisoformat(args.now.replace("Z", "+00:00"))
            if args.now
            else datetime.now(tz=UTC)
        )
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
    except ValueError as exc:
        print(f"error: --now is not a valid ISO-8601 timestamp: {exc}", file=sys.stderr)
        return 2

    try:
        config = TriageConfig.load(Path(args.config) if args.config else None)
        raw_records, sources = _collect_raw_records(args)
    except TriageInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # --validate-only and --strict check the INPUT against the schema: the
    # caller is asserting their input is already canonical.
    if args.validate_only or args.strict:
        input_violations = validate_records(raw_records, label="input record")
        if input_violations:
            print(f"{len(input_violations)} input schema violation(s):", file=sys.stderr)
            for violation in input_violations:
                print(f"  - {violation}", file=sys.stderr)
            return 2
        if args.validate_only:
            print(f"{len(raw_records)} input record(s) validated successfully.")
            return 0

    findings: list[Finding] = []
    warnings: list[str] = []
    for index, record in enumerate(raw_records):
        try:
            finding, record_warnings = normalize_finding(record, config, now=now)
        except TriageInputError as exc:
            # One malformed record must not discard the other 200. Record it
            # and carry on -- a triage tool that refuses to run because of one
            # bad row is a triage tool nobody uses.
            warnings.append(f"record #{index} skipped: {exc}")
            continue
        findings.append(finding)
        warnings.extend(record_warnings)

    # Assert the adapters produced canonical findings. A violation here is a
    # bug in this tool, not in the input.
    schema_violations = validate_normalized_output(findings)

    findings = [assign_owner(score_finding(f, config), config) for f in findings]

    duplicates_removed = 0
    if not args.no_dedup:
        findings, duplicates_removed = deduplicate(findings)

    previous_report: dict[str, Any] | None = None
    if args.previous:
        previous_path = Path(args.previous)
        if previous_path.exists():
            try:
                loaded = _load_json(previous_path)
                previous_report = loaded if isinstance(loaded, dict) else None
                if previous_report is None:
                    warnings.append(f"{previous_path}: not a report object; previous state ignored")
            except TriageInputError as exc:
                warnings.append(f"previous report ignored: {exc}")
        else:
            warnings.append(f"{previous_path}: not found; treating every finding as new")

    findings, resolved = apply_previous_state(findings, previous_report, now=now, config=config)

    findings = apply_filters(findings, args)

    report = build_report(
        findings,
        resolved,
        sources=sources,
        duplicates_removed=duplicates_removed,
        warnings=warnings,
        schema_violations=schema_violations,
        now=now,
        config=config,
    )

    if args.output:
        destination = Path(args.output)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {destination}: {exc}", file=sys.stderr)
            return 2
        print(f"JSON report written to {destination}")

    if args.markdown:
        destination = Path(args.markdown)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(render_markdown(report), encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {destination}: {exc}", file=sys.stderr)
            return 2
        print(f"Markdown report written to {destination}")

    if args.print_format == "summary":
        print(_render_summary(report))
    elif args.print_format == "json":
        print(json.dumps(report, indent=2))
    elif args.print_format == "markdown":
        print(render_markdown(report))

    if args.fail_on:
        floor = SEVERITY_RANK[args.fail_on]
        blocking = [f for f in findings if f.is_open and SEVERITY_RANK[f.severity] >= floor]
        if blocking:
            print(
                f"\n{len(blocking)} open finding(s) at or above '{args.fail_on}' severity.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
