# Requirements Traceability Matrix

Maps each security-engineering capability to the artefact that implements it and the
evidence that it works.

> **Note on scope.** The build specification referred to "the supplied Amazon Security
> Engineer I job description", but **no job description was provided** to this project. The
> capability rows below are therefore derived from the engineering outcomes listed in the
> build specification itself, plus the commonly-published responsibilities of an
> entry-level application/cloud security engineering role (threat modelling, secure code
> review, vulnerability remediation, security automation, IAM, SDLC integration, incident
> response, risk communication). Where a responsibility is **not** covered by this project,
> it is listed as a gap in §4 rather than quietly omitted.

| Status | Meaning |
|---|---|
| ✅ **Verified** | Implemented, with a command that was actually run in this environment producing the stated result |
| 🟡 **Partial** | Implemented, but verification depends on something unavailable here (AWS account, Terraform binary, GitHub) |
| ⬜ **Not covered** | Not implemented. Listed in §4 |

---

## 1. Core capability matrix

| # | Capability | Implementation | Evidence | Status |
|---|---|---|---|---|
| 1 | **Threat modelling (STRIDE)** | `threat-model/threat-model.md` — STRIDE applied per data flow across 10 cross-boundary flows | 16 threats, each with preconditions, impact, likelihood, severity, mitigations, verification method and residual risk; threats considered-and-discarded documented with reasons | ✅ |
| 2 | **Trust boundary analysis** | `threat-model/architecture.md` §4 | 7 boundaries (TB1–TB7); TB2 identified as the critical one and traced to the file that enforces it | ✅ |
| 3 | **Data-flow analysis** | `threat-model/data-flow.md` | 4 Mermaid diagrams + a 10-row cross-boundary flow table naming the enforcing file for each | ✅ |
| 4 | **Security requirements engineering** | `threat-model/security-requirements.md` | 91 testable requirements mapped to ASVS 4.0.3 / OWASP Top 10 / API Top 10; 76 verified, 11 AWS-gated, 4 not implemented | ✅ |
| 5 | **Risk register and prioritisation** | `threat-model/risk-register.csv` | 16 rows × 19 columns: inherent vs residual rating, status, owner, mitigation, next action, review date | ✅ |
| 6 | **Manual secure code review** | `assessments/code-review-checklist.md` | 10-domain, 60-item checklist applied to 2,064 statements; every item carries a verdict; methodology and its limitations disclosed | ✅ |
| 7 | **Vulnerability identification** | `assessments/security-findings.md` | **15 confirmed findings** (1 critical, 4 high, 7 medium, 3 low), each with file/line evidence from `v1-pre-review`, CWE and OWASP mapping | ✅ |
| 8 | **Separating confirmed from theoretical** | Same, §Observations | 7 observations (O-1–O-7) recorded separately and **excluded from finding counts** | ✅ |
| 9 | **Vulnerability remediation** | `git diff v1-pre-review v2-remediated` | 14 files, +1,744 / −312; every finding mapped to the files that fixed it in `assessments/remediation-tracker.md` | ✅ |
| 10 | **Remediation verification** | `assessments/regression-evidence.md` | Security suite against vulnerable code: **93 failed, 102 passed**. Against fixed code: **195 passed**. Verbatim output captured | ✅ |
| 11 | **Secure Python development** | `application/app/` — 24 modules, type-hinted, layered | `ruff check` clean (incl. `S` + `ANN` rule sets); Bandit 0 findings at medium+; 0 `nosec` | ✅ |
| 12 | **HTTP / REST API security** | `app/security/http.py`, `app/main.py`, `app/routes/` | 8 security headers on **every** response incl. 500s; uniform error envelope; `test_api_behaviour.py` (24 tests) | ✅ |
| 13 | **Authentication design** | `app/security/identity.py` + API Gateway JWT authorizer | Identity read only from verified claims; `test_authentication.py` (26 tests). Gateway-level validation is 🟡 | 🟡 |
| 14 | **Authorization design** | `app/security/authorization.py`, `app/services/ticket_service.py` | Explicit `Decision` + `enforce()`; exhaustive role × operation × transition matrix in `test_authorization.py` (27 tests) | ✅ |
| 15 | **Multi-tenant isolation** | `PK = TENANT#{org}` + GSI1 + IAM `Deny` on `Scan` | `test_tenant_isolation.py` (16), `test_data_access_scoping.py` (12) — the latter asserts `scan` is **never called** and keys are always pinned | ✅ |
| 16 | **Input validation** | `app/models/ticket.py`, `repositories/keys.py`, `repositories/pagination.py` | `extra="forbid"` everywhere; `test_input_validation.py` (64 tests) incl. key-separator and encoded-byte cases | ✅ |
| 17 | **Secure error handling** | `app/main.py` exception handlers | `test_error_handling.py` — no trace, no exception text, no echoed values, uniform envelope across 7 status codes | ✅ |
| 18 | **Sensitive-data protection in logs** | `app/observability/logging.py` field allow-list | `test_logging_and_data_protection.py` (10 tests); live demo shows **0 occurrences** of ticket content in the log stream | ✅ |
| 19 | **Security logging and auditability** | Structured JSON, 6 security event types, request-id correlation | Live transcript in `docs/DEMO.md` §5 showing `authorization_denied` with actor, target and machine-readable reason | ✅ |
| 20 | **AWS IAM and least privilege** | `infrastructure/terraform/iam.tf` + `policies/*.json` | Enumerated actions; explicit `Deny` statements; permissions boundary; and the authorization source of truth in its **own table with a read-only grant**. `iam_policy_checker.py` → **1 INFO, 0 blocking**; the policy itself asserted by `test_membership_table_isolation.py`. Live enforcement 🟡 | 🟡 |
| 21 | **Infrastructure as code security** | 10 `.tf` files + 1 module | Checkov: **137 passed, 0 failed, 12 justified skips**. `terraform validate` not run (L2) | 🟡 |
| 22 | **Secure-by-default configuration** | `app/config.py` | Every default is the safe value; fail-closed guard on the identity source; `test_config.py` (25 tests) | ✅ |
| 23 | **Custom security automation (1)** | `security-automation/iam_policy_checker.py` — 1,586 lines, 11 rules | 59 unit tests; `confirmed` vs `needs_context` confidence; documents its own limitations; **CI gate self-test proves it rejects the insecure fixture** | ✅ |
| 24 | **Custom security automation (2)** | `security-automation/finding_triage.py` — 1,927 lines | 142 unit tests; normalises 5 tool formats + ASFF; stable dedup; risk scoring; owner rules; cross-run status tracking; JSON + Markdown | ✅ |
| 25 | **SAST integration** | Bandit + Ruff `S` rules, CI stage 2 | 4,780 lines scanned; 0 at medium+; the one LOW is a documented false positive left **visible** | ✅ |
| 26 | **Semantic code scanning** | CodeQL `security-extended`, CI stage 2a | Configured and reviewed. **Never executed** — no remote repository (L3) | 🟡 |
| 27 | **Dependency / SCA scanning** | pip-audit, CI stage 2c, runtime + dev trees | 21 packages, **0 vulnerabilities** | ✅ |
| 28 | **CI/CD security gating** | `.github/workflows/security-ci.yml` | 5 stages + a `security-gate` job that **treats a skipped security job as a failure**; mirrored locally by `run_security_checks.sh` → **15/15 pass** | 🟡 |
| 29 | **Pipeline supply-chain hygiene** | Deny-by-default `permissions`, `pull_request` not `pull_request_target`, no deploy job, scanners from PyPI | Workflow YAML validated; per-job permissions enumerated in `docs/SECURITY.md` §3. Tag pins not SHA pins (L3) | 🟡 |
| 30 | **No suppression of findings to pass CI** | 0 `nosec`; no Checkov baseline; no `--skip-check` | 12 inline skips, each single-check, single-resource, justified, referencing an accepted-risk ID | ✅ |
| 31 | **Cloud security monitoring** | `monitoring.tf` — 5 metric filters, 8 alarms, 4 Insights queries, 1 dashboard | Configuration reviewed; event emission verified in tests and the live demo. **Alarms never observed firing** (L1) | 🟡 |
| 32 | **Security finding triage** | `finding_triage.py` + Runbook B | Real run aggregating 4 scanner reports → 2 open findings, 0 duplicates, priorities and owners assigned | ✅ |
| 33 | **Cloud CSPM integration** | `infrastructure/modules/security_hub_triage/` — Security Hub → EventBridge → Lambda | 38 unit tests against synthetic ASFF events. Security Hub never enabled (L6); off by default | 🟡 |
| 34 | **Incident response procedure** | `runbooks/authorization-alert-triage.md` | Triggering conditions tied to real alarm names/thresholds; 6-option containment framework; **documents its own detection gaps** | ✅ |
| 35 | **Cloud finding response procedure** | `runbooks/cloud-security-finding-response.md` | Intake → asset criticality → true-positive test → owner → fix-in-IaC → verification → resolution criteria | ✅ |
| 36 | **Incident documentation** | `runbooks/incident-report-template.md` | Structured template; requires distinguishing "no evidence of access" from "undetermined" | ✅ |
| 37 | **SDLC integration** | Two-pass methodology + gated pipeline + regression requirement | Every finding has a regression test that **failed first**; re-review triggers enumerated | ✅ |
| 38 | **Technical security reporting** | `assessments/final-security-assessment.md` | 13 sections: scope, objectives, methodology, findings, remediation decisions with rejected alternatives, residual risk, limitations, prioritised next steps | ✅ |
| 39 | **Risk communication to leadership** | `assessments/executive-summary.md` | One page, plain language, business consequence first, explicit "what we are not claiming" section | ✅ |
| 40 | **Accurate reporting of limitations** | `final-security-assessment.md` §12 | 9 limitations (L1–L9) including "author and reviewer are the same engineer" | ✅ |
| 41 | **Reproducibility by another engineer** | `docs/SETUP.md`, `docs/DEMO.md`, `scripts/local_server.py` | Runs with no AWS account, no credentials, no Docker. Every demo output captured from a real run | ✅ |

---

## 2. Verification summary

| Status | Count |
|---|---|
| ✅ Verified | 31 |
| 🟡 Partial (blocked on AWS / Terraform / GitHub) | 10 |
| ⬜ Not covered | see §4 |

Every 🟡 traces to one of three external blockers:

| Blocker | Affects | Fix |
|---|---|---|
| **L1** — no AWS account used | 13, 20, 21, 31, 33 | Deploy to a sandbox and run the 13 AWS-gated tests |
| **L2** — Terraform binary not installable (`releases.hashicorp.com` outside the egress allow-list) | 21 | Run `terraform fmt`/`validate`/`plan` anywhere Terraform is available |
| **L3** — no remote repository | 26, 28, 29 | Push and observe one pipeline run |

---

## 3. Standards coverage

| Standard | Where | Coverage |
|---|---|---|
| **OWASP Top 10 (2021)** | `security-findings.md` App. B | A01, A03, A04, A05, A07, A09 addressed by findings. A02 (crypto) via KMS/TLS configuration. A06 via pip-audit. A08 (integrity) addressed — hashed lock file installed with `--require-hashes`. A10 (SSRF) discarded with reasons |
| **OWASP API Security Top 10 (2023)** | Same | API1, API2, API3, API4, API5, API6, API8 addressed. API7 (SSRF) n/a — no outbound requests. API9/API10 (inventory, unsafe API consumption) not applicable at this scope |
| **OWASP ASVS 4.0.3** | `security-requirements.md` | 91 requirements mapped across V1, V2, V3, V4, V5, V6, V7, V8, V9, V11, V14 |
| **STRIDE** | `threat-model.md` | All 6 categories, applied per data flow with discards documented |
| **CWE** | `security-findings.md` | 22 distinct CWEs across the 15 findings |
| **CIS / AWS Foundational Security Best Practices** | Checkov + Security Hub module | 137 Checkov checks passing; CSPM pipeline implemented but Security Hub not enabled |

---

## 4. Not covered — honest gaps

Capabilities an entry-level security engineering role may touch that this project does
**not** demonstrate. Listed so the matrix is not read as broader than it is.

| Area | Why not | Could it be added? |
|---|---|---|
| **Penetration testing / offensive tooling** | Deliberately out of scope. The build specification excluded offensive and destructive tooling, and this project owns no target it would be appropriate to attack | No — correctly excluded |
| **Network security** (VPC, security groups, NACLs, WAF rules) | The architecture is serverless and reaches only AWS service endpoints, so a VPC adds cost and latency with no security gain (AR-06). WAF is identified as a gap (S-3) but not built | Yes — WAF rate rules are a concrete next step |
| **Container / Kubernetes security** | No containers. The build specification explicitly excluded Kubernetes | Not applicable to this architecture |
| **Detection engineering at scale** (SIEM rules, correlation) | CloudWatch metric filters and Insights queries only. No SIEM | Partially — the structured log schema is designed for it |
| **Live incident response** | Both runbooks are **reasoned and locally exercised, never executed against a real incident**, because nothing is deployed | Only with a deployment |
| **Forensics / malware analysis** | Out of scope | No |
| **Compliance audit** (SOC 2, PCI, ISO 27001) | No control framework mapping to an audit standard | Yes — the 91 requirements are a reasonable starting point |
| **Secrets management** (Secrets Manager, rotation) | **No secrets exist in this design** — Cognito issues tokens, there is no shared API key, Terraform has no secret variables. So there is nothing to rotate | Not applicable, which is itself a design outcome |
| **Load / performance / chaos testing** | Limitation L8. T-13 (flooding) is reasoned about, not measured | Yes, with a deployment |
| **Independent security review** | Limitation L7 — the project's largest acknowledged weakness | Only by another person |

---

## 5. What a personal project cannot evidence

Stated plainly, because a traceability matrix that implies otherwise would be dishonest.

This repository demonstrates **technical capability**. It does **not** evidence:

- Professional or non-internship work experience, or years of it
- Educational qualifications
- Operating a production system under real load, real customers or real on-call pressure
- Working within a team's review, change-management and escalation processes
- Responding to a real security incident
- Having had this work independently reviewed or signed off

The honest framing is: *this is what the work looks like when I do it, end to end, and here
is the evidence it actually runs.* The findings are real findings in real code with real
failing-then-passing tests — and the author of the vulnerable code and the reviewer who
found it are the same person, which is the weakest form of review and is disclosed
everywhere it is relevant.
