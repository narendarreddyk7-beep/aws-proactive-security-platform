# Resume Bullets

Drawn **strictly** from work in this repository that was actually executed and verified.

> **Ground rules applied.** No invented percentages. No implied deployment. No claimed
> business impact. Every number below traces to a command in
> [`../assessments/regression-evidence.md`](../assessments/regression-evidence.md) that was
> run on 2026-10-23. Things this project cannot evidence — production operation, team
> process, years of experience — are listed in §4 and must not be implied.

---

## 1. Recommended set (use 4–5)

Each is a single bullet; the note underneath is for you, not the resume.

**1.**
> Designed and built a multi-tenant AWS support-ticket API (Python 3.12, FastAPI, Lambda,
> API Gateway JWT authorizer, Cognito, DynamoDB) enforcing tenant isolation through
> partition-key-scoped data access and least-privilege IAM rather than application-layer
> filtering.

*Leads with the architectural idea, not the tool list. "Rather than application-layer
filtering" is the part a security engineer will react to.*

**2.**
> Performed STRIDE threat modelling across 10 cross-boundary data flows, producing 16
> documented threats, a 16-row risk register, and 91 testable security requirements mapped
> to OWASP ASVS and the OWASP API Security Top 10.

*All four numbers are countable in the repository.*

**3.**
> Conducted a manual secure code review of 2,064 statements against a 60-item checklist,
> identifying and remediating 15 confirmed findings (1 critical authentication bypass, 4
> high-severity broken access control) each mapped to CWE/OWASP and verified by a regression
> test demonstrated to fail against the pre-remediation code.

*The last clause is the strongest thing on the page: it is the difference between "I wrote
tests" and "I proved the tests work". Expect to be asked about it — the answer is in
`INTERVIEW_GUIDE.md` §8.*

**4.**
> Built two Python security CLIs (3,513 lines, 201 unit tests): an IAM policy analyzer with
> 11 detection rules and confirmed/needs-context confidence classification, and a
> multi-tool finding-triage engine normalising Checkov, Bandit, pip-audit and Security Hub
> ASFF output with deterministic deduplication, risk scoring and cross-run status tracking.

*Original work, not configuration of someone else's tool. The confidence classification is
the detail that signals you understand alert fatigue.*

**5.**
> Implemented a 5-stage GitHub Actions security pipeline (Ruff, CodeQL, Bandit, pip-audit,
> Checkov, custom IAM analysis, 616-test suite) with least-privilege job permissions, a gate
> that treats a skipped security job as a failure, and a self-test asserting the IAM gate
> rejects a known-insecure policy.

*The self-test and the skipped-job handling are what distinguish this from "added scanners
to CI".*

---

## 2. Alternatives, by emphasis

### If the role emphasises cloud / IAM

> Authored least-privilege AWS IAM policies as version-controlled JSON — enumerated actions,
> ARN-scoped resources, explicit Deny on `dynamodb:Scan` and credential self-modification,
> and a permissions boundary — so CI gates the policy document that actually deploys rather
> than one rendered only at plan time.

> Built AWS infrastructure as 10 Terraform files covering API Gateway HTTP API with a
> Cognito JWT authorizer, Lambda, DynamoDB with tenant-partitioned keys, KMS, and CloudWatch
> detection (5 metric filters, 8 alarms, 4 saved Insights queries), passing 134 Checkov
> checks with 12 individually justified exceptions and no baseline file.

### If the role emphasises detection / response

> Implemented structured JSON security logging with a field allow-list that excludes
> customer content and credentials by construction, plus CloudWatch metric filters and
> alarms for authorization denials, token-claim/record mismatches, and activation of the
> development authentication adapter.

> Wrote two incident response runbooks (suspicious authorization activity; high-severity
> cloud finding) keyed to the deployed alarm names and thresholds, including a graduated
> containment framework and an explicit statement of what the detection cannot see.

### If the role emphasises AppSec / SDLC

> Established a two-pass secure development methodology — unreviewed first draft preserved
> in version control, then security review with every confirmed finding proven by a test
> that failed against the draft — producing 93 demonstrated failures against the
> pre-remediation code and 176 passes after remediation.

> Hardened a REST API against OWASP API Top 10 risks: schema-level rejection of unknown
> fields to close mass assignment, server-controlled tenancy and ownership fields, bounded
> pagination and field sizes, tenant-bound pagination cursors, a uniform error envelope
> carrying no stack traces or submitted values, and identical 404 responses for
> cross-tenant and non-existent resources.

---

## 3. Verified numbers

Every figure available for use, with its source. **Do not use a number that is not here.**

| Figure | Value | Source |
|---|---|---|
| Confirmed findings | **15** (1 crit / 4 high / 7 med / 3 low) | `security-findings.md` |
| Findings remediated and retested | **17 of 17** | `remediation-tracker.md` |
| Observations (not counted as findings) | 7 | `code-review-checklist.md` §5 |
| Tests passing | **584** | `pytest -q` |
| Tests skipped (AWS-gated) | 13 | same |
| Total tests | 595 | same |
| Regression-marked tests | 141 | `pytest -m regression --collect-only` |
| Failures against pre-review code | **93** (92 passed) | `regression-evidence.md` §1 |
| Security-suite passes after remediation | **195** | same |
| Coverage | **89%** | `pytest --cov` |
| Statements reviewed | 2,058 | `coverage.xml` |
| STRIDE threats | 16 | `threat-model.md` |
| Cross-boundary data flows analysed | 10 | `data-flow.md` |
| Trust boundaries | 7 | `architecture.md` |
| Security requirements | 91 (76 verified / 11 AWS-gated / 4 open) | `security-requirements.md` |
| Risk register rows | 16 | `risk-register.csv` |
| Review checklist items | 60 across 10 domains | `code-review-checklist.md` |
| Distinct CWEs mapped | 22 | `security-findings.md` App. B |
| IAM analyzer rules | 11 | `iam_policy_checker.py --list-rules` |
| Automation tool lines | 3,513 | `wc -l security-automation/*.py` |
| Automation tool tests | 201 (59 + 142) | `pytest security-automation/tests` |
| Security Hub handler tests | 38 | same |
| Checkov result | **137 passed, 0 failed, 12 justified skips** | `checkov -d infrastructure/` |
| Bandit result | 0 at medium+; **0 `nosec`** | `bandit -ll` |
| pip-audit result | 21 packages, **0 vulnerabilities** | `pip-audit` |
| IAM analyzer on deployed policies | 1 INFO, **0 blocking** | `iam_policy_checker.py` |
| Local pipeline stages passing | **17 of 17** | `run_security_checks.sh` |
| Terraform files | 10 + 1 module | `ls infrastructure/terraform/*.tf` |
| CloudWatch alarms / metric filters | 8 / 5 | `monitoring.tf` |
| Remediation diff | 14 files, +1,744 / −312 | `git diff v1-pre-review v2-remediated` |
| Documented limitations | 9 (L1–L9) | `final-security-assessment.md` §12 |
| Accepted risks | 6 (AR-01–AR-06) | same §11.1 |
| Residual risk | 0 critical, 0 high, **2 medium, 14 low** | same |

---

## 4. Never claim these

| Do not say | Because |
|---|---|
| "Deployed to AWS" / "in production" | **Nothing was deployed.** No AWS account was used (L1) |
| "Validated infrastructure with Terraform" | `terraform fmt`/`validate`/`plan` were **never run** (L2). Say "statically analysed with Checkov and a custom reference linter" |
| "CI/CD pipeline running in production" | The workflow has **never executed** (L3). Say "implemented", and that it is mirrored by a local runner passing 17/17 |
| "CodeQL analysis identified…" | CodeQL has produced **no results at all** (L3) |
| "Reduced vulnerabilities by N%" | Invented. The honest figure is 15 findings identified and remediated |
| "Improved security posture by N%" | Not measurable, and an interviewer will ask how it was measured |
| "Prevented a breach" / any business impact | Synthetic data, no users, no incident |
| "Verified IAM least privilege" | The policy **document** was analysed; live IAM enforcement is unverified |
| "Penetration tested" | No offensive testing was performed — deliberately out of scope |
| "Led" / "collaborated with" / "mentored" | Solo project |
| "N years of experience" | A project is not employment history |
| "Independently reviewed" / "audited" | Author and reviewer are the same engineer (L7) |
| "Security Hub integration operational" | Security Hub was **never enabled** (L6). Say "implemented and unit-tested against synthetic ASFF events" |

---

## 5. Project line for the Projects section

> **AWS Proactive Security Engineering & Automated Risk Remediation Platform** — Python,
> FastAPI, Terraform, AWS (Lambda, API Gateway, Cognito, DynamoDB, IAM, KMS, CloudWatch),
> GitHub Actions
>
> Multi-tenant support API built as an application security engineering exercise: STRIDE
> threat model (16 threats), manual code review of a deliberately unreviewed first draft
> (15 confirmed findings, all remediated), 616-test suite including 141 regression tests
> each demonstrated to fail against the pre-remediation code, two original Python security
> CLIs, and a 5-stage gated security pipeline. Runs locally with no AWS account; all
> limitations and residual risks documented.
> `github.com/<user>/aws-proactive-security-platform`

---

## 6. How to talk about it

**Lead with the method, not the stack.** Anyone can list FastAPI and Terraform. Far fewer
can say "I wrote the insecure version first, reviewed it, and can show you the 93 tests that
failed before the fix."

**Volunteer the limitations.** Saying "nothing is deployed, so live IAM enforcement is
unverified — here are the 11 tests that are skipped for exactly that reason" builds more
credibility than any claim you could make instead. It also pre-empts the question that would
otherwise catch you out.

**Have one finding ready in detail.** F-001 is the best one: a local-development convenience
implemented as a silent runtime fallback in the production path, with the insecure mode as
the configured default. It is a realistic bug, the root cause is interesting, and the fix is
architectural rather than a patch.

**Know what you would do next.** Separate the membership table (AR-04), deploy to a sandbox
and run the 13 AWS-gated tests, and get an independent review. Knowing the top three gaps in
your own work is the signal.
