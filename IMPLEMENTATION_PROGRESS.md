# Implementation Progress

Engineering log for the **AWS Proactive Security Engineering & Automated Risk Remediation
Platform**.

**Last updated:** 2026-10-23, after a full verification pass.

| Legend | Meaning |
|---|---|
| ✅ | Complete, and verified by a command actually run in this environment |
| 🟡 | Implemented, but verification is blocked by a documented external dependency |
| ⬜ | Not started |

> ### Correction to an earlier version of this file
>
> A previous revision of this document marked milestones M3, M4, M7, M8, M9 and M10 as ✅
> while the artefacts they referenced — `README.md`, `threat-model/`, `assessments/`,
> `runbooks/`, `docs/` and `.github/workflows/` — **did not exist on disk**. The
> application code, test suite, Terraform and automation tools were real and verified; the
> documentation was not written.
>
> That has been corrected: the missing artefacts are now written, and every status below is
> backed by a file that exists and a command whose output is recorded. A progress tracker
> that overstates completion is worse than no tracker, because it is the document a
> reviewer trusts to tell them where to look.

---

## 1. Architecture decided up front

### 1.1 Runtime shape

```
Client (curl / Postman / SPA)
   │  HTTPS + Authorization: Bearer <Cognito access token>
   ▼
Amazon API Gateway HTTP API  ──── JWT Authorizer (signature, issuer, audience, expiry)
   │  AWS_PROXY v2 event; verified claims in
   │  requestContext.authorizer.jwt.claims
   ▼
AWS Lambda (Python 3.12, arm64) → Mangum → FastAPI
   │
   ├── IdentityProvider      reads ONLY the verified gateway claims
   ├── AuthorizationService  explicit Decision allow/deny
   ├── TicketService         business rules + the single enforcement layer
   └── Repositories          tenant-scoped DynamoDB access
                                   │
                                   ▼
                        Amazon DynamoDB (single table, SSE + PITR)
   │
   └── Structured JSON logs → CloudWatch Logs → metric filters → 8 alarms → SNS
```

### 1.2 Key security decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | JWT validation at **API Gateway**, not in application code | No code path in the app accepts a token, so a token-parsing bug has nowhere to land. Unauthenticated requests never reach compute. Cost: not locally testable (11 skipped tests) |
| D2 | Identity read **only** from `requestContext.authorizer.jwt.claims` | Anything reachable from an HTTP header is attacker-controlled. The single most important control in the system (finding F-001) |
| D3 | Role resolved from a **server-side membership record**, not the token | A token is a cached snapshot; a user demoted five minutes ago still carries one. Revocation then takes effect immediately (finding F-002) |
| D4 | Cognito app client has **no write access** to `custom:organization_id` / `custom:role` | Closes self-asserted tenancy and privilege at the identity provider |
| D5 | DynamoDB partition key is `TENANT#{organization_id}` | Isolation becomes a property of the access pattern, not of remembering to filter |
| D6 | **No `Scan`** in any user-facing read path, **plus an explicit IAM `Deny`** | Two layers that fail differently: the code control can be undone by a refactor, the IAM one cannot (finding F-006) |
| D7 | GSI1 keyed on **tenant *and* user** | Keying on the user alone would surface one organization's tickets in a query scoped to another |
| D8 | Pagination cursors validated against the caller's partition | An opaque cursor is still client-controlled input (finding F-010) |
| D9 | `404` for both not-authorized and not-found on the read path | Prevents the API confirming that another tenant's resource exists (finding F-008) |
| D10 | Authorization returns an explicit `Decision`, never a bare `bool` | A forgotten check becomes visible in review (finding F-003) |
| D11 | Log **field allow-list**, not a deny-list | The failure mode of forgetting is a missing dashboard field, not customer data in a log (finding F-007) |
| D12 | The local identity adapter **fails closed**, three independent ways | It is a deliberate authentication bypass, so containment has to be redundant (finding F-012) |
| D13 | IAM policies as **committed JSON**, not `aws_iam_policy_document` | A data source renders only at plan time, so CI could not otherwise gate the policy that actually deploys (finding F-005) |
| D14 | Optional and paid services **off by default** | Security Hub, X-Ray and SNS email are feature-flagged, so the default apply stays near the free tier |

Full reasoning, including rejected alternatives: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### 1.3 Review methodology

A deliberate **two-pass** approach, disclosed in full:

1. **Pass 1** — the application written the way a competent engineer under delivery pressure
   plausibly writes it: feature-complete, idiomatic, not security-reviewed. Tag
   `v1-pre-review` (`31f4335`).
2. **Pass 2** — reviewed against a 60-item checklist. Every confirmed weakness: a test that
   **fails** against pass 1 → a finding record with file/line evidence → a fix → re-run →
   marked `@pytest.mark.regression`. Tag `v2-remediated` (`c9ec2b4`).

So the findings are real findings in real code with real before/after output. **The author
of pass 1 and the reviewer of pass 2 are the same engineer** — the weakest form of review,
and stated wherever it is relevant.

### 1.4 Dependency strategy

| Layer | Strategy |
|---|---|
| Runtime (Lambda) | Minimal: `fastapi`, `pydantic`, `pydantic-settings`, `mangum`, `boto3` |
| Development | `[project.optional-dependencies].dev`; never shipped to Lambda |
| Pinning | Lower bounds (`>=`) so `pip-audit` surfaces advisories rather than being masked by a stale pin. A lock file is the documented gap (L4 / S-2) |
| Supply chain | `pip-audit` in CI against runtime **and** dev trees; weekly scheduled re-scan |

---

## 2. Milestones

| # | Milestone | Status |
|---|---|---|
| M1 | Project foundation (structure, tooling, lint/test config) | ✅ |
| M2 | FastAPI multi-tenant application (pass 1 → pass 2) | ✅ |
| M3 | STRIDE threat model package | ✅ |
| M4 | Manual code review, findings, remediation, regression evidence | ✅ |
| M5 | Terraform infrastructure | 🟡 — written and statically analysed; `terraform validate` not run (L2) |
| M6 | Security automation: IAM analyzer + finding triage engine | ✅ |
| M7 | GitHub Actions security pipeline | 🟡 — implemented and locally mirrored; never executed (L3) |
| M8 | Monitoring, optional Security Hub triage, incident runbooks | 🟡 — runbooks ✅; alarms never observed firing (L1) |
| M9 | Final validation and security assessment | ✅ |
| M10 | Portfolio deliverables | ✅ |

---

## 3. Milestone log

### M1 — Project foundation ✅

Full repository tree, no empty placeholder files. `pyproject.toml` configures Ruff
(including `S` bandit-equivalent and `ANN` annotation rule sets), pytest with five custom
markers, Bandit, and coverage. `.gitignore` blocks `*.tfvars`, `*.tfstate*`, `.env`,
`*.pem` and `reports/`. `LICENSE` carries a security-testing scope notice.

`*.md` was later added to Ruff's `exclude` — Ruff will reformat a fenced ` ```python ` block
inside markdown, which silently edits the finding evidence. Evidence has to match what was
actually in the repository at `v1-pre-review`.

### M2 — Application ✅

24 modules. `config.py` (fail-closed guards), `models/` (Pydantic v2, `extra="forbid"`),
`security/` (identity, principal, authorization, errors, HTTP headers), `repositories/`
(tickets, memberships, keys, pagination, client factory), `services/ticket_service.py`
(the single enforcement layer), `routes/`, `observability/` (allow-listed JSON logging),
`main.py` (app factory, exception handlers, Mangum handler).

### M3 — Threat model ✅

`architecture.md` (15 components, 6 actor types, 7 trust boundaries, Mermaid diagram),
`data-flow.md` (4 diagrams + a 10-row cross-boundary table naming the enforcing file),
`threat-model.md` (**16 STRIDE threats**, plus threats considered-and-discarded with
reasons), `security-requirements.md` (**91 requirements**: 76 verified, 11 AWS-gated, 4
open), `risk-register.csv` (16 rows × 19 columns, CSV-validated).

### M4 — Security review and remediation ✅

**15 confirmed findings** (F-001–F-015) and **7 observations** kept separate. Remediation
diff: 14 files, +1,744 / −312.

Regression experiment, run today:

```
$ python -m pytest tests/security -q      # @ v1-pre-review
84 failed, 92 passed

$ python -m pytest tests/security -q      # @ HEAD
176 passed
```

F-005 is recorded as `Validated: partial` — the pre-remediation IAM policy is not preserved
in git, so there is no before/after test diff. Its evidence is a design-decision record plus
a CI gate self-test. Flagged rather than smoothed over.

### M5 — Terraform 🟡

10 `.tf` files + 1 module + 2 environment tfvars. API Gateway HTTP API with a Cognito JWT
authorizer and per-route authorization; Lambda (arm64, reserved concurrency, CMK-encrypted
env vars); Cognito user pool with no client write access to the tenancy/role claims;
DynamoDB single table with GSI1; least-privilege IAM as committed JSON plus a permissions
boundary; KMS CMK; CloudWatch log groups, 5 metric filters, 8 alarms, 4 Insights queries, 1
dashboard; optional Security Hub module (off by default).

| Verified | Result |
|---|---|
| Checkov | 134 passed, **0 failed**, 12 inline justified skips |
| Custom HCL reference linter | Pass (root + module) |
| IAM policy analysis | 1 INFO, **0 blocking** |
| `terraform fmt` / `validate` / `plan` | **NOT RUN** — binary not installable (L2) |

### M6 — Security automation ✅

`iam_policy_checker.py` (1,586 lines, 11 rules, 59 tests): confirmed/needs-context
confidence, directory and Terraform-plan input, JSON + text output, severity gating, and
`--list-rules` printing its own documented limitations.

`finding_triage.py` (1,927 lines, 142 tests): normalises 5 tool formats + ASFF,
deterministic deduplication, configurable multiplicative risk scoring, owner rules,
cross-run status tracking via `--previous`, JSON + Markdown reports.

Plus 38 tests for the Security Hub triage Lambda. **239 automation tests, all passing.**

### M7 — CI/CD 🟡

`.github/workflows/security-ci.yml`: 5 stages, `permissions: {}` at workflow level with
per-job minimums, `pull_request` (not `pull_request_target`), no deployment job, weekly
scheduled re-scan, and a `security-gate` job that **treats a skipped security job as a
failure**. Includes a gate self-test asserting the IAM analyzer rejects a known-insecure
fixture. YAML validated.

**Never executed** — no remote repository, so CodeQL has produced no results (L3). Actions
are pinned to tags rather than commit SHAs, because the SHAs could not be resolved in this
environment and unverifiable hashes would look more trustworthy while being less so; the
workflow header carries the exact `gh api` loop to convert them.

### M8 — Monitoring and runbooks 🟡

Metric filters and alarms for authorization denials, authentication failures, role-claim
mismatches, insecure-adapter activation, unhandled errors, gateway 401s, and Lambda /
DynamoDB throttles. One Insights query detects cross-tenant probing via
`resource_not_found` volume with distinct resource ids — the signal that replaces the 403
the API deliberately does not return.

Runbooks ✅: `authorization-alert-triage.md` (keyed to real alarm names and thresholds, with
a 6-option containment framework), `cloud-security-finding-response.md`,
`incident-report-template.md`. Each documents its own detection gaps.

**No alarm has ever fired** — nothing is deployed, so the thresholds are reasoned estimates
(L1).

### M9 — Final validation ✅

```
$ ./scripts/run_security_checks.sh
Passed: 15   Failed: 0
```

Three genuine failures were found and **fixed** during this pass rather than written off:

| Stage | Failure | Fix |
|---|---|---|
| Ruff lint | 4 violations in `scripts/validate_terraform.py` (2× `E501`, 2× `ARG001`) | Lines wrapped; intentionally-unused parameters renamed `_parsed` with a docstring explaining the uniform-signature reason |
| Ruff format | 1 file unformatted | `ruff format` applied |
| Finding triage | `reports/checkov.json: Is a directory` — Checkov treats `--output-file-path` as a **directory**, so no JSON report was produced and the aggregation stage failed | Report captured from stdout; comment added explaining why |

A fourth correction came from writing the docs: `docs/SETUP.md` initially claimed the health
endpoint discloses no configuration. It returns the **environment label**. The wording was
corrected in `SETUP.md`, the AR-02 accepted-risk entry, the `api.tf` Checkov skip
justification, and `threat-model/architecture.md`.

### M10 — Portfolio ✅

`README.md`, plus `docs/`: `SETUP.md`, `DEMO.md`, `ARCHITECTURE.md`, `SECURITY.md`,
`TESTING.md`, `AWS_DEPLOYMENT.md`, `REQUIREMENTS_TRACEABILITY.md`, `INTERVIEW_GUIDE.md`,
`RESUME_BULLETS.md`. Assessment set: `executive-summary.md`,
`final-security-assessment.md`, `security-findings.md`, `remediation-tracker.md`,
`regression-evidence.md`, `code-review-checklist.md`.

`scripts/local_server.py` was added so the demo is reproducible with no AWS account and no
Docker — it serves the real application against an in-process mocked DynamoDB. **Every
transcript in `docs/DEMO.md` was captured from a real run of it**, including the live
verification that zero ticket content reaches the log stream.

---

## 4. Verification ledger

Everything below is a real command and its real result, 2026-10-23.

| Check | Result |
|---|---|
| `pytest -q` | **584 passed, 11 skipped** |
| `pytest -m unit` / `integration` / `security` / `regression` | 377 / 43 / 258 / 122 — all pass |
| `pytest -m aws` | 11 skipped, each naming its prerequisite |
| `pytest tests/security` @ `v1-pre-review` | **84 failed, 92 passed** |
| `pytest tests/security` @ `HEAD` | **176 passed** |
| `pytest --cov` | **89%** (2,058 statements, 668 branches) |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 64 files already formatted |
| `bandit -ll` | 0 at medium+; 4,780 lines; **0 `nosec`** |
| `pip-audit` | 21 packages, **0 vulnerabilities** |
| `checkov -d infrastructure/` | 134 passed, **0 failed**, 12 justified skips |
| `scripts/validate_terraform.py` | Pass (root + module) |
| `iam_policy_checker.py` on deployed policies | 1 INFO, **0 blocking** |
| IAM gate self-test | Insecure fixture correctly **rejected** |
| `finding_triage.py` on 4 scanner reports | 2 open (P4), 0 duplicates |
| `scripts/run_security_checks.sh` | **15 / 15 stages pass** |
| `scripts/local_server.py` + full demo flow | All 16 demo assertions behaved as documented |
| Ticket content in logs after the demo | **0 occurrences** |
| `terraform fmt` / `validate` / `plan` | **NOT RUN** (L2) |
| AWS deployment | **NOT PERFORMED** (L1) |
| GitHub Actions run | **NEVER EXECUTED** (L3) |

---

## 5. Known limitations

Carried forward, not hidden. Full detail:
[`assessments/final-security-assessment.md`](assessments/final-security-assessment.md) §12.

| ID | Limitation | Where documented |
|---|---|---|
| L1 | No AWS account used; nothing deployed | `docs/AWS_DEPLOYMENT.md`, README |
| L2 | `terraform validate` / `fmt` / `plan` never run — `releases.hashicorp.com` is outside this environment's egress allow-list (proxy returned `403 to CONNECT`) | `docs/AWS_DEPLOYMENT.md` |
| L3 | CI workflow never executed; CodeQL has produced no results; actions tag-pinned not SHA-pinned | `docs/SECURITY.md` §4 |
| L4 | No `requirements.lock`; lower-bound pinning | §1.4 above |
| L5 | DynamoDB behaviour asserted against `moto`, not the real service | `docs/TESTING.md` |
| L6 | Security Hub never enabled; ASFF transformation unit-tested only | `docs/AWS_DEPLOYMENT.md` §7 |
| L7 | Author and reviewer are the same engineer | `assessments/code-review-checklist.md` §1 |
| L8 | No load, fuzz or penetration testing | `docs/TESTING.md` §8 |
| L9 | Membership provisioning is out of band and unimplemented | `docs/ARCHITECTURE.md` §4 |

---

## 6. Next steps

Ranked. Full list of 13 deferred safeguards:
[`assessments/remediation-tracker.md`](assessments/remediation-tracker.md) §3.

| # | Action | Addresses |
|---|---|---|
| 1 | Split memberships into a separate DynamoDB table so the execution role is read-only on them | AR-04 / T-06 — the last Medium residual risk with a clean fix |
| 2 | Deploy to a sandbox AWS account and run the 11 AWS-gated tests | L1, L2, L5 |
| 3 | Push to GitHub and observe one pipeline run | L3 — CodeQL has produced nothing so far |
| 4 | Generate a dependency lock file | L4 |
| 5 | Mandate MFA for the administrator role; shorten the production access-token TTL | AR-03 |
| 6 | Add WAF rate-based rules and per-tenant usage plans | AR-05 |
| 7 | Independent security review by another engineer | L7 |
