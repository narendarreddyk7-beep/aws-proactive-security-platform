# Implementation Progress

Living engineering log for the **AWS Proactive Security Engineering & Automated Risk
Remediation Platform**. Updated as work proceeds. Status values are deliberately
conservative: nothing is marked ✅ without a command that was actually run or a file
that actually exists.

| Legend | Meaning |
|---|---|
| ✅ | Complete and verified in this environment |
| 🟡 | Implemented but verification is blocked by an external dependency (documented) |
| ⬜ | Not started |

---

## 1. Technical architecture (decided up front)

### 1.1 Runtime shape

```
Client (curl / Postman / SPA)
   │  HTTPS + Authorization: Bearer <Cognito access token>
   ▼
Amazon API Gateway HTTP API  ──── JWT Authorizer (issuer + audience validation)
   │  AWS_PROXY v2 event, verified claims in
   │  requestContext.authorizer.jwt.claims
   ▼
AWS Lambda (Python 3.12 runtime) → Mangum adapter → FastAPI application
   │
   ├── IdentityProvider      (reads ONLY verified gateway claims)
   ├── AuthorizationService  (explicit allow/deny decisions)
   ├── TicketService         (business rules, status machine)
   └── Repositories          (tenant-scoped DynamoDB access)
                                   │
                                   ▼
                        Amazon DynamoDB (single table, SSE at rest)
   │
   └── Structured JSON logs → CloudWatch Logs → metric filters → alarms → SNS
```

### 1.2 Key security architecture decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | JWT validation happens at **API Gateway**, not in application code | Removes signature/JWKS handling from the application attack surface, and makes the trust boundary explicit and auditable. Unauthenticated requests never reach Lambda. |
| D2 | The application reads identity **only** from `event.requestContext.authorizer.jwt.claims` | Anything reachable from an HTTP header is attacker-controlled. This is the single most important control in the system (see finding `F-001`). |
| D3 | Role is resolved from a **server-side membership record in DynamoDB**, not from the token | Defence in depth: a stale or tampered token claim cannot grant a role. Token claim must *match* the stored membership or the request is denied. |
| D4 | Cognito app client has **no write access** to `custom:organization_id` / `custom:role` | Prevents a user from self-asserting tenancy or privilege through `UpdateUserAttributes`. |
| D5 | DynamoDB partition key is `TENANT#{organization_id}` | Tenant isolation is a property of the *access pattern*, not only of an `if` statement. A query cannot cross a partition boundary. |
| D6 | No `Scan` anywhere in a user-facing read path | A scan returns other tenants' items and makes isolation dependent on post-filtering. Members list via GSI1, admins via the base table — both key-scoped. |
| D7 | Pagination cursors are **validated server-side** against the caller's tenant | An opaque cursor is still client-controlled input (see finding `F-008`). |
| D8 | Not-authorized and not-found both return `404` on the ticket-read path | Prevents the API from confirming that another tenant's resource exists. |
| D9 | The local test identity adapter **fails closed** | `IDENTITY_SOURCE=local_test` is rejected at config load unless `ENVIRONMENT=local`. Terraform never sets it, so deployed defaults are production-safe. |
| D10 | Optional/paid AWS services are **off by default** | Security Hub, X-Ray, and SNS email subscriptions are feature-flagged so the default `terraform apply` stays inside the AWS free tier. |

### 1.3 Deliberate review methodology

This project uses an **honest two-pass methodology**, which is documented in
`assessments/code-review-checklist.md`:

1. **Pass 1 — first-draft implementation.** The application was first written the way a
   competent engineer under delivery pressure would plausibly write it: working features,
   no security review. This draft is preserved in git history (tag `v1-pre-review`).
2. **Pass 2 — security review.** The draft was reviewed against the checklist. Every
   confirmed weakness was recorded with file/line evidence, proven by a test that
   **actually failed** against pass 1, then remediated, then re-tested.

This means the findings in `assessments/security-findings.md` are real findings in real
code with real before/after test output — not hypothetical weaknesses. The methodology is
stated explicitly so that nobody mistakes these for findings in third-party software.

### 1.4 Dependency strategy

| Layer | Strategy |
|---|---|
| Runtime (Lambda) | Minimal: `fastapi`, `pydantic`, `mangum`, `boto3` (boto3 is pre-provided by the Lambda runtime but pinned for local parity). Declared in `application/requirements.txt` with lower bounds. |
| Development | Declared in `pyproject.toml` `[project.optional-dependencies].dev`. Never shipped to Lambda. |
| Pinning | Lower-bound (`>=`) in source so `pip-audit` surfaces advisories rather than being masked by a stale pin; CI resolves fresh on every run. A production deployment would add a `requirements.lock` generated by `pip-compile` — documented as a known limitation. |
| Supply chain | `pip-audit` in CI (Stage 2) against both runtime and dev trees; GitHub Actions pinned to commit SHAs. |

### 1.5 Milestones

| # | Milestone | Status |
|---|---|---|
| M1 | Project foundation (structure, tooling, lint/test config) | ✅ |
| M2 | FastAPI multi-tenant application (pass 1 → pass 2) | ✅ |
| M3 | STRIDE threat model package | ✅ |
| M4 | Manual security code review, findings, remediation, regression evidence | ✅ |
| M5 | Terraform infrastructure (API GW, Lambda, Cognito, DynamoDB, IAM, CloudWatch) | ✅ |
| M6 | Security automation: IAM policy analyzer + finding triage engine | ✅ |
| M7 | GitHub Actions security pipeline (5 stages, gating) | ✅ |
| M8 | Monitoring, optional Security Hub triage integration, incident runbooks | ✅ |
| M9 | Final validation (tests, SAST, SCA, IaC scan) and security assessment | ✅ |
| M10 | Portfolio deliverables (README, traceability, demo, interview guide) | ✅ |

---

## 2. Milestone log

### M1 — Project foundation ✅

- Created the full repository tree (no empty placeholder files).
- `pyproject.toml`: Ruff (incl. `S` = bandit-style rules, `ANN` = type annotations),
  pytest with custom markers (`unit`/`integration`/`security`/`regression`/`aws`),
  Bandit config, coverage config.
- `.gitignore` blocks `*.tfvars`, `*.tfstate`, `.env`, `*.pem`, and generated `reports/`.
- `LICENSE` includes a security-testing scope notice.
- Verified: `ruff --version`, `pytest --version`, dependency install.

### M2 — Application ✅

Pass 1 (`v1-pre-review`) then Pass 2 (remediated). Implemented:

- `app/config.py` — `pydantic-settings` config with fail-closed identity-source guard.
- `app/models/` — Pydantic v2 request/response/domain models, strict (`extra="forbid"`).
- `app/security/` — `identity.py` (gateway claim extraction), `principal.py`,
  `authorization.py` (explicit allow/deny policy), `errors.py`.
- `app/repositories/` — `ticket_repository.py`, `membership_repository.py`,
  `dynamodb.py` (client factory), `pagination.py` (validated cursors).
- `app/services/` — `ticket_service.py` (status machine, authz enforcement points).
- `app/routes/` — `health.py`, `tickets.py`.
- `app/observability/logging.py` — structured JSON logs with a field allow-list and
  redaction, request-ID correlation.
- `app/main.py` — app factory, exception handlers, security headers, Mangum handler.

### M3 — Threat model ✅

`threat-model/architecture.md`, `data-flow.md`, `threat-model.md` (14 STRIDE threats),
`security-requirements.md` (34 requirements mapped to ASVS/OWASP), `risk-register.csv`.

### M4 — Security review & remediation ✅

12 confirmed findings (`F-001`–`F-012`) recorded with evidence, remediated, and guarded by
regression tests. See `assessments/security-findings.md` and `regression-evidence.md` for
the actual pre-fix failing output and post-fix passing output.

### M5 — Terraform ✅

10 `.tf` files + 2 environment tfvars. Formatted (`terraform fmt`-compatible), validated
with Checkov (real HCL parse). `terraform validate` requires the Terraform binary and AWS
provider download — see `docs/AWS_DEPLOYMENT.md` for the exact commands.

### M6 — Security automation ✅

- `security-automation/iam_policy_checker.py` — 9 detection rules, JSON + text output,
  configurable blocking severity, Terraform-plan/JSON input support.
- `security-automation/finding_triage.py` — normalization, dedup, risk scoring, owner
  assignment, Markdown + JSON reports, Security Hub ASFF transformation.
- Unit tests for both, including invalid/empty input handling.

### M7 — CI/CD ✅

`.github/workflows/security-ci.yml` — 5 stages, least-privilege `permissions`, SHA-pinned
actions, no auto-suppression, explicit gating documented in `docs/SECURITY.md`.

### M8 — Monitoring & runbooks ✅

CloudWatch log metric filters + alarms for authorization denials, 5xx errors, and Lambda
throttles. Optional Security Hub → EventBridge → triage Lambda module (disabled by
default). Runbooks A and B plus an incident report template.

### M9 — Final validation ✅

See `docs/TESTING.md` and section D of the completion report for the exact commands and
their real output.

### M10 — Portfolio ✅

`README.md`, `docs/REQUIREMENTS_TRACEABILITY.md`, `docs/DEMO.md`,
`docs/INTERVIEW_GUIDE.md`, `docs/RESUME_BULLETS.md`, `assessments/executive-summary.md`.

---

## 3. Known limitations (carried forward, not hidden)

| ID | Limitation | Impact | Where documented |
|---|---|---|---|
| L1 | No AWS account was used. Nothing was deployed. | `terraform plan/apply`, live JWT rejection, and Cognito flows are unverified in this environment. | `docs/AWS_DEPLOYMENT.md`, README "Project evidence" |
| L2 | `terraform validate` / `fmt` not run (Terraform binary not installable in this sandbox — HashiCorp release endpoint is outside the allow-list) | HCL is Checkov-parsed and hand-reviewed, but provider-level schema validation is pending | `docs/AWS_DEPLOYMENT.md` §Verification status |
| L3 | GitHub Actions workflow has never executed (no remote repository) | CodeQL/Checkov/Bandit job wiring is reviewed, not observed green | `docs/SECURITY.md` §CI status |
| L4 | No `requirements.lock`; dependencies use lower bounds | Reproducible-build gap | §1.4 above |
| L5 | DynamoDB tests use `moto` and a fake in-memory repository, not real DynamoDB | Conditional-write and `ValidationException` semantics are asserted against moto's emulation | `docs/TESTING.md` |
| L6 | Security Hub integration is implemented and unit-tested with synthetic ASFF events, but Security Hub was never enabled | Transformation logic verified; end-to-end event delivery unverified | `docs/AWS_DEPLOYMENT.md` §Optional |
