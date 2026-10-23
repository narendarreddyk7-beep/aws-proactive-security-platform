# Final Security Assessment

**System:** Multi-Tenant Customer Support API (AWS Proactive Security Engineering &
Automated Risk Remediation Platform)
**Assessment period:** October 2026
**Assessed version:** `8cb87f5` (application remediation at tag `v2-remediated`)
**Assessor:** Security Engineering (this project)
**Classification:** Internal — portfolio project, synthetic data only

---

## 1. Executive summary

A multi-tenant support-ticket API was designed, built, threat-modelled, security-reviewed
and remediated. The review examined 2,058 statements of application and automation code
plus 10 Terraform files, and **confirmed 15 findings** — one Critical, four High, seven
Medium, three Low. **All 15 are remediated**, each guarded by a regression test that was
first demonstrated to fail against the vulnerable code.

The single most serious finding (**F-001**) was a complete authentication bypass: the
identity resolver fell back to client-supplied `X-User-Id` / `X-Org-Id` headers when the
API Gateway authorizer context was absent, and the insecure identity source was the
**configured default**. Any unauthenticated caller who could reach the function could
assert an arbitrary user in an arbitrary tenant. Two further findings (**F-003**, **F-004**)
independently allowed cross-tenant and cross-user data access by any authenticated user —
including a cross-tenant **write** available by adding one JSON field to a request body.

The remediated system enforces tenant isolation **structurally** rather than
procedurally: the DynamoDB partition key is derived from a gateway-verified identity, a
member's listing is narrowed by an index key condition rather than a post-query filter,
`dynamodb:Scan` is explicitly denied in IAM, and the role a caller holds is read from a
server-side membership record instead of a token claim. The practical consequence is that
the most common multi-tenant breach pattern — "the filter was dropped in a refactor" — has
no code path to travel down.

**Verification is complete for everything testable without an AWS account, and honestly
incomplete beyond that.** 584 tests pass, 11 are explicitly skipped because they require a
deployed environment. `terraform validate` was never run: the Terraform binary cannot be
installed here because `releases.hashicorp.com` is outside this environment's egress
allow-list. **Nothing has been deployed to AWS.** Those gaps are stated in §12 and are not
represented as anything else.

### Posture at a glance

| Dimension | Assessment |
|---|---|
| Authentication | **Strong** — validation delegated to the gateway; application reads verified claims only; three independent guards on the local adapter |
| Authorization | **Strong** — explicit `Decision` objects, enforcement concentrated in one layer, role from server-side record |
| Tenant isolation | **Strong** — structural (partition key + index + IAM Deny), not procedural |
| Input validation | **Strong** — `extra="forbid"` everywhere, typed identifiers, bounded sizes |
| Data protection | **Strong** — log field allow-list, CMK encryption, no content in logs or errors |
| IAM least privilege | **Strong, one known gap** — enumerated actions and explicit Denies; `PutItem` is table-scoped rather than sort-key-scoped (S-1) |
| Detection | **Adequate, unverified** — metric filters and 8 alarms defined; never observed firing |
| Availability | **Adequate** — throttling and reserved concurrency; no per-tenant quota (AR-05) |
| Supply chain | **Adequate** — SAST/SCA/IaC scanning in CI; no lock file (S-2) |
| Deployment assurance | **Not established** — nothing deployed; `terraform validate` not run |

---

## 2. Project and system scope

### In scope

| Component | Artefact |
|---|---|
| FastAPI application, 24 modules | `application/app/**` |
| IAM policy documents | `infrastructure/terraform/policies/*.json` |
| Terraform configuration, 10 files + 1 module | `infrastructure/**` |
| Security automation, 2 CLIs (3,513 lines) | `security-automation/*.py` |
| Test suite, 595 tests | `tests/**`, `security-automation/tests/**` |
| CI/CD pipeline | `.github/workflows/security-ci.yml` |

### Out of scope

Third-party library internals (delegated to `pip-audit`); AWS-managed service
implementations (shared-responsibility model); client applications (none exist); load and
performance testing; physical and personnel security; any live AWS environment.

### Data classification

All data is **synthetic**. Ticket content is treated as confidential customer data for
design purposes because, in production, free-text support tickets reliably contain
identifiers, hostnames and occasionally credentials. No real customer data was used at any
point.

---

## 3. Security objectives

Ranked, because ranking is what makes trade-offs decidable.

| # | Objective | Why it ranks here |
|---|---|---|
| O1 | **No cross-tenant data access, read or write** | A multi-tenant breach is unrecoverable commercially and reportable legally |
| O2 | **No unauthenticated access to tenant data** | Prerequisite for O1 |
| O3 | **No privilege escalation within a tenant** | Bounds the damage from one compromised account |
| O4 | **Customer content stays out of logs and error responses** | Logs and error pipelines have wider readership and longer retention than the database |
| O5 | **Every security-relevant decision is attributable** | An unlogged denial cannot be alerted on or investigated |
| O6 | **Least privilege at the cloud control plane** | Caps the blast radius of any application-layer compromise |
| O7 | **Security regressions are caught before merge** | A control without a gate decays |
| O8 | **Availability under abuse** | Ranked last deliberately: degraded availability is recoverable, a breach is not |

---

## 4. Architecture overview

```
Client ──HTTPS+Bearer──▶ API Gateway HTTP API ──▶ Lambda (Mangum ▶ FastAPI) ──▶ DynamoDB
                         │  JWT authorizer         │  IdentityProvider           single table
                         │  issuer + audience      │  AuthorizationService       PK=TENANT#org
                         │  signature + expiry     │  TicketService              SK=TICKET#id
                         │  throttling             │  Repositories               GSI1 per member
                         ▼                         ▼
                    401 (never reaches Lambda)   CloudWatch Logs ─▶ metric filters ─▶ alarms ─▶ SNS
```

Four decisions carry most of the security weight:

1. **Token validation happens at the gateway, not in application code.** The application
   has no code path that accepts a token, so a token-parsing vulnerability has nowhere to
   land. Unauthenticated requests never reach compute.
2. **Identity comes only from `requestContext.authorizer.jwt.claims`.** Everything an HTTP
   client can influence crosses the same boundary in the same event object; reading from
   anywhere else is what F-001 was.
3. **The organization is the DynamoDB partition key.** Isolation becomes a property of the
   access pattern. A `Query` physically cannot return another partition's items, so
   isolation does not depend on remembering a filter.
4. **Role comes from a server-side membership record, not the token.** A token is a cached
   snapshot; a user demoted five minutes ago still carries one asserting the old role.

Full detail: [`../threat-model/architecture.md`](../threat-model/architecture.md) and
[`../threat-model/data-flow.md`](../threat-model/data-flow.md).

---

## 5. Threat modelling methodology

STRIDE applied **per data flow** rather than per component, because in this system every
interesting threat lives at a boundary crossing. Ten cross-boundary flows (DF1–DF10) were
enumerated; for each, all six STRIDE categories were considered and discarded where not
credible.

**16 threats** survived (T-01 – T-16), each recording affected component, category, trust
boundary, preconditions, business impact, likelihood, severity, existing mitigations,
recommended safeguards, verification method and residual risk. Threats considered and
**discarded** are listed with reasons (SQL injection, XSS, CSRF, insecure deserialization,
SSRF, path traversal), so the analysis is auditable rather than selectively reported.

Ten of the 16 threats were found **realised** in the pre-review implementation. That is the
point of the two-pass method: the threat model is not a parallel document asserting safety,
it is what the review was conducted against.

Scoring is deliberately plain — Likelihood High/Medium/Low keyed to the attacker capability
required, Severity Critical/High/Medium/Low keyed to blast radius. Residual risk is never
recorded as "none"; a residual of Low still means "re-check after a refactor".

Artefacts: [`../threat-model/threat-model.md`](../threat-model/threat-model.md),
[`../threat-model/risk-register.csv`](../threat-model/risk-register.csv) (16 rows, 19
columns), [`../threat-model/security-requirements.md`](../threat-model/security-requirements.md)
(91 requirements: 76 verified, 11 AWS-gated, 4 not implemented).

---

## 6. Security review methodology

A deliberate **two-pass** approach, disclosed in full because the alternative would be
misleading:

**Pass 1.** The application was written the way a competent engineer under delivery
pressure plausibly writes it — feature-complete, idiomatic, not security-reviewed, with
convenience chosen where convenience was the obvious path. Preserved at tag
`v1-pre-review`.

**Pass 2.** Reviewed line by line against a 10-domain, 60-item checklist. For each
confirmed weakness: write a test that **fails** against pass 1 → record the finding with
file/line evidence → fix → re-run → mark `@pytest.mark.regression`.

**What this is:** a real review of real code, with real failing tests as evidence and a
real remediation diff (14 files, +1,744/−312).

**What this is not:** a claim to have found vulnerabilities in third-party software, and
not a penetration test. **The author of pass 1 and the reviewer of pass 2 are the same
engineer** — the weakest form of review. A genuine second pair of eyes would find things
this review did not. Stated here rather than buried.

Findings are recorded as **confirmed** only where there is a concrete code path and a test
demonstrating the behaviour. Seven items that did not meet that bar are recorded separately
as **observations** (O-1 – O-7) and are excluded from the finding counts.

Artefacts: [`code-review-checklist.md`](code-review-checklist.md),
[`security-findings.md`](security-findings.md).

---

## 7. Verified findings

| ID | Finding | Severity | CWE | Identified | Validated | Remediated | Retested |
|---|---|---|---|---|---|---|---|
| F-001 | Authentication bypass via client-controlled identity headers | **Critical** | CWE-290 | ✅ | ✅ | ✅ | ✅ |
| F-002 | Privilege escalation through a self-asserted role claim | High | CWE-269 | ✅ | ✅ | ✅ | ✅ |
| F-003 | Authorization check defined but never enforced on update | High | CWE-862 | ✅ | ✅ | ✅ | ✅ |
| F-004 | Mass assignment permits cross-tenant writes | High | CWE-915 | ✅ | ✅ | ✅ | ✅ |
| F-005 | Over-privileged Lambda execution role | Medium | CWE-250 | ✅ | ⚠️ partial | ✅ | ✅ |
| F-006 | Tenant isolation dependent on a filter over a full scan | High | CWE-639 | ✅ | ✅ | ✅ | ✅ |
| F-007 | Customer content and bearer tokens written to logs | Medium | CWE-532 | ✅ | ✅ | ✅ | ✅ |
| F-008 | Information disclosure through error responses | Medium | CWE-209 | ✅ | ✅ | ✅ | ✅ |
| F-009 | Unbounded pagination and request field sizes | Medium | CWE-770 | ✅ | ✅ | ✅ | ✅ |
| F-010 | Pagination cursor forwarded to the database unvalidated | Medium | CWE-639 | ✅ | ✅ | ✅ | ✅ |
| F-011 | Unvalidated identifiers permit storage-key injection | Medium | CWE-20 | ✅ | ✅ | ✅ | ✅ |
| F-012 | Insecure-by-default configuration | Medium | CWE-1188 | ✅ | ✅ | ✅ | ✅ |
| F-013 | Missing ticket lifecycle controls | Low | CWE-285 | ✅ | ✅ | ✅ | ✅ |
| F-014 | Missing HTTP security response headers | Low | CWE-693 | ✅ | ✅ | ✅ | ✅ |
| F-015 | Unconditional writes silently replace records | Low | CWE-362 | ✅ | ✅ | ✅ | ✅ |

**15 identified · 14 fully validated · 15 remediated · 15 retested · 0 open.**

The three findings a reviewer should look at first, because they are the ones that would
have caused a breach:

- **F-001** — unauthenticated, remote, attacker-chosen tenant *and* user, full read/write.
- **F-004** — cross-tenant **write** by any authenticated user via one extra JSON field.
  The regression evidence captures a `201 Created` placing a ticket in the victim tenant.
- **F-003** — `can_update_ticket()` defined and never called. The defect was invisible
  precisely *because* the helper existed.

---

## 8. Remediation decisions

Where more than one fix was available, the choice and its reasoning:

| Finding | Options considered | Chosen | Reasoning |
|---|---|---|---|
| F-001 | (a) keep the header fallback but require a shared secret; (b) delete the fallback and make the local adapter explicitly selected | **(b)** | A shared secret is another credential to manage and leak, and the fallback would still trigger exactly when the trusted context is missing — the condition an attacker creates |
| F-002 | (a) trust the token claim but shorten TTL; (b) resolve role from a server-side record on every request | **(b)** | A short TTL narrows the stale-privilege window; it does not close it. Cost is one `GetItem` per request, consciously accepted (O-2) |
| F-003 | (a) add the missing `if can_update_ticket(...)`; (b) change the policy's return type so a forgotten check is visible | **(b)** | (a) fixes this instance; (b) fixes the class. An unused `Decision` stands out in review; an unused `bool` does not |
| F-004 | (a) strip server-controlled fields in the service; (b) remove them from the request schema and forbid unknown fields | **(b)** | Stripping is a step that can be forgotten. An absent field cannot be populated, and `extra="forbid"` makes probing visible as a logged 422 instead of a silent drop |
| F-006 | (a) keep `Scan` and harden the filter; (b) redesign keys so tenancy is in the partition key, add GSI1 for the member path | **(b)** | A filter makes isolation a remembered step. A partition key makes it structural — and IAM can then deny `Scan` outright |
| F-007 | (a) deny-list sensitive field names; (b) allow-list renderable fields | **(b)** | A deny-list fails the moment someone adds a field. With an allow-list, the failure mode of forgetting is a missing dashboard field, not customer data in a log |
| F-008 | (a) 403 for cross-tenant, 404 for missing; (b) 404 for both | **(b)** | (a) is an existence oracle. Because reads are partition-scoped, both cases produce the same `None` — the indistinguishability is structural, not a branch that could be forgotten |
| F-010 | (a) sign the cursor; (b) validate the cursor's partition against the caller | **(b)** | A signature proves *we issued it*, not that we issued it *to this tenant*. Checking the partition is simpler, stronger, and needs no key management |
| F-005 | (a) `aws_iam_policy_document` data sources; (b) committed JSON policy templates | **(b)** | A data source is rendered only at plan time, so the policy cannot be inspected without AWS credentials. Committed JSON lets CI gate the document that actually deploys, and makes permission changes reviewable as policy diffs |

---

## 9. Automated security controls

Five pipeline stages, `.github/workflows/security-ci.yml`, mirrored by
`scripts/run_security_checks.sh` so a developer can reproduce a CI failure locally.

| Stage | Tool | Gate | Verified result (2026-10-23) |
|---|---|---|---|
| 1 Code quality | Ruff lint + format (incl. `S` bandit rules, `ANN`) | any violation fails | All checks passed; 65 files formatted |
| 2 AppSec | CodeQL (Python, `security-extended`) | alerts surface in Security tab | **Never executed** (L3) |
| 2 AppSec | Bandit | medium severity+ fails | 0 at medium+; 0 `nosec`; 4,780 lines |
| 2 AppSec | pip-audit | any known vulnerability fails | 21 packages, 0 vulnerabilities |
| 3 IaC | Custom HCL reference linter | any error fails | Pass (root + module) |
| 3 IaC | Checkov | any failed check fails | 134 passed, 0 failed, 12 justified skips |
| 3 IaC | **`iam_policy_checker.py`** (own tool) | high severity+ fails | 1 INFO, 0 blocking |
| 3 IaC | **IAM gate self-test** | insecure fixture *must* fail | Confirmed rejected |
| 4 Tests | pytest unit / integration / security / regression | any failure fails | 584 passed, 11 skipped |
| 5 Reporting | **`finding_triage.py`** (own tool) | aggregates, dedups, prioritises | 2 open (P4), 0 duplicates |

Two custom tools, both with their own unit tests:

- **`iam_policy_checker.py`** (1,586 lines, 11 rules IAM001–IAM011): admin wildcards,
  service-wide wildcards, unscoped resources, privilege-escalation primitives, unscoped
  data/secret reads, inverted matching (`NotAction`), wildcard principals, confused-deputy
  gaps, destructive/anti-forensic actions, missing `Sid`, legacy policy version. Classifies
  every finding `confirmed` or `needs_context`, and **documents its own limitations** — it
  does not claim IAM policy-evaluation equivalence or parity with AWS IAM Access Analyzer.
- **`finding_triage.py`** (1,927 lines): normalizes Checkov, Bandit, pip-audit, its own IAM
  output and Security Hub ASFF into one schema; stable deduplication; configurable
  multiplicative risk scoring; owner assignment by rule; cross-run status tracking
  (new/open/overdue/newly-resolved); JSON + Markdown reports.

**Nothing is auto-suppressed.** The 12 Checkov skips are inline, per-resource, and each
carries a written justification referencing an accepted risk. There is no baseline file and
no blanket `--skip-check`. The Bandit false positive is left visible rather than silenced
with `# nosec` (repository `nosec` count: **0**).

Pipeline security: least-privilege `permissions` per job, SHA-pinned actions, no long-lived
AWS credentials, `pull_request` trigger with no deployment job.

---

## 10. Testing evidence

```
$ python3 -m pytest -q
584 passed, 11 skipped, 148 warnings in 11.44s

$ python3 -m pytest -q --cov
TOTAL  2058 stmts  183 miss  668 branch  83 brpart  89% cover
```

| Suite | Collected | Result |
|---|---|---|
| `unit` | 377 | pass |
| `integration` | 43 | pass |
| `security` | 258 | pass |
| `regression` | 122 | pass |
| `aws` | 11 | **skipped** — named prerequisite missing |

**The regression experiment is the central piece of evidence.** The security suite, run
unchanged against the pre-review code:

```
$ python3 -m pytest tests/security -q        # @ v1-pre-review
84 failed, 92 passed

$ python3 -m pytest tests/security -q        # @ HEAD
176 passed
```

Each of the 14 fully-validated findings maps to named tests that fail on one side and pass
on the other. Verbatim output, including the captured `201 Created` cross-tenant write and
the log lines showing customer content being written, is in
[`regression-evidence.md`](regression-evidence.md).

The 11 skips are explicit and name their prerequisite (`SUPPORT_API_BASE_URL`,
`SUPPORT_API_EXPIRED_TOKEN`, `SUPPORT_API_TABLE_NAME`). They are **present and skipped
rather than absent**, so the suite reports the gap instead of concealing it.

---

## 11. Residual risk

### 11.1 Accepted risks

| ID | Risk | Rating | Rationale | Owner | Review |
|---|---|---|---|---|---|
| **AR-01** | KMS key policies use `Resource: "*"` (Checkov `CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_356`) | Low | In a *key* policy, `Resource: "*"` denotes the key itself — it is the only legal form, and the account-root statement is mandatory for key manageability. The discretionary service grants are condition-constrained. A true positive in an identity policy; a false positive here | Cloud Security | 2027-04-23 |
| **AR-02** | `GET /v1/health` is unauthenticated (`CKV_AWS_309`) | Low | Intentional liveness probe. Returns a static payload naming only the service, application version and environment label (`dev`/`production`) — deliberately **not** the table name, region, or any identity-provider detail, which `tests/security/test_api_behaviour.py::test_health_endpoint_does_not_disclose_configuration` asserts by setting a distinctive table name and region and requiring neither appears. The version and environment are accepted as low-value disclosure in exchange for an operator being able to confirm which stage they reached | Cloud Security | 2027-04-23 |
| **AR-03** | Bearer-token theft and replay (T-02) | Medium | Inherent to the OAuth bearer model. Mitigated by short token TTL, optional MFA, Cognito advanced security, TLS and per-request audit logging. Eliminating it needs proof-of-possession (DPoP/mTLS), which the client application would have to support | Product + Security | 2026-12-23 |
| **AR-04** | Execution role's `PutItem` is table-scoped, not sort-key-scoped (T-06) | Medium | IAM cannot constrain a sort-key prefix — `dynamodb:LeadingKeys` governs the partition key only. Compensated by: no code path writes a `USER#` key (test-asserted), conditional writes, explicit `Deny` on delete/bulk-write, permissions boundary, PITR, `role_claim_mismatch` alarm. **The clean fix (S-1) is the top-priority next step** | Cloud Security | **2026-11-23** |
| **AR-05** | No per-tenant availability quota (T-13) | Medium | Reserved concurrency protects the account but *is* the mechanism by which one tenant's flood becomes everyone's outage, because the function is shared. Availability is objective O8 — ranked last deliberately | Cloud Security | 2026-12-23 |
| **AR-06** | Lambda not in a VPC; no DLQ; no code signing (`CKV_AWS_117`, `CKV_AWS_116`, `CKV_AWS_272`) | Low | The function reaches only DynamoDB, KMS and CloudWatch endpoints, so a VPC adds cost and cold-start latency with no security gain. Invocations are synchronous, so a DLQ has no event to replay. Code signing needs a Signer profile and a CI signing step (S-13) | Cloud Security | 2027-04-23 |

### 11.2 Residual risk after remediation

| Residual | Risks | IDs |
|---|---|---|
| **Low** | 13 | R-01, R-03, R-04, R-05, R-07, R-08, R-09, R-10, R-11, R-12, R-14, R-15, R-16 |
| **Medium** | 3 | R-02 (token replay), R-06 (membership tampering), R-13 (flooding) |
| **High / Critical** | 0 | — |

No residual risk is recorded as "none". Every Low rating means "the control is verified
today; re-verify after a refactor", and the re-review triggers are listed in
[`code-review-checklist.md`](code-review-checklist.md) §6.

---

## 12. Known limitations

Stated plainly. Each is a real gap in assurance, not a formality.

| ID | Limitation | What it means for confidence |
|---|---|---|
| **L1** | **Nothing was deployed to AWS.** No account was used. | `terraform plan/apply/destroy` unexercised. Live JWT rejection, Cognito flows, real IAM enforcement and alarm firing are all **unverified**. Infrastructure confidence rests on static analysis and review only |
| **L2** | **`terraform fmt` / `validate` / `plan` were never run.** The binary cannot be installed: `releases.hashicorp.com` is outside this environment's egress allow-list (proxy returned `403 to CONNECT`) | HCL is parsed by Checkov and by a custom reference linter, which is partial evidence that it parses — **it is not provider-schema validation.** An argument name or type error would not have been caught |
| **L3** | **The GitHub Actions workflow has never executed.** No remote repository. | Job wiring, CodeQL configuration and gating behaviour are reviewed, not observed. Every stage *is* reproduced locally by `scripts/run_security_checks.sh`, which passes 15/15 — but CodeQL has no local equivalent and has produced **no results at all** |
| **L4** | **No dependency lock file.** Lower bounds only. | Builds are not bit-reproducible. Deliberate trade-off: lower bounds let `pip-audit` surface advisories rather than masking them behind a stale pin. Fix: S-2 |
| **L5** | **DynamoDB behaviour is asserted against `moto`**, not real DynamoDB. | Conditional-write semantics, `ValidationException` shapes and GSI consistency are verified against an emulator. The expressions are standard and reviewed, but real-service behaviour is unconfirmed |
| **L6** | **Security Hub was never enabled.** | The ASFF transformation is unit-tested with synthetic events; end-to-end EventBridge delivery is unverified. The integration is off by default and the project is fully demonstrable without it |
| **L7** | **Author and reviewer are the same engineer.** | The weakest form of review. An independent reviewer would find issues this review did not. No external validation of the findings or their severities |
| **L8** | **No load, fuzz or penetration testing.** | T-13 (flooding) is reasoned about, not measured. Input validation is tested with targeted cases, not fuzzed |
| **L9** | **Membership provisioning is out of band and unimplemented.** | The authorization source of truth is populated by a process that does not exist yet, so its own security is unassessed — which is precisely why T-06/AR-04 is rated Medium |

---

## 13. Prioritised next steps

| # | Action | Addresses | Why this priority |
|---|---|---|---|
| **1** | **Split memberships into a separate DynamoDB table** and grant the execution role read-only access to it | AR-04, T-06, S-1 | The only remaining Medium residual risk with a clean architectural fix. IAM cannot constrain a sort-key prefix, so no policy change can substitute |
| **2** | **Deploy to a sandbox AWS account and run the AWS-gated tests** | L1, L2, L5 | Converts 11 skipped tests into real evidence and closes the largest assurance gap. Also the only way to run `terraform validate/plan` and confirm `Scan` is genuinely denied |
| **3** | **Push to GitHub and observe the pipeline run** | L3 | CodeQL has produced no results. Until the workflow executes, the gating is reviewed rather than verified |
| **4** | **Generate a dependency lock file** | L4, S-2 | Cheap, closes the reproducibility gap. Keep `pip-audit` on the resolved tree so advisories still surface |
| **5** | **Mandate MFA for the administrator role; shorten production access-token TTL** | AR-03 | Narrows the replay window on the highest-privilege accounts. Configurable today; needs a product decision |
| **6** | **Add WAF rate-based rules and per-tenant usage plans** | AR-05, T-13 | The only control that stops one tenant's flood becoming everyone's outage. Needs a deployment to tune |
| **7** | **Independent security review by another engineer** | L7 | The methodological limitation no amount of self-review can close |
| **8** | Add the cheap CI guards: `.scan(` lint rule, `enforce()` coverage assertion, request-model schema test | S-8, S-9, S-10 | Each converts a review-maintained invariant into an automated one |
| **9** | CloudWatch Logs data-protection policy; log archival to S3 with Object Lock | S-5, S-6, SR-L12 | Second independent layer on the only Low-residual control with no backstop |
| **10** | Load and fuzz testing | L8 | Turns T-13 from reasoning into measurement |

---

## Appendix — Document index

| Document | Contents |
|---|---|
| [`executive-summary.md`](executive-summary.md) | One page for engineering leadership |
| [`security-findings.md`](security-findings.md) | 15 full finding records with evidence |
| [`remediation-tracker.md`](remediation-tracker.md) | Status board, diff map, deferred safeguards |
| [`regression-evidence.md`](regression-evidence.md) | Verbatim before/after command output |
| [`code-review-checklist.md`](code-review-checklist.md) | 60-item checklist, methodology, observations |
| [`../threat-model/threat-model.md`](../threat-model/threat-model.md) | 16 STRIDE threats |
| [`../threat-model/risk-register.csv`](../threat-model/risk-register.csv) | 16-row risk register |
| [`../threat-model/security-requirements.md`](../threat-model/security-requirements.md) | 91 testable requirements |
| [`../runbooks/`](../runbooks/) | Incident response runbooks A and B + report template |
| [`../docs/REQUIREMENTS_TRACEABILITY.md`](../docs/REQUIREMENTS_TRACEABILITY.md) | Skill → implementation → evidence matrix |
