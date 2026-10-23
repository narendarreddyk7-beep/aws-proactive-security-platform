# Security Overview

The security model, the controls that implement it, and how the CI gates work.

| Document | For |
|---|---|
| **this file** | The control inventory and the CI gating contract |
| [`../threat-model/threat-model.md`](../threat-model/threat-model.md) | 16 STRIDE threats |
| [`../assessments/security-findings.md`](../assessments/security-findings.md) | 15 findings with evidence |
| [`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md) | Full report, residual risk, limitations |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Why each design decision was made |

---

## 1. The security model in one paragraph

A caller proves **who they are** to API Gateway, which validates the token's signature,
issuer, audience and expiry before any application code runs. The application reads that
caller's identity from the gateway-verified claims and **from nowhere else**. It then looks
up what that caller is **entitled to** in a server-side membership record, because a token
is a cached snapshot and entitlement is current server state. Every data operation is
scoped to the caller's own DynamoDB partition, derived from that verified identity — so
cross-tenant access is not prevented by a check, it is prevented by the shape of the query.
Within a tenant, an explicit allow/deny decision is made and enforced for every operation.
Nothing a client sends — header, query string, body, cursor — is ever treated as a statement
about identity, tenancy or privilege.

---

## 2. Control inventory

### 2.1 Authentication

| Control | Implementation | Verified by |
|---|---|---|
| Token validated before compute | API Gateway JWT authorizer (`api.tf`) | 🟡 AWS-gated |
| Issuer and audience pinned | Terraform resource references, so they cannot drift from the deployed pool | 🟡 Review |
| Identity only from verified claims | `security/identity.py` reads `requestContext.authorizer.jwt.claims` | ✅ `test_authentication.py` |
| Non-JWT authorizer context rejected | `authorizer.lambda` explicitly ignored | ✅ `test_authentication.py` |
| Local bypass cannot load in a deployed env | 3 independent guards (config, constructor, default) | ✅ `test_config.py` |
| Bypass activation is alarmed | `insecure_identity_adapter_enabled`, threshold 1 | ✅ event; 🟡 alarm |
| Password policy / MFA / adaptive auth | `cognito.tf`, stronger in prod | 🟡 Review |

### 2.2 Authorization and tenant isolation

| Control | Implementation | Verified by |
|---|---|---|
| Role from server-side record, not the token | `resolve_principal` + `membership_repository` (`ConsistentRead`) | ✅ `test_authorization_policy.py` |
| Membership must be active | revocation takes effect immediately, not at token expiry | ✅ `test_authentication.py` |
| Claim/record mismatch logged and alarmed | `role_claim_mismatch` | ✅ event; 🟡 alarm |
| App client cannot write tenancy/role claims | `cognito.tf` | 🟡 Review |
| Explicit decision on every operation | `Decision` + `enforce()` | ✅ `test_authorization.py` |
| Enforcement concentrated in one layer | `services/ticket_service.py` | ✅ `test_ticket_service.py` |
| Partition key from verified principal | `PK = TENANT#{org}` | ✅ `test_tenant_isolation.py` |
| No `Scan` in any read path | key-scoped `Query`/`GetItem` only | ✅ `test_data_access_scoping.py` |
| `Scan` denied at the IAM layer | explicit `Deny` in `lambda-execution.json` | ✅ policy analysis; 🟡 enforcement |
| Member listing narrowed by index key | GSI1 `TENANT#{org}#USER#{user}` | ✅ `test_data_access_scoping.py` |
| Cursor bound to the caller's partition | `decode_cursor` + repository re-validation | ✅ `test_tenant_isolation.py` |
| Cross-tenant indistinguishable from absent | structural 404 | ✅ `test_tenant_isolation.py` |
| Privileged transitions are admin-only | `PRIVILEGED_STATUSES`, `closed` terminal | ✅ `test_authorization_policy.py` |

### 2.3 Input validation and integrity

| Control | Implementation | Verified by |
|---|---|---|
| Unknown fields rejected | `extra="forbid"` on every model | ✅ `test_input_validation.py` |
| Server-controlled fields absent from request models | `TicketCreateRequest` has 3 fields | ✅ `test_tenant_isolation.py` |
| Writable fields allow-listed | `CLIENT_UPDATABLE_FIELDS` | ✅ `test_input_validation.py` |
| Identifiers typed as UUID at the edge | `ticket_id: UUID` | ✅ `test_input_validation.py` |
| Key separator rejected in identifiers | `keys._assert_no_separator` | ✅ `test_models_and_keys.py` |
| Page size bounded twice | `ge`/`le` at the edge + repository clamp | ✅ `test_input_validation.py` |
| Field lengths bounded | 200 / 10,000 chars | ✅ `test_input_validation.py` |
| Lifecycle state machine | `ALLOWED_STATUS_TRANSITIONS` | ✅ `test_authorization_policy.py` |
| Conditional writes | `attribute_not_exists` / `attribute_exists` | ✅ `test_dynamodb_repository.py` (moto) |

### 2.4 Data protection

| Control | Implementation | Verified by |
|---|---|---|
| Log field allow-list | `ALLOWED_LOG_FIELDS` | ✅ `test_logging_and_data_protection.py` |
| No ticket content in logs | no such field on the allow-list | ✅ same |
| No tokens in logs | debug branch removed; `debug=False` default | ✅ same |
| Changed field **names** only | `payload.changed_fields()` | ✅ same |
| Uniform error envelope | `main.py` handlers | ✅ `test_error_handling.py` |
| No traces or exception text to clients | type name only, into a log field | ✅ same |
| Validation errors omit submitted values | `_sanitize_validation_errors` | ✅ same |
| Internal attributes stripped from responses | `_from_item` | ✅ `test_dynamodb_repository.py` |
| Encryption at rest | DynamoDB SSE, CMK on logs and Lambda env vars | ✅ Checkov; 🟡 live |
| `Cache-Control: no-store` on every response | `security/http.py` | ✅ `test_api_behaviour.py` |

### 2.5 Cloud and infrastructure

| Control | Implementation | Verified by |
|---|---|---|
| Enumerated IAM actions | `GetItem`, `PutItem`, `Query` only | ✅ `iam_policy_checker.py` |
| ARN-scoped resources | table + GSI; own log group | ✅ same |
| Unused actions omitted | a new need fails closed and goes through review | ✅ policy review |
| Explicit `Deny` on destructive actions | `Scan`, `DeleteItem`, `DeleteTable`, … | ✅ policy review |
| Explicit `Deny` on self-modification | `iam:*`, `sts:AssumeRole`, `kms:ScheduleKeyDeletion`, `logs:Delete*` | ✅ policy review |
| Permissions boundary | `aws_iam_policy.lambda_boundary` | ✅ `iam.tf` |
| **Membership table is read-only to the role** | `GetItem` only + explicit `Deny` on every write; boundary capped the same way | ✅ `test_membership_table_isolation.py` (parses the deployed policy) |
| Confused-deputy guard on the trust policy | source-ARN condition | ✅ `iam_policy_checker.py` IAM008 |
| KMS use condition-constrained | `kms:ViaService` | ✅ policy review |
| Bounded timeout, memory, concurrency | `lambda.tf` | ✅ Checkov |
| Stage throttling | `api.tf` | ✅ Checkov |
| No public data access | only `/v1/health` is unauthenticated (AR-02) | ✅ Checkov + tests |
| Log retention set and encrypted | `monitoring.tf` | ✅ Checkov |
| No secrets or account ids in source | no secret variables exist by design | ✅ custom linter + Bandit |

### 2.6 Detection

8 alarms, 5 log metric filters, 4 saved Insights queries, 1 dashboard — all in
`monitoring.tf`.

| Alarm | Signal | Dev / Prod threshold |
|---|---|---|
| `authorization-denied-burst` | Someone being refused repeatedly | 3 / 25 per 5 min |
| `role-claim-mismatch` | Token role ≠ membership record | 5 per 5 min |
| `insecure-identity-adapter` | **The F-001 bypass activated** | 1 per 60 s |
| `unhandled-errors` | Application exceptions | 3 / 10 per 5 min |
| `lambda-errors` | Invocation failures | 3 / 10 |
| `lambda-throttles` | Concurrency ceiling reached | 10 |
| `gateway-unauthorized-burst` | 401 storm at the edge | per env |
| `dynamodb-throttles` | Capacity throttling | per env |

**All alarm thresholds are unverified.** Nothing has been deployed, so these are reasoned
estimates, never tuned against real traffic (limitation L1). Expect to retune in the first
week of production.

Triage procedure: [`../runbooks/authorization-alert-triage.md`](../runbooks/authorization-alert-triage.md).

---

## 3. The CI security gate

`.github/workflows/security-ci.yml`. Mirrored locally by `scripts/run_security_checks.sh`,
which passes **17/17 stages**.

| Stage | Tool | Gating rule |
|---|---|---|
| 1a | Ruff lint (incl. `S` bandit rules, `ANN`) | **any** violation fails |
| 1b | Ruff format | **any** diff fails |
| 1c | Import + compile check | failure fails |
| 2a | CodeQL (`security-extended`) | alerts surface in the Security tab |
| 2b | Bandit | **medium severity and above** fails |
| 2c | pip-audit (lock, `--strict`) | **any** known vulnerability fails |
| 2c | **Lock drift** — recompile and diff | a stale lock fails, with the regeneration command |
| 2c | pip-audit (dev) | **any** known vulnerability fails |
| 3a | `terraform fmt -check` | any diff fails |
| 3b | `terraform validate` | failure fails |
| 3c | Custom HCL reference linter (incl. **TF013** `templatefile()` var completeness) | any error fails |
| 3d | Checkov | **any** failed check fails |
| 3e | `iam_policy_checker.py` on deployed policies | **high severity and above** fails |
| 3f | **IAM gate self-test** | the insecure fixture **must** fail, or the job fails |
| 4 | pytest unit / integration / security / regression | any failure fails |
| 4e | Full suite + coverage | any failure fails |
| 5 | `finding_triage.py` | aggregates; reports, does not gate |
| — | **`security-gate`** | fails if **any** upstream job failed, was cancelled, **or was skipped** |

### Why `security-gate` exists

Set it as the only required status check in branch protection. It treats a **skipped**
security job as a failure, because "did not run" must never read as "passed" — which is the
most common way a security pipeline silently stops working.

### The gating contract

Four rules, all currently honoured:

1. **No `continue-on-error` on a security step.** The one `continue-on-error` in the
   workflow is on the Terraform *setup* step, and the next step immediately fails with an
   explicit error if setup did not succeed — so a runner that cannot fetch Terraform fails
   loudly instead of silently skipping `fmt`/`validate`.
2. **No baseline files, no blanket skips.** No Checkov baseline, no `--skip-check`, no
   `# nosec`. Repository `nosec` count: **0**.
3. **Every suppression is inline, single-check, single-resource, and justified.** All 12
   Checkov skips name an accepted-risk ID. `grep -rn 'checkov:skip' infrastructure/`
   enumerates them.
4. **A false positive stays visible.** The one Bandit `B105` finding is a confirmed false
   positive (a category-synonym dictionary mapping `"secret"` → `"secrets"`) and is left in
   the report rather than silenced. Recorded as observation O-6.

### Pipeline security

| Control | Implementation |
|---|---|
| Deny-by-default token | `permissions: {}` at workflow level; each job re-grants the minimum |
| No secrets to fork PRs | `pull_request`, **not** `pull_request_target` |
| No deployment from this workflow | there is no deploy job at all |
| Minimal action surface | scanners installed from PyPI; only GitHub's own actions plus `hashicorp/setup-terraform` |
| No long-lived AWS credentials | none are referenced; OIDC is the documented path if deployment is added |
| Scheduled re-scan | weekly, so a new advisory against unchanged code is still found |

**Action pinning is to tags, not commit SHAs.** The SHAs could not be resolved in the
environment this repository was authored in (no GitHub API access), and writing
unverifiable 40-character hashes would look *more* trustworthy while being *less* so. The
workflow header carries the exact `gh api` loop to convert them. Recorded as part of
limitation L3.

---

## 4. CI status — honest

**Run `39988484351` (2026-10-23) was fully green: all 12 jobs, `security-gate` included.**
Both project-written gates executed in CI for the first time on that run and passed — the
IAM policy analyzer against the deployed policy documents, and the self-test asserting it
still rejects a known-insecure fixture.

Getting there took five runs. The four that failed are worth listing, because every one was
a real defect that the local 17/17 pipeline reported as clean:

| Run | Failure | Nature |
|---|---|---|
| #1 | **Zero runs, no error** | Triggers named `main`; the default branch was `master` |
| #2–3 | Lock drift | The lock was pinned for Python 3.13 against a 3.12 Lambda runtime — wrong for the deployed artifact |
| #3 | `terraform fmt` | Four module files never formatted; `fmt` had only been run one directory deeper |
| #4 | IAM analyzer exit 2 | `--input` given a directory; it takes `--input-dir` |
| #4 | Dev-tree advisories | **Not a defect** — the SCA gate finding real vulnerabilities (AR-07) |

**Still outstanding:** branch protection is not configured, so `security-gate` reports
without blocking. Until it is the required status check, the gating is demonstrated but not
enforced.



**The workflow now executes, and CodeQL has produced results.** It was pushed to GitHub on
2026-10-23 and
immediately revealed a misconfiguration worth recording: the triggers named `main` while
the repository's default branch was `master`, so the push produced **zero runs and no
error**. A pipeline that silently never runs is a worse failure than one that fails — which
is the same principle the `security-gate` job encodes, applied one level up, to the
triggers themselves. Both branch names are now listed.

As of that fix:

- Job wiring and gating logic are **reviewed, not observed**.
- **CodeQL has now run and passed** (`security-extended`, ~1 minute). It was the one tool
  with no local equivalent, so that blind spot is closed.
- Every other stage *is* reproduced locally by `scripts/run_security_checks.sh` (15/15
  passing), which is why the gaps are limited to CodeQL and the Terraform steps.

Recorded as limitations **L2** and **L3**.

---

### 4.1 Gate self-test (PR #1, run 39990888962)

Branch protection on `master` requires the `Security gate` check, with
`enforce_admins: true` (the repository owner is not exempt) and
`strict: true` (the branch must be current before merging).

The control was verified by deliberately breaking it, not by reading its
configuration. A single unformatted line was committed to
`application/app/config.py` on a branch and opened as a pull request.

| Expected | Observed |
|---|---|
| The detector fires | `ruff format --check` exit 1 at `config.py:184` |
| The gate fails | `Error: stage 'code-quality' did not pass (result: failure)` |
| The gate evaluates stages individually | 6 stages logged `ok`, 1 logged the failure |
| Unrelated stages unaffected | CodeQL, Bandit, pip-audit, Checkov and all 5 test jobs green |
| The merge is prevented | `mergeable: MERGEABLE`, `mergeStateStatus: BLOCKED` |

The last row is the one that matters: git reported the merge was
mechanically clean, and policy refused it anyway. Nothing about the code
blocked the merge — the control did.

The branch was closed without merging; `master` stayed green throughout.
An enforcement control that has never been observed rejecting anything is
an untested control, so this result, rather than the protection settings,
is the evidence for L3.

### 4.2 A defect the local runner could not have found

Running `scripts/run_security_checks.sh` in a freshly built virtualenv on
macOS exposed a bug in the runner itself: under `set -u`, bash 3.2 (which
macOS ships) treats an **empty** array as unset when `${arr[@]}` is
expanded. `FAILED_STAGES` is empty on exactly one path -- the all-pass path
-- so the script aborted with `unbound variable` and exited 1 whenever every
stage passed. CI runs bash 5 on Ubuntu and never reproduced it.

The fix uses `${arr[@]+"${arr[@]}"}` and counts stages as it prints them.
The point worth keeping is the shape of the bug: the only untested path was
the success path, and a gate that rejects only clean trees fails in the
direction that looks like diligence.

**Residual.** Workflow actions are pinned by tag (`actions/checkout@v5`),
not by commit SHA. A tag is mutable by whoever owns the action, so a
re-pointed tag would execute in CI under this workflow's permissions.
Tracked as an open item.

## 5. Reporting a vulnerability

This is a portfolio project operating on synthetic data, with no production deployment and
no users. There is nothing live to compromise.

If you find a flaw in the code, the threat model, or the reasoning in these documents, open
an issue. Findings about the **reasoning** are the most valuable: the project's largest
acknowledged weakness is that the author and the reviewer are the same engineer
(limitation L7), so an independent pair of eyes is exactly what it is missing.

**Do not** use the security tooling here against infrastructure you do not own.
`iam_policy_checker.py` reads local JSON and Terraform plan output only; it makes no AWS API
calls. `finding_triage.py` reads local files. Neither tool scans, probes or touches a remote
system.
