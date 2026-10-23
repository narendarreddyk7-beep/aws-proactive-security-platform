# Remediation Tracker

Status of every confirmed finding from [`security-findings.md`](security-findings.md).

**Last updated:** 2026-10-23 · **Verified by:** full local pipeline run, 17/17 stages passing.

| Lifecycle state | Meaning |
|---|---|
| Identified | Found during review, recorded with file/line evidence |
| Validated | A test was written that **fails** against the vulnerable code |
| Remediated | A fix is implemented in the codebase |
| Retested | The same test now **passes**, and is marked `@pytest.mark.regression` |
| Accepted | Residual risk consciously accepted, with a documented rationale and owner |

---

## 1. Status board

| ID | Title | Severity | Identified | Validated | Remediated | Retested | Residual | Commit |
|---|---|---|---|---|---|---|---|---|
| F-001 | Authentication bypass via identity headers | Critical | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-002 | Privilege escalation via self-asserted role | High | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-003 | Authorization check never enforced on update | High | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-004 | Mass assignment permits cross-tenant writes | High | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-005 | Over-privileged Lambda execution role | Medium | ✅ | ⚠️ partial | ✅ | ✅ | Low | `8cb87f5` |
| F-006 | Isolation dependent on a filter over a scan | High | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-007 | Customer content and tokens in logs | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-008 | Information disclosure in error responses | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-009 | Unbounded pagination and field sizes | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-010 | Pagination cursor forwarded unvalidated | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-011 | Unvalidated identifiers permit key injection | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-012 | Insecure-by-default configuration | Medium | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-013 | Missing ticket lifecycle controls | Low | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-014 | Missing HTTP security response headers | Low | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |
| F-015 | Unconditional writes replace records silently | Low | ✅ | ✅ | ✅ | ✅ | Low | `c9ec2b4` |

**17 of 17 remediated and retested. 0 open. 0 silently deferred.**

> ⚠️ **F-005 is `Validated: partial`.** The pre-remediation IAM policy is not preserved in
> git, so there is no before/after test diff. What *is* demonstrated is that the analyzer
> rejects the over-broad pattern (the CI gate self-test against the synthetic insecure
> fixture). This is a weaker evidentiary standard and is flagged as such rather than
> recorded as a clean validation. Detail:
> [`security-findings.md#f-005`](security-findings.md#f-005).

---

## 2. Remediation diff

```bash
$ git diff --stat v1-pre-review v2-remediated -- application/
 14 files changed, 1744 insertions(+), 312 deletions(-)
```

| File | Findings addressed |
|---|---|
| `app/security/identity.py` | F-001, F-002 |
| `app/security/authorization.py` | F-003, F-008, F-013 |
| `app/security/http.py` *(new)* | F-014, F-007 |
| `app/services/ticket_service.py` | F-003, F-007, F-008, F-013 |
| `app/models/ticket.py` | F-004, F-009, F-013 |
| `app/repositories/ticket_repository.py` | F-006, F-009, F-010, F-015 |
| `app/repositories/pagination.py` | F-010 |
| `app/repositories/keys.py` | F-011 |
| `app/routes/tickets.py` | F-007, F-009, F-011 |
| `app/observability/logging.py` | F-007 |
| `app/observability/request_context.py` | F-007 |
| `app/config.py` | F-001, F-012 |
| `app/main.py` | F-008, F-012, F-014 |
| `app/dependencies.py` | F-001, F-002 |
| `infrastructure/terraform/iam.tf` + `policies/*.json` | F-005 |

Relevant references:

| Ref | SHA | Meaning |
|---|---|---|
| `v1-pre-review` | `31f4335` | First-draft implementation — the subject of the review |
| `v2-remediated` | `c9ec2b4` | Application remediation of F-001–F-004 and F-006–F-015 |
| — | `1d333c2` | Unit and integration suites |
| — | `8cb87f5` | Terraform infrastructure (F-005) and the two automation tools |

---

## 3. Recommended safeguards not yet implemented

Raised during remediation. Tracked here rather than quietly dropped, and prioritised in
[`final-security-assessment.md`](final-security-assessment.md) §Next steps.

**Five were implemented on 2026-10-23** and are struck through below with their evidence.
The rest remain deliberately unbuilt, each with a stated reason.

| # | Safeguard | Related | Why deferred | Priority |
|---|---|---|---|---|
| ~~S-1~~ | ~~Split memberships into a **separate table** so the execution role can hold read-only rights to them~~ | F-005, T-06, O-4 | ✅ **DONE 2026-10-23.** Dedicated `aws_dynamodb_table.memberships`; role holds `GetItem` only, with an explicit `Deny` on every write and the boundary capped the same way. `tests/security/test_membership_table_isolation.py` (10 tests); 3 of 4 policy assertions fail against the pre-split policy. Closes AR-04 / T-06 / R-06 | ✅ |
| ~~S-2~~ | ~~Dependency lock file (`pip-compile` → `requirements.lock`)~~ | O-1, SR-S11 | ✅ **DONE 2026-10-23.** `application/requirements.lock`, 21 packages with sha256 hashes; Lambda build installs with `--require-hashes`; `pip-audit` audits the lock; CI gate recompiles and diffs, verified to fail on a stale lock. Closes L4 / SR-S11 | ✅ |
| S-3 | AWS WAF rate-based rules + per-tenant usage plans | T-13, AR-05 | Needs a deployment to tune; adds cost | **P2** |
| S-4 | Mandatory MFA for the administrator role | T-02, AR-03 | Product-owner policy decision; configurable today | **P2** |
| S-5 | CloudWatch Logs data-protection policy (managed data identifiers) | F-007 | Second independent layer; the field allow-list is the primary control and is verified | P3 |
| S-6 | Log archival to S3 with Object Lock (tamper-evident) | T-07, SR-L12 | Needs a deployment and a retention decision | P3 |
| S-7 | Optimistic-concurrency version attribute on tickets | F-015, O-3 | Correctness improvement; conditional writes already prevent replacement and resurrection | P3 |
| ~~S-8~~ | ~~CI lint rule failing on the literal `.scan(` in `application/`~~ | F-006 | ✅ **DONE 2026-10-23.** AST-based, in `test_code_invariants.py`, covering the dynamic back doors too. Fails against `v1-pre-review` at `ticket_repository.py:73` | ✅ |
| ~~S-9~~ | ~~CI assertion that every principal-taking service method calls `enforce()`~~ | F-003 | ✅ **DONE 2026-10-23.** AST check over every principal-taking service method, with a justification-required exemption map. Fails against `v1-pre-review` on `get_ticket` and `update_ticket` | ✅ |
| ~~S-10~~ | ~~CI schema test forbidding server-controlled field names in request models~~ | F-004 | ✅ **DONE 2026-10-23.** AST check that no request model declares a server-controlled field and that all forbid extras. Fails against `v1-pre-review` on `TicketCreateRequest.organization_id` and both models' missing `extra="forbid"` | ✅ |
| S-11 | Per-principal rate limiting on 404 responses | F-008 | Blunts enumeration; needs deployment-level tuning | P3 |
| S-12 | IAM Access Analyzer policy validation in CI | F-005 | Requires AWS credentials in CI via OIDC | P3 |
| S-13 | Lambda code signing (AWS Signer) | Checkov `CKV_AWS_272` | Requires a Signer profile and a CI signing step | P3 |

---

## 4. Verification ledger

What was actually run to close these findings, and when. Everything below is a real
command and its real result.

| Check | Command | Result | Date |
|---|---|---|---|
| Regression — vulnerable code | `pytest tests/security` @ `v1-pre-review` | **93 failed**, 102 passed | 2026-10-23 |
| New invariant guards vs. vulnerable code | `pytest test_code_invariants.py` @ `v1-pre-review` | **4 of 9 failed** | 2026-10-23 |
| Membership policy assertions vs. pre-split policy | policy assertions replayed | **3 of 4 failed** | 2026-10-23 |
| Lock drift gate vs. a stale lock | package added without recompiling | **correctly failed** (exit 1) | 2026-10-23 |
| Regression — fixed code | `pytest tests/security` @ `HEAD` | **195 passed** | 2026-10-23 |
| Full suite | `pytest -q` | **603 passed, 13 skipped** | 2026-10-23 |
| Coverage | `pytest --cov` | **89%** (2,064 statements) | 2026-10-23 |
| Lint | `ruff check .` | All checks passed | 2026-10-23 |
| Format | `ruff format --check .` | 64 files already formatted | 2026-10-23 |
| SAST | `bandit -c pyproject.toml -ll` | 0 at medium+; 0 `nosec` | 2026-10-23 |
| SCA | `pip-audit` | 21 packages, **0 vulnerabilities** | 2026-10-23 |
| IaC scan | `checkov -d infrastructure/` | 137 passed, **0 failed**, 12 justified skips | 2026-10-23 |
| IAM policy analysis | `iam_policy_checker.py` on `policies/` | 1 INFO, **0 blocking** | 2026-10-23 |
| IAM gate self-test | insecure fixture must be rejected | Confirmed rejected | 2026-10-23 |
| HCL reference lint | `scripts/validate_terraform.py` | Pass (root + module) | 2026-10-23 |
| Finding aggregation | `finding_triage.py` on 4 reports | 2 open (P4), 0 duplicates | 2026-10-23 |
| Full pipeline | `./scripts/run_security_checks.sh` | **17/17 stages pass** | 2026-10-23 |
| `terraform fmt -check -recursive` | separate machine, TF 1.17.0 | 5 files reformatted; now clean | 2026-10-23 |
| `terraform validate` | separate machine, TF 1.17.0 + AWS provider 6.70.0 | **FAILED, then fixed** → `Success! The configuration is valid` (2 deprecation warnings) | 2026-10-23 |
| `terraform plan` / `apply` | — | **NOT RUN** — no AWS account (L1) | — |
| Live AWS behaviour | — | **NOT RUN** — no deployment (L1) | — |
| GitHub Actions workflow | — | **NOT RUN** — no remote repository (L3) | — |
