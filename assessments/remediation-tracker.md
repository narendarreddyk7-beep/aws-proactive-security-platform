# Remediation Tracker

Status of every confirmed finding from [`security-findings.md`](security-findings.md).

**Last updated:** 2026-10-23 · **Verified by:** full local pipeline run, 15/15 stages passing.

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

**15 of 15 remediated and retested. 0 open. 0 silently deferred.**

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

Raised during remediation and deliberately **not** built. Tracked here rather than quietly
dropped, and prioritised in
[`final-security-assessment.md`](final-security-assessment.md) §Next steps.

| # | Safeguard | Related | Why deferred | Priority |
|---|---|---|---|---|
| S-1 | Split memberships into a **separate table** so the execution role can hold read-only rights to them | F-005, T-06, O-4 | Architectural change. IAM cannot constrain a sort-key prefix (`dynamodb:LeadingKeys` is partition-key only), so this is the only clean fix | **P1** |
| S-2 | Dependency lock file (`pip-compile` → `requirements.lock`) | O-1, SR-S11 | Lower bounds currently let `pip-audit` surface advisories rather than masking them; the reproducibility gap remains | **P2** |
| S-3 | AWS WAF rate-based rules + per-tenant usage plans | T-13, AR-05 | Needs a deployment to tune; adds cost | **P2** |
| S-4 | Mandatory MFA for the administrator role | T-02, AR-03 | Product-owner policy decision; configurable today | **P2** |
| S-5 | CloudWatch Logs data-protection policy (managed data identifiers) | F-007 | Second independent layer; the field allow-list is the primary control and is verified | P3 |
| S-6 | Log archival to S3 with Object Lock (tamper-evident) | T-07, SR-L12 | Needs a deployment and a retention decision | P3 |
| S-7 | Optimistic-concurrency version attribute on tickets | F-015, O-3 | Correctness improvement; conditional writes already prevent replacement and resurrection | P3 |
| S-8 | CI lint rule failing on the literal `.scan(` in `application/` | F-006 | Cheap; the recording-table test already asserts it behaviourally | P3 |
| S-9 | CI assertion that every principal-taking service method calls `enforce()` | F-003 | Currently guaranteed by review plus the role × operation matrix | P3 |
| S-10 | CI schema test forbidding server-controlled field names in request models | F-004 | Currently guaranteed by `extra="forbid"` plus regression tests | P3 |
| S-11 | Per-principal rate limiting on 404 responses | F-008 | Blunts enumeration; needs deployment-level tuning | P3 |
| S-12 | IAM Access Analyzer policy validation in CI | F-005 | Requires AWS credentials in CI via OIDC | P3 |
| S-13 | Lambda code signing (AWS Signer) | Checkov `CKV_AWS_272` | Requires a Signer profile and a CI signing step | P3 |

---

## 4. Verification ledger

What was actually run to close these findings, and when. Everything below is a real
command and its real result.

| Check | Command | Result | Date |
|---|---|---|---|
| Regression — vulnerable code | `pytest tests/security` @ `v1-pre-review` | **84 failed**, 92 passed | 2026-10-23 |
| Regression — fixed code | `pytest tests/security` @ `HEAD` | **176 passed** | 2026-10-23 |
| Full suite | `pytest -q` | **584 passed, 11 skipped** | 2026-10-23 |
| Coverage | `pytest --cov` | **89%** (2,058 statements) | 2026-10-23 |
| Lint | `ruff check .` | All checks passed | 2026-10-23 |
| Format | `ruff format --check .` | 65 files already formatted | 2026-10-23 |
| SAST | `bandit -c pyproject.toml -ll` | 0 at medium+; 0 `nosec` | 2026-10-23 |
| SCA | `pip-audit` | 21 packages, **0 vulnerabilities** | 2026-10-23 |
| IaC scan | `checkov -d infrastructure/` | 134 passed, **0 failed**, 12 justified skips | 2026-10-23 |
| IAM policy analysis | `iam_policy_checker.py` on `policies/` | 1 INFO, **0 blocking** | 2026-10-23 |
| IAM gate self-test | insecure fixture must be rejected | Confirmed rejected | 2026-10-23 |
| HCL reference lint | `scripts/validate_terraform.py` | Pass (root + module) | 2026-10-23 |
| Finding aggregation | `finding_triage.py` on 4 reports | 2 open (P4), 0 duplicates | 2026-10-23 |
| Full pipeline | `./scripts/run_security_checks.sh` | **15/15 stages pass** | 2026-10-23 |
| `terraform fmt` / `validate` / `plan` | — | **NOT RUN** — binary unavailable (L2) | — |
| Live AWS behaviour | — | **NOT RUN** — no deployment (L1) | — |
| GitHub Actions workflow | — | **NOT RUN** — no remote repository (L3) | — |
