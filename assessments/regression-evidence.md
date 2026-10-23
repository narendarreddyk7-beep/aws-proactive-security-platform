# Regression Evidence

Real command output demonstrating that each confirmed finding was **(a)** present and
demonstrable in the pre-review code, and **(b)** fixed afterwards.

Every figure on this page was produced by a command run in this environment on
**2026-10-23**. Nothing here is estimated or illustrative. The raw captured output is kept
at [`../reports/regression-v1-pre-review.txt`](../reports/regression-v1-pre-review.txt)
(346 KB, 84 failure blocks).

---

## 1. The experiment

The security test suite written during remediation is run **unchanged** against the
pre-review implementation. A test that guards a real finding must fail there; if it passes
against the vulnerable code, it was never testing the finding.

```bash
# 1. Check out the pre-review implementation into a separate worktree
git worktree add /tmp/v1check v1-pre-review

# 2. Overlay the CURRENT test suite and config onto the OLD application code
cp -r tests /tmp/v1check/tests_current
cp pyproject.toml /tmp/v1check/pyproject.toml.cur
cd /tmp/v1check && rm -rf tests && mv tests_current tests && cp pyproject.toml.cur pyproject.toml

# 3. Run it
python3 -m pytest tests/security -p no:cacheprovider -q
```

### Result — against `v1-pre-review`

```
84 failed, 92 passed, 78 warnings in 6.75s
```

### Result — against `v2-remediated` (current `HEAD`)

```
176 passed, 78 warnings in 6.54s
```

> **Note on the 92 that passed against v1.** The pre-review code was not uniformly
> insecure — it had a working JSON log formatter, partition-keyed single reads, and correct
> happy-path behaviour. Those tests passing against v1 is expected and is itself useful
> information: it bounds the blast radius of the review to the 84 behaviours that actually
> changed.

### Failures by test module

| Module | Failures vs. v1 | Findings guarded |
|---|---|---|
| `test_input_validation.py` | 38 | F-004, F-009, F-011 |
| `test_authorization_policy.py` | 8 | F-002, F-003, F-013 |
| `test_logging_and_data_protection.py` | 7 | F-007 |
| `test_data_access_scoping.py` | 7 | F-006 |
| `test_tenant_isolation.py` | 6 | F-001, F-004, F-010 |
| `test_error_handling.py` | 6 | F-008 |
| `test_authentication.py` | 6 | F-001, F-002, F-012 |
| `test_api_behaviour.py` | 6 | F-014 |
| **Total** | **84** | |

Reproduce the breakdown:

```bash
grep '^FAILED' reports/regression-v1-pre-review.txt \
  | sed 's#^FAILED tests/security/##; s#::.*##' | sort | uniq -c | sort -rn
```

---

## 2. Worked example — F-004 (cross-tenant write), verbatim

This is the most consequential finding, so the full captured output is reproduced. The
test authenticates as a **member of `org-acme`** and supplies
`"organization_id": "org-contoso"` in the request body.

### Against `v1-pre-review` — FAILED

```
__________ test_create_cannot_target_another_tenant_via_request_body ___________

    @pytest.mark.regression
    def test_create_cannot_target_another_tenant_via_request_body(
        empty_harness: ApiHarness,
    ) -> None:
        """Guards findings F-001 and F-004. ..."""
        response = empty_harness.as_member(ORG_A).client.post(
            "/v1/tickets",
            json={
                "title": "Cross-tenant write attempt",
                "description": "Synthetic test payload",
                "organization_id": ORG_B,
            },
        )
>       assert response.status_code == 422, response.text
E       AssertionError: {"ticket_id":"0c9c7499-6ba7-4bc6-9ed5-198f74e453c5",
E                        "organization_id":"org-contoso",
E                        "created_by":"22222222-2222-4222-8222-222222222222",
E                        "title":"Cross-tenant write attempt", ...}
E       assert 201 == 422
E        +  where 201 = <Response [201 Created]>.status_code

tests/security/test_tenant_isolation.py:156: AssertionError
```

**Read the response body.** The request was made by a member of `org-acme`, and the
created ticket's `organization_id` is **`org-contoso`** — the victim tenant. `201 Created`.
The cross-tenant write succeeded.

### The same run also proves F-007, incidentally

The captured stdout from that single failing test contains the log lines the pre-review
code emitted:

```
{"timestamp": "2026-10-23T07:14:28.111805+00:00", "severity": "info",
 "component": "app.routes.tickets", "request_id": "7be71aeb7b3e46648496181da2b55a8e",
 "message": "create ticket request",
 "payload": {"title": "Cross-tenant write attempt",
             "description": "Synthetic test payload",
             "priority": "medium", "organization_id": "org-contoso"}}

{"timestamp": "2026-10-23T07:14:28.112079+00:00", "severity": "info",
 "component": "app.services.ticket", "request_id": "7be71aeb7b3e46648496181da2b55a8e",
 "message": "ticket created", "event_type": "ticket_created",
 "ticket": {"ticket_id": "0c9c7499-...", "organization_id": "org-contoso",
            "created_by": "22222222-...",
            "title": "Cross-tenant write attempt",
            "description": "Synthetic test payload", ...}}
```

Both the **entire request payload** and the **entire ticket object** — customer title and
description — were written to the log stream. That is F-007, captured as a side effect of
testing F-004.

### Against `v2-remediated` — PASSED

```bash
$ python3 -m pytest tests/security/test_tenant_isolation.py -q
14 passed
```

The request now returns `422 invalid_request`, the response body carries no submitted
values, and the log record for the rejection contains `event_type`,
`request_validation_failed`, `changed_fields` — and no content.

---

## 3. Per-finding evidence index

Each finding, the guarding test, and its verified status on each side.

| Finding | Guarding test(s) | v1 | v2 |
|---|---|---|---|
| **F-001** Auth bypass via headers | `test_authentication.py::test_identity_from_headers_is_not_accepted`, `::test_request_without_authorizer_context_is_rejected`, `test_tenant_isolation.py::test_create_cannot_target_another_tenant_via_request_body` | ❌ fail | ✅ pass |
| **F-002** Self-asserted role | `test_authorization_policy.py` (token-claim elevation), `test_authentication.py` (missing/inactive membership) | ❌ fail | ✅ pass |
| **F-003** Unenforced update authz | `test_authorization_policy.py::test_member_cannot_update_another_members_ticket` | ❌ fail | ✅ pass |
| **F-004** Mass assignment | `test_tenant_isolation.py::test_create_cannot_target_another_tenant_via_request_body`, `::test_update_cannot_move_a_ticket_to_another_tenant`, `test_input_validation.py` (unknown fields) | ❌ fail | ✅ pass |
| **F-005** Over-privileged IAM role | `security-automation/iam_policy_checker.py` on `infrastructure/terraform/policies/` + CI gate self-test | n/a — see note | ✅ 0 blocking |
| **F-006** `Scan` + filter isolation | `test_data_access_scoping.py` (recording table: `scan` never called; key conditions pinned) | ❌ fail | ✅ pass |
| **F-007** Content/tokens in logs | `test_logging_and_data_protection.py::test_ticket_content_is_never_logged`, `::test_update_changes_are_logged_as_field_names_only`, `::test_log_payloads_only_contain_allow_listed_fields` | ❌ fail | ✅ pass |
| **F-008** Error disclosure | `test_error_handling.py` (no trace/exception text; uniform envelope), `test_tenant_isolation.py::test_cross_tenant_denial_does_not_disclose_existence` | ❌ fail | ✅ pass |
| **F-009** Unbounded pagination/fields | `test_input_validation.py::test_pagination_limit_is_bounded[5 cases]`, oversized title/description | ❌ fail | ✅ pass |
| **F-010** Unvalidated cursor | `test_tenant_isolation.py::test_pagination_cursor_from_another_tenant_is_rejected`, `::test_malformed_pagination_cursor_is_rejected[…]` | ❌ fail | ✅ pass |
| **F-011** Key injection | `test_input_validation.py::test_ticket_identifier_must_be_a_uuid[9 cases]` | ❌ fail | ✅ pass |
| **F-012** Insecure defaults | `test_config.py` (defaults + fail-closed guard), `test_authentication.py` (adapter guard) | ❌ fail | ✅ pass |
| **F-013** Lifecycle controls | `test_authorization_policy.py` (member cannot close; closed is terminal) | ❌ fail | ✅ pass |
| **F-014** Security headers | `test_api_behaviour.py` (headers on 200/403/404/422/500; `X-Request-Id`) | ❌ fail | ✅ pass |
| **F-015** Unconditional writes | `test_dynamodb_repository.py` (duplicate key → 409; missing item → 409) | ❌ fail | ✅ pass |

> **F-005 note.** This is the one finding **without** a before/after test diff. The
> infrastructure was authored after the application review and committed already
> remediated, so there is no pre-review IAM policy in git to run against. Its evidence is
> therefore (a) the design-decision record in the header of `iam.tf` naming the exact two
> over-broad statements, and (b) a demonstrable gate: the CI pipeline asserts that the
> synthetic insecure fixture **is** rejected by the analyzer, so the control is proven to
> work even though the original defect is not preserved. This weaker evidentiary standing
> is stated in the finding record rather than smoothed over.

---

## 4. Current verification run — full output summary

All commands below were run on 2026-10-23 at the repository root.
Full transcript: [`../reports/local-security-run.txt`](../reports/local-security-run.txt).

### 4.1 Test suite

```bash
$ python3 -m pytest -q
584 passed, 11 skipped, 148 warnings in 11.44s
```

By marker:

| Marker | Collected | Result |
|---|---|---|
| `unit` | 377 | pass |
| `integration` | 43 | pass |
| `security` | 258 | pass |
| `regression` | 122 | pass |
| `aws` | 11 | **skipped** — require a deployed environment |

(Markers overlap: the `security-automation` tool tests are marked `unit`, and most
`security` tests are also `regression`. The directory `tests/security/` alone is 176
tests.)

The 11 skips are explicit and name their missing prerequisite, e.g.:

```
SKIPPED [1] tests/integration/test_aws_gateway_contract.py:88:
  SUPPORT_API_EXPIRED_TOKEN is required to test gateway expiry enforcement.
SKIPPED [1] tests/integration/test_aws_gateway_contract.py:147:
  SUPPORT_API_TABLE_NAME is required to test IAM least privilege.
```

They are **present and skipped rather than absent**, so the suite reports the gap instead
of hiding it.

### 4.2 Coverage

```bash
$ python3 -m pytest -q --cov --cov-report=term-missing:skip-covered
TOTAL    2058 stmts   183 miss   668 branch   83 brpart   89% cover
```

### 4.3 Static analysis — Ruff

```bash
$ ruff check . --output-format=concise
All checks passed!
$ ruff format --check .
65 files already formatted
```

Ruff is configured with `S` (bandit-equivalent) and `ANN` (type annotation) rule sets —
see `pyproject.toml`.

### 4.4 Static analysis — Bandit

```bash
$ python3 -m bandit -c pyproject.toml -r application/ security-automation/ -ll --quiet
(no findings at medium severity or above)
```

Full scan metrics: **4,780 lines**, `nosec` suppressions: **0**.

One LOW-severity / MEDIUM-confidence finding is reported at full verbosity and is a
confirmed false positive:

```
security-automation/finding_triage.py:392  B105  LOW  MEDIUM
  Possible hardcoded password: 'secrets'
  CODE:  391  "credentials": "secrets",
         392  "secret": "secrets",
```

It is a category-synonym dictionary mapping the label `"secret"` to the canonical category
`"secrets"`. **It is deliberately not suppressed with `# nosec`** — the gate is set at
medium severity, so the finding stays visible in the report instead of being silenced.
Recorded as observation O-6.

### 4.5 Dependency audit — pip-audit

```bash
$ python3 -m pip_audit --requirement application/requirements.txt
packages audited: 21   with vulnerabilities: 0
```

### 4.6 Infrastructure scan — Checkov

```bash
$ python3 -m checkov.main -d infrastructure/ --framework terraform --compact --quiet
terraform   passed: 134   failed: 0   skipped: 12
```

All 12 skips are **inline, targeted and individually justified** — no blanket
`--skip-check` and no baseline file. For example:

```hcl
#checkov:skip=CKV_AWS_109:KMS key policy. Resource "*" is the only legal form in a key
#  policy and denotes the key itself; the account-root statement is mandatory for key
#  manageability. See AR-01.
#checkov:skip=CKV_AWS_309:Intentionally public liveness probe. Returns a static payload
#  with no configuration disclosure, asserted by tests/security/test_api_behaviour.py.
#  Recorded in assessments/final-security-assessment.md §Accepted risks (AR-02).
```

List them all:

```bash
grep -rn 'checkov:skip' infrastructure/
```

### 4.7 Custom IAM policy analyzer

```bash
$ python3 security-automation/iam_policy_checker.py \
    --input infrastructure/terraform/policies/ --output reports/iam-findings.json
total_findings: 1   blocking_findings: 0
by_severity:    critical 0  high 0  medium 0  low 0  info 1
by_confidence:  confirmed 0  needs_context 1
IAM003  info  needs_context  Unscoped resource on actions that do not support scoping
                             → policies/lambda-xray.json
```

**Gate self-test** — the pipeline also proves the gate *can* fail:

```
[STAGE] 3d. IAM analyzer gate self-test (insecure fixture must fail)
Confirmed: the insecure fixture is correctly rejected.
  PASS 3d. IAM analyzer gate self-test (insecure fixture must fail)
```

A gate that has never rejected anything is not a verified gate.

### 4.8 Terraform

```bash
$ python3 scripts/validate_terraform.py infrastructure/terraform
$ python3 scripts/validate_terraform.py infrastructure/modules/security_hub_triage
(both pass)

NOTE: this checks HCL syntax and reference resolution only. It does NOT
      validate provider schemas or argument names. `terraform validate`,
      `terraform fmt -check` and `terraform plan` are still required
      before deployment — see docs/AWS_DEPLOYMENT.md.
```

```bash
$ terraform fmt -check -recursive
# NOT RUN — the Terraform binary cannot be installed in this environment.
# releases.hashicorp.com is outside the egress allow-list:
#   {"kind":"connect_rejected","detail":"gateway answered 403 to CONNECT
#    (policy denial)","host":"releases.hashicorp.com:443"}
```

This is limitation **L2**. Checkov's HCL parser reading all 10 files successfully, plus the
custom reference linter, is partial evidence that the configuration parses — it is **not**
`terraform validate`, and is not represented as such.

### 4.9 Finding triage aggregation

```bash
$ python3 security-automation/finding_triage.py \
    --input reports/checkov.json --input reports/bandit.json \
    --input reports/pip-audit.json --input reports/iam-findings.json \
    --output reports/triage-report.json --markdown reports/triage-report.md

Inputs             : checkov.json, bandit.json, pip-audit.json, iam-findings.json
Total findings     : 2
Open               : 2   New: 2   Overdue: 0   Newly resolved: 0
Duplicates removed : 0
Aggregate open risk: 18.9   (highest single: 15.0)
By priority : P4=2
By severity : low=1  info=1
By owner    : application-security=1  cloud-security-engineering=1
```

### 4.10 Full pipeline

```bash
$ ./scripts/run_security_checks.sh
...
Passed: 15   Failed: 0
```

**Three genuine failures were found and fixed during this verification run** rather than
being written off:

| Stage | Failure | Fix |
|---|---|---|
| 1a. Ruff lint | 4 violations in `scripts/validate_terraform.py` (2× `E501`, 2× `ARG001`) | Lines wrapped; the two intentionally-unused parameters renamed `_parsed` with a docstring explaining the uniform-signature reason |
| 1b. Ruff format | 1 file unformatted | `ruff format` applied |
| 5a. Finding triage | `reports/checkov.json: Is a directory` — Checkov treats `--output-file-path` as a **directory**, so no JSON report was produced and the aggregation stage failed | Report captured from stdout instead; comment added explaining why |

---

## 5. How to reproduce everything

```bash
git clone <repository> && cd aws-proactive-security-platform
python3 -m pip install -e '.[dev]'

# The full gated pipeline, same order and gating as CI
./scripts/run_security_checks.sh

# The before/after regression experiment from §1
git worktree add /tmp/v1check v1-pre-review
cp -r tests /tmp/v1check/tests_current && cp pyproject.toml /tmp/v1check/pyproject.toml.cur
cd /tmp/v1check && rm -rf tests && mv tests_current tests && cp pyproject.toml.cur pyproject.toml
python3 -m pytest tests/security -q      # expect: 84 failed, 92 passed
cd - && git worktree remove --force /tmp/v1check
```
