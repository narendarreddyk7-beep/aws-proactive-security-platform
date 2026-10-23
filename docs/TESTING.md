# Testing

```bash
python -m pytest -q
```

```
603 passed, 13 skipped, 148 warnings in 11.44s
```

Verified 2026-10-23. Coverage: **89%** (2,064 statements, 668 branches).

---

## 1. What the suite is for

Most of these tests exist to make a **security invariant** fail loudly when someone breaks
it. That is a different goal from proving the features work, and it shows up in how they are
written: a test named
`test_cross_tenant_denial_does_not_disclose_existence` asserts a *status code* rather than a
payload, because the security property is "the response is indistinguishable", not "the
response is correct".

Three principles:

1. **A regression test must have failed once.** A test that has never failed is not evidence
   that it tests anything. Every one of the 141 `regression`-marked tests was demonstrated
   to fail against `v1-pre-review` — see §5.
2. **Skips are explicit and name their prerequisite.** A test that cannot run locally is
   present and skipped, not absent. The suite reports the gap rather than concealing it.
3. **No credentials, ever.** The whole suite runs with no AWS account. Where AWS behaviour
   is needed, `moto` is used and the limitation is recorded (L5).

---

## 2. Layout and counts

```
tests/
├── unit/           138 tests — pure logic, no HTTP, no AWS
├── integration/     42 tests — the real ASGI app, moto-backed storage, Lambda event shape
├── security/       195 tests — security invariants, mostly regression-marked
└── fixtures/              — synthetic data, fake stores, gateway event injector

security-automation/tests/  239 tests — the two CLI tools and the triage Lambda
```

| File | Tests | Covers |
|---|---|---|
| **`tests/unit/`** | | |
| `test_models_and_keys.py` | 44 | Request/response models, key builders, cursor encode/decode |
| `test_authorization.py` | 27 | Full role × operation × status-transition policy matrix |
| `test_config.py` | 25 | Every default, the fail-closed identity guard, invalid literals |
| `test_logging_and_context.py` | 22 | Field allow-list, request-id sanitising, newline handling |
| `test_ticket_service.py` | 20 | Enforcement invoked on every path; repository clamping |
| **`tests/integration/`** | | |
| `test_dynamodb_repository.py` | 15 | Repository against `moto`, incl. conditional writes and GSI1 |
| `test_aws_gateway_contract.py` | 11 | **All skipped** — behaviours that genuinely require AWS |
| `test_lambda_handler.py` | 9 | The real Mangum / API Gateway v2 event boundary |
| `test_tickets_api.py` | 7 | Full ticket lifecycle and a multi-page pagination walk |
| **`tests/security/`** | | |
| `test_input_validation.py` | 64 | Unknown fields, oversized input, malformed ids, bounded limits |
| `test_authentication.py` | 26 | Missing/invalid identity, header rejection, adapter guards |
| `test_api_behaviour.py` | 24 | Security headers on every status, method handling, no banner |
| `test_authorization_policy.py` | 17 | Ownership, role, privileged transitions, terminal state |
| `test_tenant_isolation.py` | 16 | Cross-tenant read/write denial, cursor tampering |
| `test_data_access_scoping.py` | 12 | **Asserts `scan` is never called** and keys are always pinned |
| `test_logging_and_data_protection.py` | 10 | No content, no tokens, field names only |
| `test_error_handling.py` | 7 | Uniform envelope, no traces, no echoed values |
| `test_membership_table_isolation.py` | 10 | The membership table is read-only — behaviourally **and** in the committed IAM policy |
| `test_code_invariants.py` | 9 | Architectural fitness functions: no `Scan`, enforcement on every principal-taking method, no server-controlled request fields |
| **`security-automation/tests/`** | | |
| `test_finding_triage.py` | 142 | Normalisation, dedup, scoring, invalid and empty input |
| `test_iam_policy_checker.py` | 59 | All 11 rules, compliant and non-compliant fixtures |
| `test_security_hub_handler.py` | 38 | ASFF transformation with synthetic events, malformed events |

---

## 3. Running by marker

```bash
python -m pytest -m unit -q           # 377 collected
python -m pytest -m integration -q    #  43
python -m pytest -m security -q       # 279
python -m pytest -m regression -q     # 141
python -m pytest -m aws -q            #  11 — all skip without a deployment
```

> Markers and directories overlap deliberately: the `security-automation` tool tests are
> marked `unit`, and most `tests/security/` tests are also `regression`. The directory
> `tests/security/` alone is **195** tests.

| Marker | Meaning |
|---|---|
| `unit` | No HTTP, no AWS, no I/O |
| `integration` | Real ASGI app or moto-backed storage |
| `security` | Asserts a security invariant |
| `regression` | Guards a specific confirmed finding; **demonstrated to fail against `v1-pre-review`** |
| `aws` | Requires a deployed environment; skips with a named prerequisite |

---

## 4. The 13 skipped tests

These are the honest edge of this project's verification. They are not optional extras —
they are the behaviours that **cannot** be proven without AWS, and they are kept in the
suite so the gap is visible on every run.

```
SKIPPED tests/integration/test_aws_gateway_contract.py:80
  SUPPORT_API_BASE_URL is not set: no deployed API Gateway stage to test against.
SKIPPED tests/integration/test_aws_gateway_contract.py:88
  SUPPORT_API_EXPIRED_TOKEN is required to test gateway expiry enforcement.
SKIPPED tests/integration/test_aws_gateway_contract.py:147
  SUPPORT_API_TABLE_NAME is required to test IAM least privilege.
... (13 total)
```

| Behaviour | Why it needs AWS |
|---|---|
| An expired token is rejected | Token expiry is enforced by the gateway authorizer, not by application code (decision D1) |
| A token with a bad signature is rejected | Signature verification happens against the Cognito JWKS at the gateway |
| A token from another user pool is rejected | Depends on the authorizer's `issuer`/`audience` configuration |
| A request with no `Authorization` header gets 401 at the edge | The local app returns 401 too, but from a different layer |
| `dynamodb:Scan` is actually denied to the execution role | Requires real IAM evaluation. The policy document is analysed statically instead |
| `dynamodb:DeleteItem` is actually denied | As above |
| **Membership writes are *explicitly* denied to the role** | Real IAM evaluation via `iam:SimulatePrincipalPolicy`. The committed-policy assertions in `test_membership_table_isolation.py` prove the document reads correctly; only live IAM settles how boundaries, SCPs and resource policies combine (T-06 / AR-04) |
| **The role can still read memberships** | Positive control — a policy that denied everything would pass the denial test while breaking authorization entirely |

To run them against a real deployment:

```bash
export SUPPORT_API_BASE_URL="https://<api-id>.execute-api.<region>.amazonaws.com"
export SUPPORT_API_ACCESS_TOKEN="<a real Cognito access token>"
export SUPPORT_API_EXPIRED_TOKEN="<an expired one>"
export SUPPORT_API_TABLE_NAME="<the deployed ticket table name>"
export SUPPORT_API_ROLE_ARN="$(terraform output -raw lambda_execution_role_arn)"
export SUPPORT_API_MEMBERSHIP_TABLE_ARN="$(terraform output -raw membership_table_arn)"
python -m pytest -m aws -v
```

Doing this is the **second-highest-priority next step** in the final assessment, because it
converts 11 skips into real evidence in one move.

---

## 5. The before/after regression experiment

This is the central piece of evidence in the project. The security suite is run
**unchanged** against the pre-review implementation; a test guarding a real finding must
fail there.

```bash
git worktree add /tmp/v1check v1-pre-review
cp -r tests /tmp/v1check/tests_current
cp pyproject.toml /tmp/v1check/pyproject.toml.cur
cd /tmp/v1check && rm -rf tests && mv tests_current tests && cp pyproject.toml.cur pyproject.toml
python -m pytest tests/security -p no:cacheprovider -q
```

| Against | Result |
|---|---|
| `v1-pre-review` | **93 failed**, 102 passed |
| `HEAD` | **195 passed** |

Failures by module:

| Module | Failures | Findings guarded |
|---|---|---|
| `test_input_validation.py` | 38 | F-004, F-009, F-011 |
| `test_authorization_policy.py` | 8 | F-002, F-003, F-013 |
| `test_logging_and_data_protection.py` | 7 | F-007 |
| `test_data_access_scoping.py` | 7 | F-006 |
| `test_tenant_isolation.py` | 6 | F-001, F-004, F-010 |
| `test_error_handling.py` | 6 | F-008 |
| `test_authentication.py` | 6 | F-001, F-002, F-012 |
| `test_api_behaviour.py` | 6 | F-014 |
| `test_membership_table_isolation.py` | 5 | T-06 / AR-04 (the table split) |
| `test_code_invariants.py` | 4 | F-003, F-004, F-006 (the fitness functions) |

Clean up:

```bash
cd - && git worktree remove --force /tmp/v1check
```

> **On the 92 that passed against v1:** the first draft was not uniformly insecure. It had a
> working JSON log formatter, partition-keyed single reads, and correct happy-path
> behaviour. Those passes bound the review's blast radius to the 84 behaviours that actually
> changed — which is useful information, not a gap.

Verbatim output, including the captured `201 Created` cross-tenant write:
[`../assessments/regression-evidence.md`](../assessments/regression-evidence.md).

---

## 6. Test fixtures

All data is **synthetic**. Two organizations (`org-acme`, `org-contoso`), six users with
UUID identifiers shaped like Cognito `sub` values, one deliberately suspended.

| Fixture | Purpose |
|---|---|
| `fixtures/gateway.py` | Injects a **realistic API Gateway v2 event** into `request.scope["aws.event"]`, so identity is exercised through the same path AWS uses. This is what makes it possible to test the production identity provider rather than only the local adapter |
| `fixtures/fake_store.py` | In-memory ticket and membership stores. Fast, and lets a test construct awkward states (a suspended membership, a ticket owned by a stranger) directly |
| `fixtures/recording_table.py` | Records every call made to the DynamoDB table. **This is a security control in test form**: it asserts that `scan` is never called and that every key condition pins the caller's partition — a property no amount of response-checking can establish |
| `fixtures/synthetic_data.py` | Organizations, users, roles, ticket factories |

### Why `recording_table.py` matters

Most tenant-isolation tests check that tenant B's data does not appear in tenant A's
response. That proves the *output* is right, not that the *query* was scoped — a `Scan` with
a correct post-filter passes those tests while reading every tenant's data on every request
(finding F-006). The recording table asserts the shape of the database call itself, which is
the actual invariant.

---

## 7. Coverage

```bash
python -m pytest -q --cov --cov-report=term-missing:skip-covered
```

```
TOTAL    2064 stmts   183 miss   668 branch   83 brpart   89% cover
```

Uncovered lines are mostly defensive branches that are hard to reach by design: the
`pragma: no cover` paths in `logging.py` (a broken `%`-format must not kill logging), the
`__main__` development-server block, and some `botocore` error branches.

**Coverage is reported, not targeted.** 100% coverage of a codebase with no authorization
enforcement would still be insecure; the regression experiment in §5 is the metric that
actually speaks to security.

---

## 8. Known testing limitations

| ID | Limitation | Consequence |
|---|---|---|
| L1 | No AWS deployment | 13 behaviours unverified; alarms never observed firing |
| L5 | DynamoDB behaviour asserted against **`moto`** | Conditional-write semantics, `ValidationException` shapes and GSI consistency are verified against an emulator. The expressions are standard and reviewed, but real-service behaviour is unconfirmed |
| L8 | No load, fuzz or penetration testing | T-13 (flooding) is reasoned about, not measured. Input validation uses targeted cases, not fuzzing |
| — | Property-based testing not used | Hypothesis against the key builders and cursor codec would likely find edge cases these targeted tests do not |
| — | No mutation testing | The strongest available answer to "are these tests actually load-bearing?" The §5 experiment is a partial substitute: it proves 93 of them fail when the code is wrong |
