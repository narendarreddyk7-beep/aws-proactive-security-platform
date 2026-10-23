# Manual Security Code Review — Checklist and Methodology

**Target:** `application/app/` (the FastAPI service) and
`infrastructure/terraform/` (the IAM policies).
**Reviewer:** Security Engineering (this project).
**Review date:** 2026-10-23.
**Method:** manual line-by-line review against the checklist below, performed against the
threats in [`../threat-model/threat-model.md`](../threat-model/threat-model.md).

---

## 1. Methodology — and an important disclosure

This project uses a deliberate **two-pass methodology**, and it is stated plainly here so
that nobody mistakes these findings for findings in third-party software.

### Pass 1 — first-draft implementation

The application was first written the way a competent engineer under delivery pressure
plausibly writes it: feature-complete against the functional requirements, idiomatic,
readable — and not security-reviewed. Decisions were made for convenience where
convenience was the obvious path (a header fallback "so it works locally", `extra="allow"`
"while the schema settles", `Scan` + filter because it is the shortest route to a
working list endpoint, a stack trace in the 500 body "so clients can report actionable
bugs").

That draft is preserved in git:

```bash
git show v1-pre-review                   # the pre-review commit
git tag -l                               # v1-pre-review, v2-remediated
git diff v1-pre-review v2-remediated -- application/
```

### Pass 2 — security review

The draft was then reviewed against the checklist in §3. For every confirmed weakness:

1. A **test was written that failed against pass 1**, demonstrating the weakness.
2. The weakness was **recorded** with file/line evidence in
   [`security-findings.md`](security-findings.md).
3. A **fix** was implemented.
4. The test was **re-run** and now passes; it is marked `@pytest.mark.regression`.

The before/after output of that process — real command output, not a summary — is in
[`regression-evidence.md`](regression-evidence.md).

### Why this is a legitimate exercise, and what it is not

**It is** a real review of real code, with real failing tests as evidence and a real
remediation diff. The weaknesses are the ones that actually show up in multi-tenant APIs,
and the fixes are the ones a reviewer would ask for.

**It is not** a claim to have found vulnerabilities in anyone else's software, and it is
not a penetration test. The author of pass 1 and the reviewer of pass 2 are the same
engineer, which is the weakest form of review: a genuine second pair of eyes would find
things this review did not. That limitation is recorded in
[`final-security-assessment.md`](final-security-assessment.md) §Limitations.

### Confirmed vs. theoretical

Findings are only recorded as **confirmed** when there is a concrete code path and a test
that demonstrates the behaviour. Concerns that depend on an unproven assumption are
recorded separately as **observations** (§5) and are *not* counted in the finding totals.
This distinction is the difference between a finding and a worry.

---

## 2. Scope

| In scope | Out of scope |
|---|---|
| `application/app/**` — all 24 Python modules | Third-party library internals (covered by `pip-audit`) |
| `infrastructure/terraform/policies/*.json` — IAM policy documents | AWS-managed service implementations |
| `infrastructure/terraform/*.tf` — security-relevant configuration | Client applications (none exist) |
| `security-automation/*.py` — the tools themselves | Load/performance testing |
| `tests/**` — reviewed for test quality, not as a finding source | Physical and personnel security |

Lines reviewed: **2,064 statements** in the application and automation trees (per
`coverage.xml`), plus 10 Terraform files and 3 IAM policy documents.

---

## 3. Review checklist

Each item records the verdict: ✅ no finding, ⚠️ finding raised (with ID), or ℹ️
observation only.

### 3.1 Authentication enforcement

| # | Check | Verdict |
|---|---|---|
| A1 | Is there exactly one place where identity is established? | ✅ `security/identity.py` + `dependencies.get_principal` |
| A2 | Can identity come from any client-controllable source (header, query, cookie, body)? | ⚠️ **F-001** — header fallback accepted `X-User-Id`/`X-Org-Id` in any environment |
| A3 | Is a development/test authentication bypass reachable in a deployed configuration? | ⚠️ **F-012** — `debug=True` default, no guard on the local adapter |
| A4 | Does every protected route actually depend on the authentication gate? | ✅ all `/v1/tickets*` routes `Depends(get_principal)`; `/v1/health` intentionally public |
| A5 | Are missing and invalid credentials distinguished in the response? | ✅ both 401, no reason disclosed |
| A6 | Is a non-JWT authorizer context accepted as a substitute? | ⚠️ folded into **F-001** — `authorizer` was read without requiring the `jwt` sub-key |
| A7 | Is token signature/expiry validation the application's responsibility? | ✅ no — delegated to the gateway by design; documented |

### 3.2 Authorization and tenant isolation

| # | Check | Verdict |
|---|---|---|
| Z1 | Is the caller's role derived from a token claim? | ⚠️ **F-002** — role taken from `custom:role`, with a silent fallback to `member` on an unrecognised value |
| Z2 | Is there a server-side source of truth for membership and role? | ⚠️ **F-002** — none consulted |
| Z3 | Does every data operation make and enforce an explicit authorization decision? | ⚠️ **F-003** — `can_update_ticket` defined but **never called** on the update path |
| Z4 | Can the tenant identifier used for data access come from client input? | ⚠️ **F-004** — `TicketCreateRequest.organization_id` was client-supplied |
| Z5 | Is tenant scoping a property of the access pattern or of a filter? | ⚠️ **F-006** — `Scan` + `FilterExpression` |
| Z6 | Do role differences change the *query* or only the *results*? | ⚠️ folded into **F-003**/**F-006** — listing was org-wide for members |
| Z7 | Is a cross-tenant resource request distinguishable from a non-existent one? | ⚠️ **F-008** — denial message named the owner and the organization |
| Z8 | Are privileged state changes restricted by role? | ⚠️ **F-013** — any member could close a ticket |
| Z9 | Is authorization policy unit-testable without HTTP? | ✅ pure functions |
| Z10 | Is there any self-service path to grant membership or role? | ✅ none by design |

### 3.3 Input validation

| # | Check | Verdict |
|---|---|---|
| V1 | Do request models reject unknown fields? | ⚠️ **F-004** — `extra="allow"` on `TicketUpdateRequest` |
| V2 | Are server-controlled fields absent from request models? | ⚠️ **F-004** |
| V3 | Are identifiers in the URL path validated for format? | ⚠️ **F-011** — `ticket_id` was `str` |
| V4 | Are identifiers validated before being used to build storage keys? | ⚠️ **F-011** — `#` separator injectable |
| V5 | Is pagination bounded? | ⚠️ **F-009** — `limit` had no `ge`/`le` and no repository clamp |
| V6 | Do string fields have maximum lengths? | ⚠️ folded into **F-009** — `description` had `min_length` only |
| V7 | Are enumerated fields typed as enums? | ⚠️ folded into **F-004** — `priority`/`status` were `str` on update |
| V8 | Is client-supplied pagination state validated? | ⚠️ **F-010** — cursor passed straight to `ExclusiveStartKey` |
| V9 | Is a no-op update rejected? | ⚠️ folded into **F-013** — empty PATCH accepted, bumping `updated_at` |

### 3.4 Secure error handling

| # | Check | Verdict |
|---|---|---|
| E1 | Can a response body contain a stack trace or exception text? | ⚠️ **F-008** — `str(exc)` and `traceback.format_exc()` returned in the 500 body |
| E2 | Is there one consistent error envelope? | ⚠️ folded into **F-008** — framework 404/405 returned `{"detail": …}` |
| E3 | Do validation errors echo submitted values? | ⚠️ folded into **F-008** — FastAPI's default 422 includes `input` |
| E4 | Are denial messages generic and uniform? | ⚠️ **F-008** |
| E5 | Is interactive documentation disabled outside local development? | ⚠️ folded into **F-012** |
| E6 | Do error paths still apply security headers? | ⚠️ folded into **F-014** — no headers anywhere |

### 3.5 Sensitive-data exposure

| # | Check | Verdict |
|---|---|---|
| D1 | Are request payloads logged? | ⚠️ **F-007** — `extra={"payload": payload.model_dump()}` on create |
| D2 | Are credentials or tokens logged? | ⚠️ **F-007** — `Authorization` header logged in a `debug` branch |
| D3 | Are update values logged? | ⚠️ **F-007** — `extra={"changes": changes}` |
| D4 | Can internal storage attributes reach an API response? | ✅ `_from_item` strips `PK`/`SK`/`GSI1*`/`entity_type` |
| D5 | Are responses cacheable by intermediaries? | ⚠️ folded into **F-014** — no `Cache-Control` |
| D6 | Is data encrypted at rest? | ✅ table SSE and CMK configured in Terraform |

### 3.6 Logging and auditability

| # | Check | Verdict |
|---|---|---|
| L1 | Are logs structured and queryable? | ✅ JSON formatter present in pass 1 |
| L2 | Is there a field allow-list or a deny-list? | ⚠️ **F-007** — arbitrary `extra` rendered |
| L3 | Is every authorization denial logged with actor and reason? | ⚠️ folded into **F-003** — denials raised without a security event |
| L4 | Can a client forge a log record? | ⚠️ folded into **F-007** — `X-Request-Id` accepted unsanitised |
| L5 | Is a correlation id returned to the caller? | ⚠️ folded into **F-014** — no `X-Request-Id` on responses |
| L6 | Are noisy third-party loggers constrained? | ⚠️ folded into **F-007** — `botocore` at default level |

### 3.7 Unsafe configuration defaults

| # | Check | Verdict |
|---|---|---|
| C1 | Does every security-relevant setting default to the safe value? | ⚠️ **F-012** — `debug=True`, `cors_allow_origins="*"` |
| C2 | Is a wildcard CORS origin combined with credentials? | ⚠️ folded into **F-012** |
| C3 | Does the development server bind to all interfaces? | ⚠️ folded into **F-012** — `host="0.0.0.0"` (Bandit B104 / CWE-605) |
| C4 | Does the application fail closed on invalid configuration? | ⚠️ folded into **F-012** — no validation at load |

### 3.8 Dependency management

| # | Check | Verdict |
|---|---|---|
| P1 | Are dependencies declared explicitly? | ✅ `application/requirements.txt` |
| P2 | Are known-vulnerable versions present? | ✅ `pip-audit` 2026-10-23: 21 packages, **0 vulnerabilities** |
| P3 | Is there a lock file for reproducible builds? | ℹ️ **Observation O-1** — lower bounds only; see §5 |
| P4 | Is the runtime dependency surface minimal? | ✅ 4 runtime packages (`fastapi`, `pydantic`, `mangum`, `boto3`) |

### 3.9 HTTP and API security controls

| # | Check | Verdict |
|---|---|---|
| H1 | Are security response headers applied? | ⚠️ **F-014** — none |
| H2 | Is a CSP set for JSON responses? | ⚠️ folded into **F-014** |
| H3 | Are only implemented HTTP methods routed? | ✅ |
| H4 | Do trailing-slash redirects change the effective route? | ⚠️ folded into **F-014** — `redirect_slashes` default `True` |
| H5 | Does the server advertise its framework/version? | ⚠️ folded into **F-014** |
| H6 | Is the health endpoint free of configuration disclosure? | ✅ static payload |

### 3.10 Insecure AWS integration patterns

| # | Check | Verdict |
|---|---|---|
| W1 | Does the execution role use wildcard actions? | ⚠️ **F-005** — `dynamodb:*` on the table, `logs:*` on `*` |
| W2 | Are resources ARN-scoped? | ⚠️ **F-005** — `logs:*` on `Resource: "*"` |
| W3 | Are unused permissions granted? | ⚠️ folded into **F-005** — `Scan`, `DeleteItem`, `DeleteTable` all reachable |
| W4 | Is there an explicit Deny on large-blast-radius actions? | ⚠️ folded into **F-005** |
| W5 | Is there a permissions boundary? | ⚠️ folded into **F-005** |
| W6 | Is the trust policy constrained against confused-deputy abuse? | ⚠️ folded into **F-005** |
| W7 | Are writes conditional, or can they silently replace data? | ⚠️ **F-015** — unconditional `put_item` on both paths |
| W8 | Is `boto3` client construction cached across invocations? | ✅ module-level factory |
| W9 | Are DynamoDB expressions built by string concatenation? | ✅ no — `boto3.dynamodb.conditions` builders throughout |

---

## 4. Finding summary

**15 confirmed findings.** Many checklist items are marked "folded into" a finding:
related weaknesses with one root cause are recorded as a single finding with multiple
vectors rather than inflated into separate entries.

| Severity | Count | IDs |
|---|---|---|
| Critical | 1 | F-001 |
| High | 4 | F-002, F-003, F-004, F-006 |
| Medium | 7 | F-005, F-007, F-008, F-009, F-010, F-011, F-012 |
| Low | 3 | F-013, F-014, F-015 |
| **Total** | **15** | |

Full records: [`security-findings.md`](security-findings.md).
Status: [`remediation-tracker.md`](remediation-tracker.md).

---

## 5. Observations (not counted as findings)

Recorded because they are real engineering concerns, but they do not meet the bar for a
confirmed finding — there is no demonstrable weakness in the current code.

| ID | Observation | Why not a finding | Disposition |
|---|---|---|---|
| O-1 | Dependencies use lower bounds (`>=`) with no lock file. | No vulnerable version was present (`pip-audit` clean), and lower bounds meant `pip-audit` surfaced advisories rather than being masked by a stale pin. The reproducibility gap was real but was not a vulnerability. | **RESOLVED 2026-10-23.** `application/requirements.lock` pins 21 packages with sha256 hashes; the build installs with `--require-hashes`; `pip-audit` audits the lock; a CI gate catches drift. The advisory-visibility concern is met by the weekly scheduled scan. |
| O-2 | Membership lookup costs one `GetItem` per request. | Deliberate: caching role data is how stale-privilege bugs are introduced. Cost, not security. | Accepted. Revisit with short-TTL caching plus explicit invalidation if it becomes a cost issue. |
| O-3 | Ticket updates are last-writer-wins at field granularity. | Conditional writes prevent record replacement and resurrection; concurrent field-level clobbering is a correctness concern, not a security boundary. | Tracked as a recommended safeguard under T-08. |
| O-4 | The execution role's `PutItem` grant was table-scoped, not sort-key-prefix-scoped. | IAM cannot express a sort-key-prefix condition (`dynamodb:LeadingKeys` constrains the partition key only), so "the application never writes a `USER#` key" was a compensating control rather than a boundary. | **RESOLVED 2026-10-23.** Escalated to risk R-06/T-06 and fixed by splitting memberships into a dedicated table: `GetItem` only, explicit `Deny` on every write, boundary capped the same way. Closed accepted risk AR-04. |
| O-5 | `/v1/health` is unauthenticated. | Intentional liveness probe returning a static payload with no configuration disclosure, asserted by `tests/security/test_api_behaviour.py`. | Accepted as AR-02. |
| O-6 | Bandit reports one LOW/MEDIUM `B105` on `finding_triage.py:392`. | False positive: a category-synonym dictionary maps the label `"secret"` to the string `"secrets"`. No credential exists. | Left visible rather than suppressed with `# nosec`. `nosec` count across the repo is **0**. |
| O-7 | The reviewer and the author of pass 1 are the same engineer. | Methodological limitation, not a code weakness. | Disclosed in §1 and in the final assessment's Limitations. |

---

## 6. Re-review triggers

This review is valid for the code at tag `v2-remediated`. It must be repeated when any of
these change:

1. `app/security/identity.py` — any change to where identity comes from.
2. `app/security/authorization.py` or `app/services/ticket_service.py` — any change to
   enforcement points.
3. `app/repositories/` — any new query, index, or write path.
4. `app/models/` — any new request field, or a change to `model_config`.
5. `app/observability/logging.py` — any addition to `ALLOWED_LOG_FIELDS`.
6. `infrastructure/terraform/policies/*.json` — any permission change.
7. A new route, or a route's dependency on `get_principal` being removed.
