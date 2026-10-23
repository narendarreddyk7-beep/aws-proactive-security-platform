# Demo Walkthrough

An end-to-end demonstration that runs on a laptop with **no AWS account, no credentials and
no Docker**, in about 10 minutes.

**Every output on this page was captured from a real run on 2026-10-23.** Request ids and
ticket ids will differ on your machine; everything else should match exactly.

---

## 0. Setup

```bash
python -m pip install -e '.[dev]'
python scripts/local_server.py          # leave this running in one terminal
```

The server prints the synthetic identities. Use a second terminal for the `curl` commands.

Shell helpers, so the examples stay readable:

```bash
B=http://127.0.0.1:8000

# Alice — ADMIN of org-acme
a1() { curl -s "$@" -H "X-Local-User-Id: 11111111-1111-4111-8111-111111111111" \
                    -H "X-Local-Org-Id: org-acme" -H "X-Local-Role: admin"; }
# Bob — MEMBER of org-acme
m1() { curl -s "$@" -H "X-Local-User-Id: 22222222-2222-4222-8222-222222222222" \
                    -H "X-Local-Org-Id: org-acme" -H "X-Local-Role: member"; }
# Carol — a different MEMBER of org-acme
m2() { curl -s "$@" -H "X-Local-User-Id: 33333333-3333-4333-8333-333333333333" \
                    -H "X-Local-Org-Id: org-acme" -H "X-Local-Role: member"; }
# Dave — ADMIN of org-contoso (a DIFFERENT tenant)
b1() { curl -s "$@" -H "X-Local-User-Id: 44444444-4444-4444-8444-444444444444" \
                    -H "X-Local-Org-Id: org-contoso" -H "X-Local-Role: admin"; }
```

> Identity comes from headers **only** because `APP_ENVIRONMENT=local`. In AWS it comes
> solely from the API Gateway JWT authorizer context. See [`SETUP.md`](SETUP.md) §3.

---

## 1. Running the application

### 1.1 Health check — the one public endpoint

```bash
curl -s -i $B/v1/health
```

```http
HTTP/1.1 200 OK
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: no-referrer
cache-control: no-store
pragma: no-cache
x-permitted-cross-domain-policies: none
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
x-request-id: f5b08e3fa4fb4fa9875d856e37220e9f
```

**What to notice.** Eight security headers and a correlation id on an endpoint that needs
none of them — they are applied to *every* response, including errors (finding F-014).
`Cache-Control: no-store` is the one that matters most for a multi-tenant API: without it
an intermediate cache can retain one tenant's data and serve it to the next similar
request.

### 1.2 No identity → 401

```bash
curl -s -w '\nstatus=%{http_code}\n' $B/v1/tickets
```

```json
{"error":"not_authenticated","message":"Authentication is required.","request_id":"96048b3395c34a83b43743312867d150"}
status=401
```

No hint about *why*. In AWS this request never reaches the function at all — the gateway
rejects it (finding F-001).

---

## 2. Legitimate API requests

### 2.1 Bob creates a ticket

```bash
m1 -X POST $B/v1/tickets -H 'Content-Type: application/json' \
  -d '{"title":"Cannot access account","description":"Synthetic support request","priority":"high"}'
```

```json
{"ticket_id":"2c0e45fe-451c-485b-a4bd-2be908d8d1a3","organization_id":"org-acme",
 "created_by":"22222222-2222-4222-8222-222222222222","title":"Cannot access account",
 "description":"Synthetic support request","priority":"high","status":"open",
 "created_at":"2026-10-23T07:46:18.884247Z","updated_at":"2026-10-23T07:46:18.884247Z"}
```

```bash
TID=2c0e45fe-451c-485b-a4bd-2be908d8d1a3     # use the id from your own run
```

**What to notice.** `ticket_id`, `organization_id`, `created_by` and `status` were all set
by the **server**. None of them appear in `TicketCreateRequest` — there is no field for a
client to populate (finding F-004).

### 2.2 Bob reads his own ticket

```bash
m1 -o /dev/null -w 'status=%{http_code}\n' $B/v1/tickets/$TID
```

```
status=200
```

---

## 3. Verifying tenant isolation and authorization

This is the part worth watching closely. **Five requests, five different refusals.**

### 3.1 Carol — a colleague in the same organization — tries to read Bob's ticket

```bash
m2 -w '\nstatus=%{http_code}\n' $B/v1/tickets/$TID
```

```json
{"error":"forbidden","message":"You do not have access to this resource.","request_id":"3fcc06276b904b358495f7cc4c57f692"}
status=403
```

**403, generic message.** Carol is a legitimate member of `org-acme` but does not own this
ticket. In the pre-review code this returned **200** — `can_update_ticket` / `can_read_ticket`
existed and the update path never called it (finding F-003).

### 3.2 Alice — the admin of the same organization — reads it

```bash
a1 -o /dev/null -w 'status=%{http_code}\n' $B/v1/tickets/$TID
```

```
status=200
```

Role-based access working in the allow direction, not just the deny direction.

### 3.3 Dave — admin of a *different tenant* — tries to read it

```bash
b1 -w '\nstatus=%{http_code}\n' $B/v1/tickets/$TID
```

```json
{"error":"not_found","message":"The requested ticket was not found.","request_id":"239278cc1e7a44b7bbb3af0ed3618692"}
status=404
```

**404, not 403.** This is the single most important line in the demo. Dave is an
administrator — just of the wrong tenant. He learns **nothing**: not that the ticket
exists, not that it belongs to someone else.

And it is **structural**, not a hand-written branch. The read is
`GetItem(PK=TENANT#org-contoso, SK=TICKET#<id>)`; that item is not in Dave's partition, so
DynamoDB returns nothing and the service returns the same 404 it returns for an id that
exists nowhere. A 403 here would be an existence oracle for enumerating ticket ids across
tenants (finding F-008).

### 3.4 Bob tries to write *into* Dave's tenant

```bash
m1 -X POST $B/v1/tickets -H 'Content-Type: application/json' \
   -d '{"title":"x","description":"y","organization_id":"org-contoso"}' \
   -w '\nstatus=%{http_code}\n'
```

```json
{"error":"invalid_request","message":"The request did not match the expected schema.",
 "request_id":"d6fe0035ab0742b4b60a676b87febad5",
 "fields":[{"field":"organization_id","reason":"Extra inputs are not permitted","type":"extra_forbidden"}]}
status=422
```

**422, and the submitted value is not echoed back.** Two controls visible at once:
`extra="forbid"` rejects the unknown field outright rather than silently dropping it
(rejection is *logged*, so a probing client becomes visible), and the validation error names
the field but not its value (finding F-008).

Against the pre-review code this request returned **`201 Created`** with
`"organization_id":"org-contoso"` — a successful cross-tenant write. The captured output is
in [`../assessments/regression-evidence.md`](../assessments/regression-evidence.md) §2.

### 3.5 Bob claims to be an admin in the header

```bash
# Same user id as Bob, but asserting X-Local-Role: admin
curl -s -w '\nstatus=%{http_code}\n' -X PATCH $B/v1/tickets/$TID \
  -H 'Content-Type: application/json' -d '{"status":"closed"}' \
  -H "X-Local-User-Id: 22222222-2222-4222-8222-222222222222" \
  -H "X-Local-Org-Id: org-acme" -H "X-Local-Role: admin"
```

```json
{"error":"forbidden","message":"You do not have access to this resource.","request_id":"777c906987ee4ab89783c1d6d2fd35bb"}
status=403
```

**Denied.** Bob asserted `admin`, but the **membership record** in DynamoDB says `member`,
and the record is what the authorization decision uses — the claim is advisory only
(finding F-002). In AWS the equivalent is a `custom:role` token claim, and the same thing
happens.

The attempt is not silent. The server logged:

```json
{"event_type": "role_claim_mismatch", "outcome": "allowed",
 "reason": "membership_record_is_authoritative",
 "principal_id": "22222222-2222-4222-8222-222222222222", "organization_id": "org-acme"}
```

That event has a CloudWatch alarm (threshold 5 / 5 min) and a runbook entry.

### 3.6 A suspended member

```bash
curl -s -w '\nstatus=%{http_code}\n' $B/v1/tickets \
  -H "X-Local-User-Id: 66666666-6666-4666-8666-666666666666" \
  -H "X-Local-Org-Id: org-acme" -H "X-Local-Role: member"
```

```json
{"error":"forbidden","message":"Access to this organization is not permitted.","request_id":"93796cadb1da4f139ca151929f3a5e41"}
status=403
```

The membership exists but `status != "active"`. Because the role is read from the record on
**every request**, a revocation takes effect immediately rather than when a token expires.
That is the operational payoff of the F-002 design, and Runbook A §7 option C3 relies on it.

---

## 4. Lifecycle and input validation

### 4.1 Closing a ticket is admin-only, and `closed` is terminal

```bash
m1 -w '\nstatus=%{http_code}\n' -X PATCH $B/v1/tickets/$TID \
   -H 'Content-Type: application/json' -d '{"status":"closed"}'
```

```json
{"error":"forbidden","message":"You do not have access to this resource.","request_id":"698e6bd2d49d473c939582268a4bd051"}
status=403
```

Bob owns the ticket, so he may *update* it — but closing is a privileged transition
(finding F-013). Closing ends the support obligation and stops SLA measurement, so a
compromised member account cannot use it to bury activity.

```bash
a1 -o /dev/null -w 'status=%{http_code}\n' -X PATCH $B/v1/tickets/$TID \
   -H 'Content-Type: application/json' -d '{"status":"closed"}'
# status=200

a1 -w '\nstatus=%{http_code}\n' -X PATCH $B/v1/tickets/$TID \
   -H 'Content-Type: application/json' -d '{"status":"open"}'
```

```json
{"error":"conflict","message":"A ticket in status 'closed' cannot move to 'open'.","request_id":"2d8e5f0b27a64d4c9296773361c338cc"}
status=409
```

**409, not 403.** The caller *is* permitted to act; the ticket is simply not in a state that
allows it. Keeping those distinct is what makes the 403 metric meaningful for alerting.

### 4.2 Page size is bounded

```bash
for L in 0 -5 101 999999; do printf 'limit=%-8s ' "$L"
  m1 -o /dev/null -w 'status=%{http_code}\n' "$B/v1/tickets?limit=$L"; done
```

```
limit=0        status=422
limit=-5       status=422
limit=101      status=422
limit=999999   status=422
```

Rejected at the edge, before a handler runs, and clamped again in the repository
(finding F-009).

### 4.3 Identifiers must be UUIDs

```bash
m1 -o /dev/null -w 'status=%{http_code}\n' "$B/v1/tickets/not-a-uuid"
m1 -o /dev/null -w 'status=%{http_code}\n' "$B/v1/tickets/x%23TICKET%23other"
```

```
status=422
status=422
```

The second is the interesting one: `%23` is `#`, the DynamoDB key separator. A
`ticket_id` of `x#TICKET#other` would compose a key the application never intended to build
(finding F-011). Rejected twice — by the `UUID` type at the edge, and again by
`keys._assert_no_separator` before any key is constructed.

### 4.4 A forged pagination cursor

```bash
FORGED=$(python3 -c "import base64,json;print(base64.urlsafe_b64encode(json.dumps(
  {'PK':'TENANT#org-contoso','SK':'TICKET#00000000-0000-4000-8000-000000000000'},
  separators=(',',':'),sort_keys=True).encode()).decode())")
echo "$FORGED"
m1 -w '\nstatus=%{http_code}\n' "$B/v1/tickets?cursor=$FORGED"
```

```
eyJQSyI6IlRFTkFOVCNvcmctY29udG9zbyIsIlNLIjoiVElDS0VUIzAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMCJ9
{"error":"invalid_request","message":"Invalid pagination cursor.","request_id":"d7f827d855c048daa9c2fa60cf9990df"}
status=400
```

A cursor is opaque to a well-behaved client and **mutable input** to everyone else. This one
was hand-built to resume a listing inside `org-contoso`'s partition. It is rejected because
`decode_cursor` requires `PK == TENANT#{caller's own org}`, and the database is never
queried (finding F-010). The error message is identical for every rejection reason, so the
decoder cannot be probed.

---

## 5. No customer content reaches the logs

```bash
# In the server's terminal, or against a captured log file:
grep -c 'Cannot access account\|Synthetic support request' server.log
```

```
0
```

Zero. The ticket was created, read, denied, updated and closed — and neither its title nor
its description appears anywhere in the log stream (finding F-007).

What *is* logged is enough to investigate:

```json
{"event_type": "ticket_created", "outcome": "allowed",
 "principal_id": "22222222-2222-4222-8222-222222222222", "organization_id": "org-acme",
 "resource_type": "ticket", "resource_id": "2c0e45fe-451c-485b-a4bd-2be908d8d1a3"}

{"event_type": "authorization_denied", "outcome": "denied", "reason": "read:not_ticket_owner",
 "principal_id": "33333333-3333-4333-8333-333333333333", "organization_id": "org-acme",
 "role": "member", "resource_type": "ticket", "resource_id": "2c0e45fe-451c-485b-a4bd-2be908d8d1a3"}

{"event_type": "authorization_denied", "outcome": "denied",
 "reason": "status_change:privileged_status_requires_admin",
 "principal_id": "22222222-2222-4222-8222-222222222222", "organization_id": "org-acme", ...}
```

Who, which organization, which ticket, what was attempted, and why it was refused —
**identifiers and outcomes, never content.** The control is an allow-list
(`ALLOWED_LOG_FIELDS`), so a field is invisible unless it has been explicitly reviewed. A
deny-list would fail the first time someone added a field.

---

## 6. Running the security tests

```bash
python -m pytest -q
```

```
603 passed, 13 skipped, 148 warnings in 11.44s
```

```bash
python -m pytest -m regression -q --no-header
# 141 passed
```

### The before/after proof

A regression test that has never failed is not evidence that it tests anything. Run the
current security suite against the pre-review code:

```bash
git worktree add /tmp/v1check v1-pre-review
cp -r tests /tmp/v1check/tests_current && cp pyproject.toml /tmp/v1check/pyproject.toml.cur
cd /tmp/v1check && rm -rf tests && mv tests_current tests && cp pyproject.toml.cur pyproject.toml
python -m pytest tests/security -q
```

```
93 failed, 102 passed, 78 warnings in 6.75s
```

```bash
cd - && git worktree remove --force /tmp/v1check
```

**93 failures against the vulnerable code; 195 passes against the fixed code.** That is the
difference between a test suite and a claim.

---

## 7. Scanning the infrastructure

```bash
python -m checkov.main -d infrastructure/ --framework terraform --compact --quiet
```

```
Passed checks: 137, Failed checks: 0, Skipped checks: 12
```

All 12 skips are inline, scoped to one check on one resource, and individually justified:

```bash
grep -rn 'checkov:skip' infrastructure/
```

There is no baseline file and no blanket `--skip-check` — both make the number of suppressed
findings invisible.

```bash
python scripts/validate_terraform.py infrastructure/terraform
```

Checks HCL references, undeclared variables, hardcoded account ids and credential-shaped
literals. It also prints its own limitations, which matters: it is **not**
`terraform validate` and does not check provider schemas.

---

## 8. The custom IAM policy checker

Against the policies that actually deploy:

```bash
python security-automation/iam_policy_checker.py \
  --input infrastructure/terraform/policies/ --output reports/iam-findings.json
```

```
total_findings: 1   blocking_findings: 0
by_severity:    critical 0  high 0  medium 0  low 0  info 1
by_confidence:  confirmed 0  needs_context 1
IAM003  info  needs_context  Unscoped resource on actions that do not support scoping
                             → policies/lambda-xray.json
```

The one finding is `needs_context`, not `confirmed` — X-Ray's `PutTraceSegments` genuinely
does not support resource-level scoping, so `Resource: "*"` is the only legal form. The
tool says "this needs a human" rather than "this is a defect".

### Now prove the gate can actually fail

```bash
python security-automation/iam_policy_checker.py \
  --input sample-data/insecure-policy.json --fail-on high
echo "exit=$?"
```

The synthetic fixture contains `Action: "*"`, `dynamodb:*`, `logs:*` on `Resource: "*"`,
`iam:PassRole`, `NotAction`, and `cloudtrail:StopLogging`. It exits **non-zero** with
findings across IAM001–IAM011. CI runs this as a **gate self-test** — a gate that has never
rejected anything is not a verified gate.

```bash
python security-automation/iam_policy_checker.py --list-rules
```

Prints all 11 rules *and the tool's documented limitations*. It does not claim IAM
policy-evaluation equivalence or parity with AWS IAM Access Analyzer.

---

## 9. Finding triage

```bash
python security-automation/finding_triage.py \
  --input reports/checkov.json --input reports/bandit.json \
  --input reports/pip-audit.json --input reports/iam-findings.json \
  --output reports/triage-report.json --markdown reports/triage-report.md
```

```
Inputs             : checkov.json, bandit.json, pip-audit.json, iam-findings.json
Total findings     : 2
Open               : 2   New: 2   Overdue: 0   Newly resolved: 0
Duplicates removed : 0
Aggregate open risk: 18.9   (highest single: 15.0)
By priority : P4=2
By severity : low=1  info=1
By owner    : application-security=1  cloud-security-engineering=1

Top open findings by risk:
  P4   15.0  FINDING-350F07A5  Possible hardcoded password: 'secrets' [NEW]
  P4    3.9  FINDING-83F4CAD6  Unscoped resource on actions that do not support sco [NEW]
```

Four tool formats into one normalised schema, with stable ids, deduplication, risk scoring
and owner assignment. Pass `--previous reports/triage-report.json` on a later run to get
cross-run status tracking (`new` / `open` / `overdue` / `newly resolved`).

> The top finding is a **false positive**, and it is left visible on purpose: a
> category-synonym dictionary in `finding_triage.py` maps the label `"secret"` to the string
> `"secrets"`, which Bandit's `B105` flags. It is not suppressed with `# nosec` — the
> repository's `nosec` count is 0. Recorded as observation O-6.

---

## 10. The whole pipeline

```bash
./scripts/run_security_checks.sh
```

```
Passed: 17   Failed: 0
Reports: reports/
```

Same tools, same order, same gating as `.github/workflows/security-ci.yml`. If this passes
and CI fails, the two have drifted — that is a pipeline bug.

---

## 11. Reviewing the security report

| Read this | For |
|---|---|
| [`../assessments/executive-summary.md`](../assessments/executive-summary.md) | One page, plain language, for leadership |
| [`../assessments/security-findings.md`](../assessments/security-findings.md) | All 15 findings with code evidence and CWE/OWASP mapping |
| [`../assessments/regression-evidence.md`](../assessments/regression-evidence.md) | Verbatim before/after command output |
| [`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md) | Full report: methodology, decisions, residual risk, limitations |
| [`../threat-model/threat-model.md`](../threat-model/threat-model.md) | 16 STRIDE threats |
| [`../runbooks/authorization-alert-triage.md`](../runbooks/authorization-alert-triage.md) | What an on-call engineer does when the denial alarm fires |

---

## 12. What this demo does *not* show

Stated so the demo is not mistaken for more than it is:

| Not demonstrated | Why | Where it is covered |
|---|---|---|
| Real JWT validation | There is no API Gateway on a laptop; validation is deliberately the gateway's job | 13 skipped tests in `tests/integration/test_aws_gateway_contract.py` |
| Real Cognito sign-in | No user pool | `cognito.tf`, reviewed only |
| Real IAM enforcement | The local run has no IAM at all. `dynamodb:Scan` being denied is unproven | Limitation L1 |
| Real DynamoDB semantics | `moto` emulates conditional writes and consistency | Limitation L5 |
| CloudWatch alarms firing | Nothing deployed; thresholds are reasoned estimates, never tuned | Limitation L1 |
| `terraform validate` / `plan` | The binary cannot be installed in the authoring environment | Limitation L2 |
| The CI pipeline running green on GitHub | No remote repository; CodeQL has produced no results | Limitation L3 |

The local demo proves the **application's** security controls. It does not prove the
**cloud** controls, and this project does not claim that it does.
