# Interview Guide

Technical explanations for every part of this project, written as answers you can actually
say out loud. Each one leads with the short version, because an interviewer asking "how does
authorization work?" wants two sentences first and depth only if they ask for it.

**Have these three things open:** `application/app/security/`,
`assessments/security-findings.md`, and a terminal running `python scripts/local_server.py`.

---

## 1. Why this architecture?

**Short version.** It is a multi-tenant API, so the dominant risk is one customer reading
another customer's data. I designed it so that isolation is a property of the *data access
pattern* rather than of a check someone has to remember — the DynamoDB partition key is the
tenant, derived from a gateway-verified identity. Everything else follows from wanting that
one property to be hard to break.

**If they push.** Three decisions did most of the work:

1. **Token validation at API Gateway, not in my code.** The application has no code path
   that accepts a token, so a token-parsing bug has nowhere to land, and unauthenticated
   requests never reach compute. The cost is real: I can't unit-test that locally, so 11
   tests are explicitly skipped rather than quietly missing.
2. **Organization as the partition key.** A `Query` can't read outside the partition it
   queries, so cross-tenant reads aren't *prevented* — they're impossible. The alternative,
   a flat table with a filter, makes isolation depend on remembering to filter.
3. **Role from a server-side record, not the token.** A token is a cached snapshot. Someone
   demoted five minutes ago still has one.

**Trade-off I'd name unprompted.** It's *logical* isolation — one table, one role, one
function. A customer with a hard-isolation requirement needs per-tenant tables or accounts,
and that's a different architecture, not a config change.

---

## 2. How does authentication work?

**Short version.** Cognito issues a JWT. API Gateway's JWT authorizer validates signature,
issuer, audience and expiry before any of my code runs. My application reads the caller's
identity from `event["requestContext"]["authorizer"]["jwt"]["claims"]` and from nowhere
else.

**The detail that matters.** It's specifically `authorizer.jwt`, not `authorizer`. A REQUEST
(Lambda) authorizer puts its context under `authorizer.lambda` — reading that would accept
an identity that never went through token validation. One line, and it's the difference
between a trust boundary and a suggestion.

**Local development.** There's no gateway on a laptop, so there's an adapter that reads
`X-Local-*` headers. That adapter is a deliberate authentication bypass, so three
independent things keep it out of a deployed environment: `Settings` refuses to load it
unless `environment=local`, its constructor raises on the same condition, and `gateway` is
the default so an unset variable is safe. Terraform also sets it explicitly. And it emits an
alarmed event when constructed, so if it ever happens in AWS I find out.

**This is finding F-001** — I'll come back to that.

---

## 3. How does tenant authorization work?

**Short version.** Two layers that fail differently. **Tenancy** is enforced in the data
layer: the partition key comes from the verified principal, so the query can't cross the
boundary. **Permissions** are enforced in the service layer with an explicit allow/deny
decision. Neither can be bypassed by forgetting the other.

**Walk the request.**

1. Gateway validates the token → claims land in the event.
2. `identity.py` extracts `sub` and `custom:organization_id`.
3. It then does a `ConsistentRead` `GetItem` for
   `USER#{sub}` / `MEMBERSHIP#{org}`. **That record is authoritative for the role.** The
   token's `custom:role` is kept as `claimed_role` and never used for a decision. If they
   disagree, the record wins and I log `role_claim_mismatch`.
4. Membership must exist *and* be `active`, so a revocation takes effect immediately rather
   than at token expiry.
5. The service loads the ticket from the caller's partition, asks the policy for a
   `Decision`, and calls `enforce()`.

**Why a `Decision` and not a `bool`.** Because the first draft defined `can_update_ticket()`
and never called it. An unused boolean is unremarkable; an unused `Decision` that was never
passed to `enforce()` stands out in review. That changes the *class* of bug, not just the
instance.

---

## 4. How does it prevent cross-tenant access?

**Four layers, and I'd say them in this order:**

| Layer | Control | What it survives |
|---|---|---|
| Data model | `PK = TENANT#{org}` from the verified principal | A forgotten filter |
| Query | No `Scan`; member listing via GSI1 keyed on **tenant + user** | Reading other tenants into memory at all |
| IAM | Explicit `Deny` on `dynamedb:Scan` and destructive actions | A code change that reintroduces a scan |
| Response | 404 for cross-tenant *and* for absent | Existence enumeration |

**The bit I'd make sure they notice.** The 404 isn't a careful `if`. The read is
`GetItem(PK=TENANT#their-org, SK=TICKET#id)`. That item isn't in their partition, so DynamoDB
returns nothing, and the service returns the same 404 it returns for an id that exists
nowhere. The indistinguishability is a *consequence* of the key design, not a branch someone
could forget.

**And the subtle one.** GSI1's partition key is `TENANT#{org}#USER#{user}` — both. If I'd
keyed it on the user alone, a user who belongs to two organizations would see tickets from
one surface in a query scoped to the other. Correct base table, cross-tenant index.

**Demo it.** `docs/DEMO.md` §3 — five requests, five different refusals, including a forged
pagination cursor.

---

## 5. How did you apply STRIDE?

**Short version.** Per data flow, not per component — because in this system every
interesting threat lives at a boundary crossing, not inside a box. I enumerated 10
cross-boundary flows, walked all six STRIDE categories against each, and kept what was
credible. 16 threats survived.

**What I'd emphasise.** I documented what I **discarded** and why: SQL injection (no SQL,
and queries use the `boto3` condition builders rather than string concatenation), XSS (JSON
only, `nosniff`, `default-src 'none'`), CSRF (no cookie auth — the credential is a header a
cross-site form can't set), insecure deserialization (no `pickle`/`yaml.load`/`eval`
anywhere). A threat model that only lists hits isn't auditable; you can't tell whether
something was considered or missed.

**The honest part.** Ten of the 16 threats turned out to be **realised** in my first draft.
That's the point of the two-pass method — the threat model isn't a parallel document
asserting the system is safe, it's what the review was conducted against.

---

## 6. How did you do the code review?

**Short version.** Deliberately two passes. I wrote the application the way you write it
under delivery pressure — working, idiomatic, not security-reviewed — and tagged it
`v1-pre-review`. Then I reviewed it against a 10-domain, 60-item checklist. For each
confirmed weakness: write a test that **fails** against the draft, record the finding with
file and line, fix it, re-run, mark it `regression`.

**Say the limitation before they ask.** The author of the vulnerable code and the reviewer
who found it are the same engineer. That's the weakest form of review and it's disclosed in
the checklist, the final assessment and the traceability matrix. A real second pair of eyes
would find things I didn't.

**The distinction I'd highlight.** I separated **confirmed findings** (concrete code path +
a demonstrating test) from **observations** (real engineering concerns with no demonstrable
weakness). 15 findings, 7 observations, and the observations are excluded from the counts.
That's the difference between a finding and a worry, and conflating them is how finding
counts get inflated.

---

## 7. What real findings did you identify?

**15 confirmed: 1 critical, 4 high, 7 medium, 3 low.** The three worth talking about:

**F-001 — Critical, authentication bypass.** The identity resolver preferred the gateway
authorizer context but **fell back to `X-User-Id` / `X-Org-Id` headers** when it was
absent — and `identity_source` defaulted to `"header"`, so the insecure path was the
default. Any unauthenticated caller who could reach the function could assert an arbitrary
user in an arbitrary tenant. They pick the identity *and* the tenant, and the logs record
whatever they typed.

The root cause is the interesting part: a local-development convenience implemented as a
**silent runtime fallback** in the production path. It triggers exactly when the trusted
context is missing — which is the condition an attacker creates.

**F-004 — High, cross-tenant write.** `TicketCreateRequest` declared an optional
`organization_id`, and the service did `payload.organization_id or principal.organization_id`.
One extra JSON field and any authenticated user writes a ticket **into another tenant's
partition**. I have the captured `201 Created` showing it — the response body says
`"organization_id":"org-contoso"` while the caller was in `org-acme`. `TicketUpdateRequest`
also had `extra="allow"` with a comment explaining it as schema flexibility, which is
exactly how that defect survives review.

**F-003 — High, missing enforcement.** `can_update_ticket()` defined, never called. Any
member could PATCH any ticket in their organization. Invisible on a quick read *because* the
helper existed.

**Full records:** `assessments/security-findings.md`, each with file/line evidence, CWE,
OWASP mapping, root cause, the fix, and the guarding test.

---

## 8. How was remediation verified?

**Short version.** Every fix is held by a test that was first demonstrated to **fail**
against the vulnerable code. I ran the current security suite, unchanged, against
`v1-pre-review`:

```
93 failed, 102 passed      # against v1-pre-review
195 passed                # against HEAD
```

**Why I bothered.** A regression test that has never failed is not evidence that it tests
anything. Plenty of test suites are full of assertions that would pass against a broken
implementation. The 84 failures are the proof that these 141 regression-marked tests are
load-bearing.

**Reproducible in four commands** — `git worktree add`, copy the current tests over the old
application, run pytest. It's in `docs/TESTING.md` §5.

**A detail I like.** 92 tests *passed* against v1, and that's useful: the first draft wasn't
uniformly insecure. It had a working log formatter and correct happy-path behaviour. Those
passes bound the review's blast radius to the 93 behaviours that actually changed.

**One finding is weaker, and I say so.** F-005 (the over-privileged IAM role) has no
before/after test diff, because the infrastructure was written after the review and
committed already remediated. Its evidence is a design-decision record plus a CI gate
self-test proving the analyzer rejects that pattern. Weaker evidentially, flagged as
`Validated: partial` rather than smoothed over.

---

## 9. How did you scope the IAM permissions?

**Short version.** Enumerated actions, ARN-scoped resources, nothing the application doesn't
do, and explicit `Deny` where the blast radius is large.

The execution role gets exactly `dynamodb:GetItem`, `PutItem`, `Query` on the table and its
GSI, plus `logs:CreateLogStream` and `PutLogEvents` on its own log group, plus KMS
constrained by a `kms:ViaService` condition.

**Four things I'd call out:**

1. **Omission as a control.** No `UpdateItem`, no `CreateLogGroup`, no `Scan`. A future
   change that needs one fails with `AccessDenied`, which forces the permission through
   review instead of letting it arrive silently.
2. **Explicit `Deny`** on `Scan`, `DeleteItem`, `DeleteTable`, `iam:PassRole`,
   `sts:AssumeRole`, `kms:ScheduleKeyDeletion`, `logs:DeleteLogGroup`. A `Deny` can't be
   overridden by any later `Allow`, so those stay shut even if someone attaches a broad
   policy to the role later. The `logs:Delete*` and `cloudtrail`-adjacent denies are
   anti-forensic protection specifically — an attacker shouldn't be able to destroy the
   evidence.
3. **A permissions boundary** caps the role, so a change-management failure can't widen it.
4. **Policies committed as JSON, not `aws_iam_policy_document`.** This is the unusual choice
   and I'd explain it: a policy document data source is rendered by the provider at plan
   time, so you can't inspect the policy without AWS credentials — which means CI can't gate
   the policy that actually deploys. Committed JSON means my own checker runs against the
   real document, and a permission change reviews as a policy diff instead of as HCL.

**The gap I'd volunteer.** `PutItem` is scoped to the table, not to the `TICKET#` sort-key
prefix. IAM can't express that — `dynamodb:LeadingKeys` constrains the *partition* key only.
So an arbitrary-write bug could in principle write a membership record, which is my
authorization source of truth. It's compensated (no code path writes a `USER#` key, and
that's test-asserted; conditional writes; `Deny` on delete) but the clean fix is a separate
membership table, and it's my number-one next step. It's accepted risk AR-04.

---

## 10. How do the CI/CD security gates work?

**Five stages:** code quality (Ruff with the bandit and annotation rule sets), application
security (CodeQL, Bandit, pip-audit), infrastructure (Terraform fmt/validate, Checkov, my
IAM checker), tests (unit/integration/security/regression), and reporting (my triage tool).

**Four design points worth more than the tool list:**

1. **A `security-gate` job that treats a *skipped* security job as a failure.** It's the
   only required status check. "Did not run" must never read as "passed" — that's the most
   common way a security pipeline silently stops working.
2. **No `continue-on-error` on a security step.** The one place it appears is the Terraform
   *setup* step, and the very next step fails loudly if setup didn't succeed — so a runner
   that can't fetch Terraform fails instead of silently skipping validation.
3. **Nothing is auto-suppressed.** No Checkov baseline, no `--skip-check`, no `# nosec`
   anywhere — the repo's `nosec` count is 0. The 12 Checkov skips are inline, scoped to one
   check on one resource, each with a written justification naming an accepted-risk ID. And
   there's a Bandit false positive I deliberately left **visible** rather than silencing.
4. **A gate self-test.** The pipeline runs my IAM checker against a deliberately insecure
   synthetic fixture and **fails if it passes**. A gate that has never rejected anything
   isn't a verified gate.

**Honest status:** the workflow has never executed — no remote repository. So CodeQL has
produced **no results at all**, and that's a real blind spot since it's the one tool with no
local equivalent. Everything else is reproduced by `scripts/run_security_checks.sh`, which
passes 16/16.

---

## 11. How do your custom tools work?

### `iam_policy_checker.py` (1,586 lines, 11 rules, 59 tests)

Parses IAM JSON — policy files, directories, or Terraform plan output — and flags risky
patterns: admin wildcards, service-wide wildcards (`dynamodb:*`), unscoped resources,
privilege-escalation primitives (`iam:PassRole` + `AttachRolePolicy`), unscoped secret and
data reads, inverted matching (`NotAction`), wildcard principals, missing confused-deputy
conditions, destructive and anti-forensic actions, missing `Sid`, legacy policy version.

**Two things I'd emphasise over the rule count:**

- **It classifies findings `confirmed` or `needs_context`.** `Resource: "*"` on X-Ray's
  `PutTraceSegments` is `needs_context`, because those actions genuinely don't support
  resource-level scoping — `"*"` is the only legal form. A tool that screamed "critical"
  there would train people to ignore it.
- **It documents its own limitations.** `--list-rules` prints them. It does **not** resolve
  policy interaction, SCPs, permissions boundaries or resource policies, and it does not
  claim parity with IAM Access Analyzer. It's a pattern matcher, and saying so is what makes
  it trustworthy.

### `finding_triage.py` (1,927 lines, 142 tests)

Takes Checkov, Bandit, pip-audit, my IAM checker and Security Hub ASFF, and produces one
normalised, deduplicated, prioritised view with owners assigned by rule.

**The feature that makes it useful rather than decorative:** `--previous`. Diff against the
last run and you get `new` / `open` / `overdue` / `newly resolved`. That's what turns a pile
of scanner output into something you can manage — "is this regressing?" becomes answerable.
Stable finding ids are what make it work, and they're deterministic so two runs on the same
input produce the same ids.

---

## 12. How are findings prioritised?

**Severity is assigned on impact in the deployed shape, not on exploit difficulty alone**,
and I adjust the tool's score using context the tool doesn't have: is the resource
internet-reachable, does it touch tenant data, could it cross the tenant boundary, is the
blast radius account-wide, would it *disable detection*.

That last one matters — a finding that blinds your logging is a Tier-1 problem wearing a
Tier-4 costume.

**Worked example of adjusting downward:** Checkov flags `Resource: "*"` on my KMS key
policy. In a *key* policy, `Resource: "*"` denotes the key itself — it's the only legal
form, and the account-root statement is mandatory for key manageability. True positive in an
identity policy, false positive here. I suppressed it inline with that reasoning and
recorded it as accepted risk AR-01 with an owner and a review date.

**Worked example of adjusting upward:** F-004's create vector is arguably Critical, not High
— it's a cross-tenant *write* available to any authenticated user via one JSON field. I
rated it High because the attacker must already hold a valid account, and I wrote that
reasoning down so a reviewer can disagree with it.

---

## 13. What does the monitoring detect?

8 alarms over 5 log metric filters. The security-relevant ones: `authorization_denied`
bursts, `role_claim_mismatch`, `insecure_identity_adapter_enabled` (threshold **1** — it
should be impossible), `unhandled_error`, and gateway 401 bursts.

**The clever one.** Because the API deliberately returns 404 for cross-tenant *and* absent
resources, there's no 403 to count for cross-tenant probing. So there's a saved Insights
query that finds principals generating many `resource_not_found` events with many
**distinct** `resource_id`s — high misses with low distinct ids is a client retrying a
deleted ticket; high misses with high distinct ids is someone walking identifiers. That
query is the signal that replaces the 403 the API intentionally doesn't return.

**What it can't detect, which I'd volunteer:**

- **A successful cross-tenant read through a control failure looks normal.** The log says
  `outcome = allowed` with whatever organization the code *believed* was right.
- **Token theft isn't directly detectable.** A replayed bearer token is indistinguishable
  from legitimate use. That's accepted risk AR-03 and it's inherent to the bearer model.
- **No alarm for "a principal read an unusual volume of tickets."** Bulk read by a
  legitimately-authorized admin isn't currently distinguishable from abuse.
- **None of these alarms has ever fired**, because nothing is deployed. The thresholds are
  reasoned estimates, not tuned values.

Those gaps are written into the runbook, because a responder needs to know what the tooling
can't see.

---

## 14. What limitations remain?

I'd lead with this rather than wait to be asked. **Nine, documented as L1–L9.** The ones
that matter:

- **L1 — nothing is deployed.** No AWS account was used. Live JWT rejection, real IAM
  enforcement, Cognito flows and alarm firing are all unverified. 11 tests are present and
  explicitly skipped rather than absent, so the suite reports the gap on every run.
- **L2 — `terraform validate` has never run.** The binary couldn't be installed in my build
  environment (`releases.hashicorp.com` was outside the egress allow-list, and routing
  around a policy denial isn't an option). Checkov parsing all 10 files is partial evidence
  the HCL parses; it is **not** provider-schema validation, and I don't present it as such.
- **L3 — the pipeline has never run.** CodeQL has produced no results.
- **L5 — DynamoDB behaviour is asserted against `moto`.** Conditional-write semantics are
  verified against an emulator.
- **L7 — author and reviewer are the same person.**

**Residual risk: 0 critical, 0 high, 2 medium, 14 low.** The two mediums are bearer-token
replay and the lack of a per-tenant availability quota — both inherent rather than unfixed.
The third used to be the table-scoped `PutItem` grant; I closed it by splitting memberships
into their own table (see §9).

---

## 15. How would this support more users and services?

**Scales fine:** more tenants (the partition key is the tenant, so load spreads), more
tickets per tenant (everything is key-scoped and paginated), more roles (extend the enum and
the policy matrix — the policy functions are pure and exhaustively tested).

**Breaks first, in order:**

1. **A very large single tenant** creates a hot partition on the admin listing path.
2. **One shared function** means one tenant's traffic spike becomes everyone's throttling.
   Reserved concurrency caps the spend but *is* the mechanism by which that happens. Fix:
   per-tenant usage plans, or dedicated concurrency for the largest customers.
3. **Adding entity types** (comments, attachments) makes sharing a partition with
   memberships worse — so do the membership-table split **first**.
4. **Multiple services** means the membership lookup becomes a cross-service call. That's
   the point where caching with explicit invalidation earns its complexity; today one
   `GetItem` per request is the safe side of that trade.
5. **A compliance requirement for hard isolation** is the real wall. Per-tenant tables or
   accounts — a different architecture, not a configuration change.

---

## Scenario questions

Five questions this project's subject matter would support, with what a strong answer
contains.

### S1. A customer reports seeing a ticket that isn't theirs. You have CloudWatch Logs and no reproduction. First hour?

**Looking for:** containment instinct balanced against evidence preservation, and knowing
which query answers the question.

**Strong answer.** Classify SEV-1 on the report alone — a customer saying this is stronger
evidence than an alarm. Get the `request_id` from them; it's returned in `X-Request-Id` on
every response, which is exactly why it's there. Then the decisive query: did any request
from that principal return `outcome = allowed` for an `organization_id` that isn't theirs?
That distinguishes "the controls held and the UI is confusing them" from "we have a breach".

Don't delete or modify anything — pre-incident configuration is evidence, and the role is
explicitly denied `logs:DeleteLogGroup` for that reason. Don't read the ticket content to
assess impact; identifier counts are enough and content access needs its own authorization.

Engage legal **early**, and be careful with language: "no evidence of access" and "we cannot
determine" are different statements with different consequences. If the logs can't answer
it, say undetermined.

### S2. A developer's PR adds `dynamodb:Scan` to the execution role. It's needed for a legitimate admin reporting feature. What do you do?

**Looking for:** not just "block it" — understanding *why* the control exists and finding
the path that keeps it.

**Strong answer.** Block the merge; my IAM checker gates on high severity and there's an
explicit `Deny` on `Scan` anyway, so the grant wouldn't even work at runtime. That `Deny` is
deliberate: `Scan` is the single action that turns a code bug into a multi-tenant breach.

But the feature is legitimate, so solve it. Options, in order of preference: a separate
access pattern (a GSI keyed for the reporting query); or if it genuinely needs a full-table
read, a **separate function with its own role** — so the tenant-facing path keeps its
`Deny` and the reporting path is a different, auditable identity with narrower exposure.

What I wouldn't do is remove the `Deny` from the shared role, or suppress the check. If we
really decided to accept it, it goes in the final assessment as an accepted risk with a
rating, an owner and a review date — not as a silent baseline entry.

### S3. Checkov fails on an infrastructure change with 40 findings, all on a new module. The release is today. What do you do?

**Looking for:** triage under pressure without either rubber-stamping or theatrically
blocking.

**Strong answer.** 40 findings on one new module is almost always a handful of root causes —
run them through normalisation and deduplication first rather than triaging 40 items.

Then sort by **reachability and data access**, not by the tool's severity. A finding on a
resource that holds tenant data or is internet-reachable blocks. A finding on a log group's
retention does not block a release, it becomes a ticket.

Check each for applicability. The KMS-key-policy `Resource: "*"` class is a real false
positive, and I'd expect a couple of those.

Then be explicit about what ships: fix the reachable/data-touching ones today, and for the
rest create targeted inline suppressions with written justifications, named owners and review
dates — recorded as accepted risks. What I won't do is add a baseline file, because that
makes the count of suppressed findings invisible, which is how 40 findings become 200.

### S4. You find an endpoint that returns 403 for a resource in another tenant and 404 for one that doesn't exist. The team says "they can't read the data either way." Is that good enough?

**Looking for:** understanding that information disclosure is a real class, not pedantry.

**Strong answer.** No. The difference is an **existence oracle**: an attacker can enumerate
valid identifiers across tenants without reading a single byte of content. That's
reconnaissance that makes every subsequent attack cheaper, and it can leak business
information on its own — resource ids are often sequential or contain structure, and
confirming which exist can reveal volumes or customers.

The fix isn't "change the 403 to a 404". That's a branch someone can forget. The fix is to
make the *data access* partition-scoped so both cases produce the same `None`, and the
identical 404 becomes a consequence of the architecture. That's what I did (F-008), and the
compensating detection is an Insights query on `resource_not_found` volume with distinct ids,
since there's no 403 left to count.

### S5. Your team wants to add membership caching because the per-request `GetItem` is showing up in latency and cost. How do you evaluate it?

**Looking for:** not reflexively saying no to a performance change, but naming the exact
security property at risk.

**Strong answer.** The property I'd be protecting is: **revocation takes effect
immediately.** That's not incidental — the containment procedure in Runbook A depends on it
(flip a membership to inactive and access stops now, rather than at token expiry), and it's
the reason role comes from a record instead of the token in the first place.

So the question isn't "cache or not", it's "what's the maximum acceptable revocation
delay?" That's a business and incident-response decision, not an engineering one. If the
answer is 30 seconds, a 30-second TTL is fine and I'd want explicit invalidation on the
revocation path as well, so the normal case is immediate and the TTL is only a backstop.

I'd also want to know the real number first. It's one `GetItem` — if that's the latency
problem, I'd want to see the trace, because it may well not be. And I'd note that caching
authorization data is a classic source of stale-privilege bugs, so whatever we build needs a
test that asserts revocation behaviour at the cache boundary, not just a cache-hit test.

---

## Questions to ask them

Signals genuine interest and tells you about the role:

1. Where does security sit relative to the teams shipping — embedded, consulted, or gating?
2. When a scanner finding is a false positive, what's the process? Is there a baseline file,
   and if so how is its size tracked?
3. How do you verify a remediation actually worked — is a regression test expected?
4. What's the on-call expectation for a security engineer at this level, and what does the
   escalation path look like?
5. How are threat models kept current after the first one is written?

---

## If you don't know something

Say so, then reason out loud from what you do know. For this project specifically, the
honest answers are already written down — nothing has been deployed, `terraform validate`
has never run, CodeQL has produced no results, and the reviewer is the same person as the
author. Knowing exactly where your evidence stops is a security engineering skill, and
claiming verification you don't have is the one thing that should actually disqualify
someone from this job.
