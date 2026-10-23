# Security Findings

Confirmed findings from the manual security code review described in
[`code-review-checklist.md`](code-review-checklist.md).

**15 confirmed findings.** All 15 are remediated and guarded by regression tests.

> **Read this first.** These are findings in **this project's own first-draft code**
> (git tag `v1-pre-review`), identified during a deliberate second-pass review and then
> fixed (tag `v2-remediated`). They are not findings in third-party software. The
> methodology, and its limitation that author and reviewer are the same engineer, are
> disclosed in [`code-review-checklist.md`](code-review-checklist.md) §1.

| ID | Title | Severity | CWE | Status |
|---|---|---|---|---|
| [F-001](#f-001) | Authentication bypass via client-controlled identity headers | **Critical** | CWE-290 | Remediated |
| [F-002](#f-002) | Privilege escalation through a self-asserted role claim | High | CWE-269 | Remediated |
| [F-003](#f-003) | Authorization check defined but never enforced on the update path | High | CWE-862 | Remediated |
| [F-004](#f-004) | Mass assignment permits cross-tenant writes | High | CWE-915 | Remediated |
| [F-005](#f-005) | Over-privileged Lambda execution role | Medium | CWE-250 | Remediated |
| [F-006](#f-006) | Tenant isolation dependent on a filter expression over a full table scan | High | CWE-639 | Remediated |
| [F-007](#f-007) | Customer content and bearer tokens written to logs | Medium | CWE-532 | Remediated |
| [F-008](#f-008) | Information disclosure through error responses | Medium | CWE-209 | Remediated |
| [F-009](#f-009) | Unbounded pagination and request field sizes | Medium | CWE-770 | Remediated |
| [F-010](#f-010) | Pagination cursor forwarded to the database unvalidated | Medium | CWE-639 | Remediated |
| [F-011](#f-011) | Unvalidated identifiers permit storage-key injection | Medium | CWE-20 | Remediated |
| [F-012](#f-012) | Insecure-by-default configuration | Medium | CWE-1188 | Remediated |
| [F-013](#f-013) | Missing ticket lifecycle controls | Low | CWE-285 | Remediated |
| [F-014](#f-014) | Missing HTTP security response headers | Low | CWE-693 | Remediated |
| [F-015](#f-015) | Unconditional writes silently replace records | Low | CWE-362 | Remediated |

---

<a id="f-001"></a>
## F-001 — Authentication bypass via client-controlled identity headers

| Field | Value |
|---|---|
| **Finding ID** | F-001 |
| **Affected component** | `application/app/security/identity.py`; `application/app/config.py` |
| **Severity** | **Critical** (CVSS 3.1 base 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N, calculated for the deployed shape) |
| **Relevant CWE** | CWE-290 (Authentication Bypass by Spoofing); CWE-807 (Reliance on Untrusted Inputs in a Security Decision) |
| **OWASP** | API2:2023 Broken Authentication; A07:2021 Identification and Authentication Failures |
| **Security requirement** | SR-A1, SR-A3, SR-A4 |
| **Threat** | T-01 |
| **Status** | **Remediated** · retested · regression test present |

### Description

The identity resolver preferred the API Gateway JWT authorizer context but **fell back to
request headers** when that context was absent, and `identity_source` defaulted to
`"header"` — so the insecure path was the default, not the exception.

Any caller who could reach the function's HTTP surface could assert an arbitrary
`X-User-Id` and `X-Org-Id` with **no bearer token at all**, and be served as that user in
that organization. The attacker chooses both the identity and the tenant.

A second, subtler issue in the same function: the authorizer context was read as
`authorizer.get("jwt", {}).get("claims")` but the code did not require the request to have
passed *JWT* validation specifically. A REQUEST (Lambda) authorizer places its context
under `authorizer.lambda`, so a future authorizer swap could have supplied claims that
never went through token validation.

### Root cause

A local-development convenience was implemented as a **silent runtime fallback** inside
the production code path, rather than as an explicitly-selected adapter that cannot load
outside local development. The fallback triggers precisely when the trusted context is
missing — which is exactly the condition an attacker creates.

### Potential impact

Complete authentication bypass and full cross-tenant read/write access for an
unauthenticated internet caller. Multi-tenant data breach, reportable. Forensics would be
near-useless: the logged `principal_id` is whatever the attacker typed.

### Evidence

Pre-remediation, `v1-pre-review`:

```python
# application/app/security/identity.py:38-50
def _header_claims(request: Request) -> dict[str, Any] | None:
    """Return claims supplied directly on the request headers.

    Used for local development and for smoke-testing the API without a
    Cognito user pool in front of it.
    """
    user_id = request.headers.get("X-User-Id")
    org_id = request.headers.get("X-Org-Id")
    if not user_id or not org_id:
        return None
    return {
        _CLAIM_USER_ID: user_id,
        _CLAIM_ORG_ID: org_id,
        _CLAIM_ROLE: request.headers.get("X-Role", "member"),
    }

    # application/app/security/identity.py:62-66
    claims = _gateway_claims(request)
    if claims is None:
        claims = _header_claims(request)  # <-- the bypass
    if claims is None:
        raise NotAuthenticatedError("No identity present on request")
```

```python
# application/app/config.py:27  (the insecure source was the DEFAULT)
    identity_source: str = "header"
```

Reproduce the finding against the pre-review tag:

```bash
git stash list >/dev/null; git worktree add /tmp/v1 v1-pre-review
cp -r tests /tmp/v1/tests && cd /tmp/v1 && python3 -m pytest tests/security/test_authentication.py -q
# 6 failures, including identity asserted purely from headers being accepted
```

### Recommended remediation

Delete the fallback. Read identity from the verified authorizer context only. Make any
local adapter an explicitly-configured object that *cannot be constructed* outside a local
environment, and make the secure source the default.

### Implemented remediation

1. `ApiGatewayJwtIdentityProvider.extract()` reads
   `event["requestContext"]["authorizer"]["jwt"]["claims"]` and returns `None` on any
   missing or wrongly-typed level. There is no header path.
2. The `authorizer.lambda` context is **explicitly ignored**, with a comment stating why,
   so a REQUEST authorizer cannot substitute for JWT validation.
3. The local adapter is a separate class reading only `X-Local-*` headers — deliberately
   prefixed so they can never be confused with a real identity header and can be stripped
   by one WAF rule.
4. Three independent guards: `Settings` refuses to load `identity_source="local_test"`
   unless `environment=="local"`; `LocalTestIdentityProvider.__init__` raises on the same
   condition; and `gateway` is the **default**.
5. Terraform sets `APP_IDENTITY_SOURCE=gateway` explicitly on the function.
6. Constructing the adapter emits `insecure_identity_adapter_enabled`, alarmed at
   threshold 1.

```python
# application/app/security/identity.py (remediated)
jwt_context = authorizer.get("jwt")
if not isinstance(jwt_context, dict):
    return None  # a REQUEST authorizer's context is not accepted
claims = jwt_context.get("claims")
```

### Verification test

- `tests/security/test_authentication.py` — identity asserted via headers is rejected;
  an `aws.event` without an authorizer yields 401; an `authorizer.lambda` context is not
  accepted.
- `tests/unit/test_config.py` — the fail-closed config guard, and `gateway` as default.
- `tests/integration/test_aws_gateway_contract.py` — live gateway rejection, **skipped**
  (requires a deployment).

### Final status

**Remediated and verified locally.** Gateway-level token rejection is unverified in this
environment; the corresponding tests exist and are explicitly skipped rather than absent.
Residual risk: Low (a future refactor reintroducing a fallback — the regression tests fail
if it does).

---

<a id="f-002"></a>
## F-002 — Privilege escalation through a self-asserted role claim

| Field | Value |
|---|---|
| **Finding ID** | F-002 |
| **Affected component** | `application/app/security/identity.py` |
| **Severity** | High |
| **Relevant CWE** | CWE-269 (Improper Privilege Management); CWE-807 |
| **OWASP** | API5:2023 Broken Function Level Authorization; A01:2021 Broken Access Control |
| **Security requirement** | SR-Z1, SR-Z2, SR-Z3 |
| **Threat** | T-14 |
| **Status** | **Remediated** · retested · regression test present |

### Description

The caller's role was taken from the `custom:role` token claim, with a silent fallback to
`member` when the value was unrecognised. No server-side record was consulted, so the
token was the sole authority on privilege.

Two distinct problems:

1. **If the Cognito app client can write `custom:role`**, a user calls
   `UpdateUserAttributes`, sets `admin`, re-authenticates and is an administrator.
2. **Even if it cannot**, a token is a *cached snapshot*. A user demoted or removed from
   an organization five minutes ago still presents a token asserting the old role, and the
   application honours a revoked privilege until expiry.

The same applied to `custom:organization_id`: tenancy itself came from the token.

### Root cause

Conflating authentication with authorization. A verified token establishes "Cognito
believes this is user `sub`". It does not establish what that user is *entitled to now* —
that is server state, and server state must be read from the server.

### Potential impact

Organization-wide read and modify rights for any member, including closing tickets, which
ends the support obligation and can suppress the record of what was done. With a writable
claim it is a one-request escalation; without one it is a window-of-staleness escalation.

### Evidence

```python
# application/app/security/identity.py:68-77  (v1-pre-review)
    role_value = claims.get(_CLAIM_ROLE, OrganizationRole.MEMBER.value)
    try:
        role = OrganizationRole(role_value)
    except ValueError:
        role = OrganizationRole.MEMBER
    ...
    return Principal(user_id=user_id, organization_id=org_id, role=role)
```

No `MembershipStore` existed in pass 1; `membership_repository.py` was added as part of
the remediation.

### Recommended remediation

Resolve role and membership from an authoritative server-side record. Treat the token
claim as advisory. Require the membership to be active. Remove the app client's ability to
write the claims.

### Implemented remediation

1. `resolve_principal(identity, memberships)` looks up
   `USER#{user_id}` / `MEMBERSHIP#{organization_id}` and constructs the `Principal` with
   `role=membership.role`. The token's claim is retained only as
   `VerifiedIdentity.claimed_role` and is **never** used for a decision.
2. Missing membership → 403. `status != "active"` → 403. Both emit
   `authorization_denied` with a machine-readable reason (`no_membership`,
   `membership_inactive`).
3. A claim/record disagreement logs `role_claim_mismatch` (alarmed); the record wins.
4. `cognito.tf` denies the app client write access to `custom:organization_id` and
   `custom:role` — the control that closes vector (1) at the identity provider.
5. There is no API endpoint that creates or modifies a membership.

### Verification test

- `tests/security/test_authorization_policy.py` — an `admin` claim on the token does not
  grant admin behaviour when the record says `member`.
- `tests/security/test_authentication.py` — missing and inactive memberships both 403.
- `tests/unit/test_authorization.py` — full role × operation matrix.
- `tests/unit/test_logging_and_context.py` — the mismatch event is emitted.

### Final status

**Remediated and verified.** Residual risk: Low. Cost note: one `GetItem` per request;
caching was deliberately rejected (observation O-2).

---

<a id="f-003"></a>
## F-003 — Authorization check defined but never enforced on the update path

| Field | Value |
|---|---|
| **Finding ID** | F-003 |
| **Affected component** | `application/app/services/ticket_service.py`; `application/app/security/authorization.py` |
| **Severity** | High |
| **Relevant CWE** | CWE-862 (Missing Authorization); CWE-639 (Authorization Bypass Through User-Controlled Key) |
| **OWASP** | API1:2023 Broken Object Level Authorization; A01:2021 |
| **Security requirement** | SR-Z4, SR-Z5 |
| **Threat** | T-15 |
| **Status** | **Remediated** · retested · regression test present |

### Description

`can_update_ticket(principal, ticket)` was defined in the policy module and **never
called**. `TicketService.update_ticket` loaded the ticket, merged the payload and saved it
with no authorization decision at all.

Any authenticated member could `PATCH` **any ticket in their organization** — a textbook
IDOR. The weakness was invisible on a quick read precisely *because* the helper existed:
the policy module looked complete, and the omission was at the call site.

Relatedly, `list_tickets` passed no scope, so a member's listing returned the whole
organization's tickets.

### Root cause

A boolean policy helper creates no obligation at the call site. Nothing in the type
system, and nothing in review, distinguishes "the check passed" from "the check was never
made". An unused `bool` is unremarkable.

### Potential impact

Horizontal privilege escalation within a tenant: read and modify every colleague's
tickets, including altering content and status. Combined with F-013 (no privileged-status
control) a member could also close records to hide activity.

### Evidence

```python
# application/app/security/authorization.py:16-20  (v1) — defined...
def can_update_ticket(principal: Principal, ticket: Ticket) -> bool:
    """Return True when the principal may modify the ticket."""
    if principal.is_admin:
        return True
    return ticket.created_by == principal.user_id
```

```python
# application/app/services/ticket_service.py:84-107  (v1) — ...and never called
    def update_ticket(self, principal, ticket_id, payload) -> Ticket:
        """Apply a partial update to a ticket."""
        ticket = self._store.get_ticket(principal.organization_id, ticket_id)
        if ticket is None:
            raise ResourceNotFoundError(f"Ticket {ticket_id} not found")

        changes = payload.model_dump(exclude_unset=True)   # no authz decision
        current = ticket.model_dump(mode="json")
        current.update(changes)
        ...
```

```bash
$ grep -rn "can_update_ticket" application/   # against v1-pre-review
application/app/security/authorization.py:16:def can_update_ticket(...
# one definition, zero call sites
```

### Recommended remediation

Make the authorization result a value that must be consumed. Concentrate enforcement in
one layer so completeness is reviewable in one file. Make the role shape the query rather
than filtering results.

### Implemented remediation

1. Policy functions return an explicit `Decision(allowed: bool, reason: str)`, not a
   `bool`. Callers pass it to `enforce(decision)`, which raises `AuthorizationError`
   unless allowed — so an unenforced `Decision` is a visibly unused value.
2. All enforcement lives in `TicketService`. Routes carry no authorization logic.
3. The update path performs three ordered checks: `authorize_update_ticket` (may this
   principal touch the object), `authorize_status_change` (is this state change permitted
   for this role), `ensure_transition_allowed` (is the transition legal — a 409, not a
   403).
4. `list_scope(principal)` returns the `created_by` filter, which selects GSI1 — so a
   member's query is narrowed in the key condition (see F-006).
5. Every denial emits `authorization_denied` with `f"{action}:{reason}"`.

### Verification test

- `tests/security/test_authorization_policy.py` — a member updating another member's
  ticket in the same organization is denied.
- `tests/unit/test_ticket_service.py` — `enforce` is invoked on read, update and status
  change.
- `tests/unit/test_authorization.py` — exhaustive policy matrix.

### Final status

**Remediated and verified.** Residual risk: Low. Recommended further safeguard (not
implemented): a CI assertion that every principal-taking service method calls `enforce()`.

---

<a id="f-004"></a>
## F-004 — Mass assignment permits cross-tenant writes

| Field | Value |
|---|---|
| **Finding ID** | F-004 |
| **Affected component** | `application/app/models/ticket.py`; `application/app/services/ticket_service.py` |
| **Severity** | High (cross-tenant **write**; the create vector alone is arguably Critical) |
| **Relevant CWE** | CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes); CWE-639 |
| **OWASP** | API3:2023 Broken Object Property Level Authorization; A01:2021 / A04:2021 |
| **Security requirement** | SR-V1, SR-V2, SR-Z7 |
| **Threat** | T-04 |
| **Status** | **Remediated** · retested · regression test present |

### Description

Two reinforcing defects:

1. **`TicketCreateRequest` declared `organization_id: str | None = None`**, and the
   service used `payload.organization_id or principal.organization_id`. A client could
   therefore **create a ticket inside another tenant's partition** by adding one JSON
   field.
2. **`TicketUpdateRequest` set `extra="allow"`**, and the service merged
   `payload.model_dump(exclude_unset=True)` into the stored record. Any attribute the
   client sent — `organization_id`, `created_by`, `ticket_id`, `created_at` — was written
   through to storage, so an existing ticket could be **moved across the tenant
   boundary** or re-attributed to another user.

The `extra="allow"` carried a comment explaining it as deliberate flexibility, which is
exactly how this class of defect survives review.

### Root cause

Server-controlled fields were modelled as client-writable, and the service merged
validated-but-unconstrained input into the domain object. The schema, not the handler, is
the right place to make a field unwritable — and `extra="allow"` removes the schema's
ability to refuse anything.

### Potential impact

Cross-tenant **integrity** loss: data planted in another customer's account, records
re-attributed to other users, and a corrupted audit trail. Worse than a cross-tenant read,
because the victim's data is modified and the attacker's content appears authentic.

### Evidence

```python
# application/app/models/ticket.py:44-66  (v1-pre-review)
class TicketCreateRequest(BaseModel):
    """Client payload for creating a ticket."""

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    priority: TicketPriority = TicketPriority.MEDIUM
    organization_id: str | None = None  # <-- client-supplied tenancy


class TicketUpdateRequest(BaseModel):
    """Client payload for updating a ticket.

    ``extra="allow"`` keeps the endpoint flexible while the ticket schema is
    still evolving, so new fields can be stored without a deploy.
    """

    model_config = ConfigDict(extra="allow")  # <-- mass assignment
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None
```

```python
# application/app/services/ticket_service.py:34  (v1) — create
        organization_id = payload.organization_id or principal.organization_id

# application/app/services/ticket_service.py:96-99  (v1) — update
        changes = payload.model_dump(exclude_unset=True)
        current = ticket.model_dump(mode="json")
        current.update(changes)
        updated = Ticket.model_validate(current)
```

### Recommended remediation

Remove server-controlled fields from request models entirely, forbid unknown fields, and
constrain what the service may apply with an explicit allow-list.

### Implemented remediation

1. `extra="forbid"` on **every** request model. An unknown field is a 422 — not a silent
   drop. A silent drop would also be invisible, letting an attacker map the schema at
   leisure; a 422 is logged and alertable.
2. `TicketCreateRequest` contains **only** `title`, `description`, `priority`.
   `organization_id`, `created_by`, `ticket_id`, `status` and the timestamps are absent —
   there is no field to populate.
3. `TicketUpdateRequest` declares exactly four writable fields, and
   `CLIENT_UPDATABLE_FIELDS` constrains `changes()` to that set, so even adding a model
   field cannot widen what the service applies.
4. `TicketService.create_ticket` sets `organization_id=principal.organization_id`,
   `created_by=principal.user_id`, `ticket_id=str(uuid.uuid4())`, `status=OPEN`.
5. `Ticket` is `frozen=True`; updates use `model_copy(update={**changes, "updated_at": …})`.
6. `Ticket` also sets `extra="forbid"`, guarding the **read** path: a stray stored
   attribute fails deserialisation loudly instead of riding into a response.

### Verification test

- `tests/security/test_tenant_isolation.py::test_create_cannot_target_another_tenant_via_request_body`
- `tests/security/test_tenant_isolation.py::test_update_cannot_move_a_ticket_to_another_tenant`
- `tests/security/test_input_validation.py` — unknown fields rejected on create and update.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-005"></a>
## F-005 — Over-privileged Lambda execution role

| Field | Value |
|---|---|
| **Finding ID** | F-005 |
| **Affected component** | `infrastructure/terraform/iam.tf`; `infrastructure/terraform/policies/lambda-execution.json` |
| **Severity** | Medium (exploitation requires another weakness; impact if chained is Critical) |
| **Relevant CWE** | CWE-250 (Execution with Unnecessary Privileges); CWE-732 |
| **OWASP** | A01:2021 Broken Access Control; A05:2021 Security Misconfiguration |
| **Security requirement** | SR-C1 – SR-C7 |
| **Threat** | T-16 |
| **Status** | **Remediated** · verified by the project's own IAM analyzer |

### Description

The first infrastructure draft granted the Lambda execution role:

```json
{ "Effect": "Allow", "Action": "dynamodb:*", "Resource": "<table arn>" }
{ "Effect": "Allow", "Action": "logs:*",     "Resource": "*" }
```

`dynamodb:*` on the table includes `Scan` (read every tenant's data in one call),
`DeleteItem`, `DeleteTable`, `UpdateTable` and `ExportTableToPointInTime`. `logs:*` on
`Resource: "*"` includes `DeleteLogGroup` and `GetLogEvents` for **any log group in the
account** — so the role could both exfiltrate and then destroy the evidence.

Once a role is this broad, every application-layer control becomes irrelevant to an
attacker who achieves code execution: they stop going through the application.

### Root cause

Permissions granted by service rather than by action, and resources left unscoped, because
`"dynamodb:*"` is the fastest way to stop getting `AccessDenied` during development.

### Potential impact

Chained with any code-execution or SSRF-class weakness: multi-tenant data breach,
destruction of the table, and destruction of the logs that would evidence it. The worst
case in this system.

### Evidence — and an honesty note

**This finding's pre-remediation state is not preserved in git history.** The
infrastructure was authored after the application review and was committed already
remediated (`8cb87f5`), so there is no `v1` IAM policy to diff. The before-state is
recorded as a design-decision record in the header comment of `iam.tf`, which names the
exact two statements above.

What *is* independently demonstrable is that the project's own analyzer detects this
pattern. The synthetic fixture `sample-data/insecure-policy.json` (clearly labelled, never
deployed) contains `Action: "*"`, `dynamodb:*`, and `logs:*` on `Resource: "*"`, and the
CI pipeline includes a **gate self-test** asserting that the fixture is rejected:

```
[STAGE] 3d. IAM analyzer gate self-test (insecure fixture must fail)
Confirmed: the insecure fixture is correctly rejected.
  PASS 3d. IAM analyzer gate self-test (insecure fixture must fail)
```

Because the before-state is a written record rather than a diff, this finding is weaker
evidentially than F-001–F-004 and F-006–F-015. It is reported as Medium and this caveat is
stated rather than glossed.

### Recommended remediation

Enumerate actions. Scope resources to ARNs. Omit anything the application does not do.
Deny the large-blast-radius actions explicitly. Cap the role with a permissions boundary.

### Implemented remediation

`policies/lambda-execution.json` (deployed via `aws_iam_role_policy.lambda_execution`):

1. **Enumerated actions only:** `dynamodb:GetItem`, `PutItem`, `Query`. No `Scan`, no
   `UpdateItem`, no `DeleteItem`, no `BatchWriteItem`.
2. **ARN-scoped resources:** the table ARN and `…/index/GSI1`.
3. **Own log group only:** `logs:CreateLogStream` + `PutLogEvents` on
   `${log_group_arn}:*`. No `CreateLogGroup` (Terraform creates it), no `logs:*`, no `*`.
4. **KMS constrained** by a `kms:ViaService` condition limiting use to the Lambda and
   DynamoDB service endpoints.
5. **Explicit `Deny`** on `dynamodb:Scan`, `DeleteItem`, `BatchWriteItem`, `DeleteTable`,
   `UpdateTable`, `CreateTable`, `ExportTableToPointInTime`, `RestoreTableFromBackup` — an
   explicit Deny cannot be overridden by any later Allow, so these stay shut even if
   someone attaches a broad policy to this role.
6. **Explicit `Deny`** on credential and policy self-modification: `iam:PutRolePolicy`,
   `iam:AttachRolePolicy`, `iam:PassRole`, `iam:CreateRole`,
   `iam:DeleteRolePermissionsBoundary`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`,
   `kms:DisableKey`, `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `logs:DeleteLogGroup`,
   `logs:DeleteLogStream`, `logs:PutRetentionPolicy`.
7. **Permissions boundary** (`aws_iam_policy.lambda_boundary`) caps the role.
8. **Confused-deputy guard** on the trust policy restricting `lambda.amazonaws.com`.
9. **Policies committed as JSON templates**, not rendered only at plan time, so CI runs
   the analyzer against the document that actually deploys — no hand-maintained copy to
   drift.

### Verification test

`security-automation/iam_policy_checker.py` against
`infrastructure/terraform/policies/`, in CI stage 3c and in
`scripts/run_security_checks.sh`. Verified run, 2026-10-23:

```
total_findings: 1   blocking_findings: 0
by_severity: critical 0, high 0, medium 0, low 0, info 1
by_confidence: confirmed 0, needs_context 1
IAM003 info needs_context  Unscoped resource on actions that do not support scoping
                           → infrastructure/terraform/policies/lambda-xray.json
```

The single remaining finding is `needs_context`, not `confirmed`: X-Ray's
`PutTraceSegments`/`PutTelemetryRecords` genuinely do not support resource-level scoping,
so `Resource: "*"` is the only legal form. X-Ray is also disabled by default
(`enable_xray = false`).

### Final status

**Remediated.** Policy-document analysis passes with zero blocking findings. **Live IAM
enforcement is unverified** — no AWS account was used, so the AWS-gated tests in
`tests/integration/test_aws_gateway_contract.py` that assert `Scan` is actually denied
remain skipped. Residual risk: Low, with one known architectural gap (the `PutItem` grant
is table-scoped, not sort-key-prefix-scoped — see R-06/T-06, the top-priority next step).

---

<a id="f-006"></a>
## F-006 — Tenant isolation dependent on a filter expression over a full table scan

| Field | Value |
|---|---|
| **Finding ID** | F-006 |
| **Affected component** | `application/app/repositories/ticket_repository.py` |
| **Severity** | High |
| **Relevant CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-1230 (Exposure of Sensitive Information Through Metadata) |
| **OWASP** | API1:2023; A01:2021 |
| **Security requirement** | SR-Z8, SR-Z9 |
| **Threat** | T-09 |
| **Status** | **Remediated** · retested · regression test present |

### Description

`list_tickets` used `Scan` with `FilterExpression=Attr("organization_id").eq(...)`. The
query produced correct answers, but tenant isolation rested on a filter expression rather
than on the access pattern:

- **Every request read every tenant's items** into the function before the filter removed
  them. A serialisation change, a logging statement, or an off-by-one in pagination
  exposes them.
- **A refactor can drop a filter.** Nothing fails loudly if it does — the endpoint keeps
  working and quietly returns other tenants' data.
- **`Scan` paginates before filtering**, so `LastEvaluatedKey` reflects scan position
  across the whole table, making cross-tenant leakage through pagination plausible.
- Cost and latency scaled with *all* tenants' data.

Because members were not scoped either (F-003), the member path also returned the whole
organization.

### Root cause

`Scan` + filter is the shortest path to a working list endpoint, and it looks correct in
testing with one tenant's data. It converts isolation from a structural property into a
remembered step.

### Potential impact

Multi-tenant data breach from a one-line regression, plus read-capacity cost proportional
to total table size on every list request.

### Evidence

```python
# application/app/repositories/ticket_repository.py:52-76  (v1-pre-review)
        kwargs: dict[str, Any] = {
            "Limit": limit,
            "FilterExpression": Attr("organization_id").eq(organization_id),
        }
        if created_by:
            kwargs["FilterExpression"] = kwargs["FilterExpression"] & Attr("created_by").eq(
                created_by
            )
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor

        response = self._table.scan(**kwargs)
```

### Recommended remediation

Make the partition key carry the tenant, derive it from the verified principal, and
replace `Scan` with key-scoped `Query`. Add an index so the per-member access pattern is
also key-scoped. Deny `Scan` at the IAM layer so the application *cannot* regress to it.

### Implemented remediation

1. **No `Scan` anywhere in a user-facing read path.** Admin listing:
   `PK = TENANT#{org} AND SK begins_with TICKET#`. Member listing: GSI1 with
   `GSI1PK = TENANT#{org}#USER#{user}`. Single read: exact `(PK, SK)` `GetItem`.
2. **GSI1's partition key embeds both tenant and user.** Keying it on the user alone would
   let a user's tickets from one organization surface in a query scoped to another,
   reintroducing the cross-tenant path through the index.
3. The member path uses an **index, not a post-query filter**, so a colleague's tickets are
   never read from the database — not read, not billed, not held in memory.
4. `organization_id` always comes from `principal.organization_id`.
5. **IAM explicitly denies `dynamodb:Scan`**, so even a future code change cannot scan.
6. Internal key attributes are stripped by `_from_item` before any response.

### Verification test

- `tests/security/test_data_access_scoping.py` — a recording-table fixture asserts that
  every database call is a key-scoped `query`/`get_item`, that **`scan` is never called**,
  and that key conditions always pin the caller's partition.
- `tests/security/test_tenant_isolation.py` — tenant B's tickets never appear for tenant A.
- `tests/integration/test_dynamodb_repository.py` — against `moto`, including the GSI1 path.

### Final status

**Remediated and verified.** Residual risk: Low. Recommended further safeguard: a CI lint
rule failing on the literal `.scan(` in `application/`.

---

<a id="f-007"></a>
## F-007 — Customer content and bearer tokens written to logs

| Field | Value |
|---|---|
| **Finding ID** | F-007 |
| **Affected component** | `application/app/routes/tickets.py`; `application/app/services/ticket_service.py`; `application/app/security/identity.py`; `application/app/observability/logging.py` |
| **Severity** | Medium (High if the log group is broadly readable) |
| **Relevant CWE** | CWE-532 (Insertion of Sensitive Information into Log File); CWE-117 (Improper Output Neutralization for Logs) |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures; API8:2023 |
| **Security requirement** | SR-L2, SR-L3, SR-L4, SR-L5, SR-L7, SR-L8 |
| **Threat** | T-07, T-11 |
| **Status** | **Remediated** · retested · regression test present |

### Description

The JSON formatter rendered **any** field passed in `extra=`, and three call sites passed
sensitive data:

1. `routes/tickets.py` logged the entire create payload — ticket title and description,
   i.e. customer content.
2. `services/ticket_service.py` logged the update `changes` dict — the new values.
3. `security/identity.py` logged the **`Authorization` header** in a `debug` branch, and
   `debug` defaulted to `True` (F-012).

Additionally, `X-Request-Id` was accepted from the client unsanitised, so a newline in the
header could inject a forged log record (CWE-117), and `botocore` ran at the default level,
duplicating URLs and headers into the stream.

CloudWatch Logs is a second data store with its own access controls, its own retention and
a much wider readership than the request that produced the entry. Anything written there
has a far larger blast radius than it appears to.

### Root cause

A permissive formatter (render whatever you are given) combined with the normal engineering
instinct to log the thing you are debugging. A deny-list would not have helped: it fails
the moment someone adds a field.

### Potential impact

Customer ticket content — and potentially live bearer tokens — replicated into a store with
broader access and longer retention than the database itself. A log reader with no
application entitlement reads customer data; an exported or forwarded log widens it again.
A logged token is directly replayable (T-02). Forged log records mislead incident response.

### Evidence

```python
# application/app/routes/tickets.py:36  (v1-pre-review)
    logger.info("create ticket request", extra={"payload": payload.model_dump()})

# application/app/services/ticket_service.py:104  (v1)
        logger.info("ticket updated", extra={"event_type": "ticket_updated", "changes": changes})

# application/app/security/identity.py:79-90  (v1)
    if settings.debug:
        # Helpful while wiring up Cognito: shows exactly what the gateway sent.
        import logging
        logging.getLogger("app.identity").debug(
            "resolved principal user=%s org=%s role=%s auth_header=%s",
            user_id, org_id, role,
            request.headers.get("Authorization"),      # <-- bearer token
        )
```

### Recommended remediation

Invert the control: an **allow-list** of renderable fields, so a field is invisible unless
explicitly reviewed. Log identifiers and outcomes, never content. Sanitise any
client-supplied value that reaches a log. Remove the token-logging branch.

### Implemented remediation

1. **`ALLOWED_LOG_FIELDS`** enumerates every renderable key. Anything else is dropped by
   the formatter — including a whole ticket object passed by mistake. The failure mode of
   forgetting is a missing dashboard field, not customer data in a log.
2. The allow-list contains **identifiers and outcomes only**: `event_type`, `outcome`,
   `reason`, `error_code`, `principal_id`, `organization_id`, `resource_type`,
   `resource_id`, `changed_fields`, `role`, HTTP shape, `duration_ms`, `result_count`,
   `exception`. There is **no** `payload`, `changes`, `title`, `description`, `token` or
   `authorization` key, so passing one has no effect.
3. Updates log `payload.changed_fields()` — **field names only**, never values.
4. The `Authorization`-logging branch is deleted; `debug` now defaults to `False`.
5. `sanitize_request_id` accepts a client `X-Request-Id` only against a strict pattern
   within 64 characters, generating one otherwise.
6. `json.dumps` escapes newlines, so a multi-line traceback cannot terminate a record and
   forge the next one. Messages are newline-stripped and truncated at 256 characters.
7. `botocore`/`boto3`/`urllib3`/`s3transfer` pinned to WARNING.
8. Handler installation is idempotent and marker-based, so it never removes the Lambda
   runtime's handler (which carries request-id correlation) or a test harness's handler.
9. Log groups are CMK-encrypted with an explicit retention period.

### Verification test

- `tests/security/test_logging_and_data_protection.py::test_ticket_content_is_never_logged`
- `::test_update_changes_are_logged_as_field_names_only`
- `::test_log_payloads_only_contain_allow_listed_fields`
- `::test_successful_access_is_auditable_without_content`
- `tests/unit/test_logging_and_context.py` — request-id sanitising, newline handling,
  truncation.

### Final status

**Remediated and verified.** Residual risk: Low. Recommended further safeguard: a
CloudWatch Logs data-protection policy as an independent second layer.

---

<a id="f-008"></a>
## F-008 — Information disclosure through error responses

| Field | Value |
|---|---|
| **Finding ID** | F-008 |
| **Affected component** | `application/app/main.py`; `application/app/services/ticket_service.py` |
| **Severity** | Medium |
| **Relevant CWE** | CWE-209 (Generation of Error Message Containing Sensitive Information); CWE-204 (Observable Response Discrepancy); CWE-497 |
| **OWASP** | A05:2021 Security Misconfiguration; API3:2023 |
| **Security requirement** | SR-E1 – SR-E4, SR-V11, SR-Z10, SR-Z12 |
| **Threat** | T-10 |
| **Status** | **Remediated** · retested · regression test present |

### Description

Four distinct disclosures:

1. **Stack traces to the client.** The unhandled-exception handler returned `str(exc)` and
   `traceback.format_exc()` in the 500 body, with a docstring describing it as helping
   clients "report actionable bugs". That body reveals file paths, library versions, and
   frequently data values from the failing call.
2. **Denial messages naming other users' data.** `AuthorizationError` was raised with
   `f"User {principal.user_id} may not read ticket {ticket_id} owned by {ticket.created_by}
   in organization {ticket.organization_id}"` — disclosing the owner and the owning
   organization of a record the caller was just told they may not read.
3. **An existence oracle.** A ticket in another tenant produced a different status/message
   than a non-existent one, so ticket ids could be enumerated across tenants without
   reading any content.
4. **Validation errors echoing submitted values.** FastAPI's default 422 body includes
   `input` — the offending value. Validation errors are routinely captured by gateways,
   proxies and client-side error reporters, so this widens where customer content ends up.

Framework 404/405 responses also returned `{"detail": …}`, giving two different error
shapes and leaking routing hints.

### Root cause

Optimising error responses for the developer rather than for the threat model, and
allowing the *shape* of a denial to carry information the body was careful not to state.

### Potential impact

Reconnaissance that makes every other attack cheaper: valid ticket ids, which
organizations exist, which users own what, the framework and library versions in use. Plus
inadvertent customer-content disclosure through error-reporting pipelines.

### Evidence

```python
# application/app/main.py:60-71  (v1-pre-review)
    @application.exception_handler(Exception)
    async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
        """Return the failure detail so clients can report actionable bugs."""
        logger.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": str(exc),
                "trace": traceback.format_exc(),     # <-- to the client
            },
        )
```

```python
# application/app/services/ticket_service.py:63-67  (v1)
        if not can_read_ticket(principal, ticket):
            raise AuthorizationError(
                f"User {principal.user_id} may not read ticket {ticket_id} "
                f"owned by {ticket.created_by} in organization {ticket.organization_id}"
            )
```

### Recommended remediation

One error envelope for everything. No exception text, no traces, no submitted values. Make
"not found" and "not yours" indistinguishable. Keep the diagnostic detail in the logs,
correlated by request id.

### Implemented remediation

1. **One envelope:** `{"error": <code>, "message": <safe sentence>, "request_id": <id>}`,
   plus `fields` for 422. Nothing else — no trace, no exception text, no module path, no
   library name.
2. **404 for both cases, structurally.** Reads are partition-scoped, so another tenant's
   ticket and a non-existent ticket both produce `None` from the repository and therefore
   the same 404. The indistinguishability is a property of the data access, not of a
   hand-written branch that could be forgotten.
3. **`enforce()` uses one identical generic message** for every denial
   (`"You do not have access to this resource."`); the specific
   `Decision.reason` goes only to the log.
4. **`_sanitize_validation_errors`** reduces each Pydantic error to `{field, reason, type}`
   and **drops `input`**. The caller still learns which field was wrong and why.
5. **Framework 404/405/415 normalised** into the same envelope.
6. The unhandled handler logs the full trace via `logger.exception` and returns a fixed
   sentence. It also **re-applies security headers**, because it runs outside the user
   middleware stack (Starlette's `ServerErrorMiddleware` is outermost) and a 500 would
   otherwise ship without them.
7. Only the exception **type name** is put into a structured log field (so 500s are
   groupable in CloudWatch) — never the message, which may carry data.

### Verification test

- `tests/security/test_error_handling.py` — no error body contains `trace`, `Traceback`,
  a file path or an exception message; envelope is uniform across 400/401/403/404/405/409/422/500.
- `tests/security/test_tenant_isolation.py::test_cross_tenant_denial_does_not_disclose_existence`
- `tests/security/test_api_behaviour.py` — normalised framework errors, no server banner.

### Final status

**Remediated and verified.** Residual risk: Low. Recommended further safeguard:
per-principal rate limiting on 404s to blunt enumeration.

---

<a id="f-009"></a>
## F-009 — Unbounded pagination and request field sizes

| Field | Value |
|---|---|
| **Finding ID** | F-009 |
| **Affected component** | `application/app/routes/tickets.py`; `application/app/repositories/ticket_repository.py`; `application/app/models/ticket.py` |
| **Severity** | Medium |
| **Relevant CWE** | CWE-770 (Allocation of Resources Without Limits or Throttling); CWE-1284 (Improper Validation of Specified Quantity in Input) |
| **OWASP** | API4:2023 Unrestricted Resource Consumption; A04:2021 Insecure Design |
| **Security requirement** | SR-V5, SR-V6 |
| **Threat** | T-12 |
| **Status** | **Remediated** · retested · regression test present |

### Description

`limit` was declared as `limit: int = Query(default=None, description=…)` with **no `ge`,
no `le` and no clamp** anywhere downstream. The value was passed straight through to the
DynamoDB `Limit` parameter. `GET /v1/tickets?limit=1000000` therefore turned one cheap
request into a full-partition read — read capacity, Lambda duration, response size and
cost all chosen by the caller. Negative and zero values were also accepted and passed to
the database.

Separately, `description` was declared `Field(min_length=1)` with **no maximum**, so a
single request could store a multi-megabyte item, inflating the tenant's partition and
every subsequent read of it.

(The declaration was also incorrect as typed: `int` with `default=None`.)

### Root cause

Pagination was treated as a usability parameter rather than as a resource-consumption
control, and the only bound in the system was DynamoDB's own 1 MB page limit — which is a
cost ceiling, not a security control.

### Potential impact

Cost and latency amplification against the whole tenant from a single authenticated
account; a handful of accounts can degrade the shared function for every tenant. Oversized
items additionally raise the cost of every unrelated read in that partition.

### Evidence

```python
# application/app/routes/tickets.py:41-52  (v1-pre-review)
def list_tickets(
    limit: int = Query(default=None, description="Maximum number of tickets to return"),
    ...
    page_size = limit if limit is not None else settings.default_page_size
    tickets, cursor = service.list_tickets(principal, limit=page_size, cursor=...)

# application/app/repositories/ticket_repository.py:63  (v1) — no clamp
        kwargs: dict[str, Any] = {"Limit": limit, ...}

# application/app/models/ticket.py:48  (v1) — no maximum
    description: str = Field(min_length=1)
```

### Recommended remediation

Bound the page size at the HTTP edge so an out-of-range value never reaches a handler, and
clamp again in the repository because a repository must not trust its caller. Give every
string field an explicit maximum chosen against the storage limit.

### Implemented remediation

1. `limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE)` — `MAX_PAGE_SIZE` is
   100, so zero, negative and oversized values are a 422 before any handler runs.
2. `DynamoDbTicketRepository.list_tickets` independently applies
   `page_size = max(1, min(int(limit), MAX_PAGE_SIZE))` — defence in depth.
3. `MAX_TITLE_LENGTH = 200`, `MAX_DESCRIPTION_LENGTH = 10_000`, applied through
   `StringConstraints` with `strip_whitespace=True, min_length=1`. Bounds chosen against
   DynamoDB's 400 KB item limit with headroom, so one request can neither bloat an item
   nor be used to fill a tenant's partition.
4. Cursor length capped at `MAX_CURSOR_LENGTH = 1024`.
5. Infrastructure layer: API Gateway stage throttling (rate + burst) and Lambda reserved
   concurrency bound the blast radius on spend.

### Verification test

- `tests/security/test_input_validation.py::test_pagination_limit_is_bounded[zero|negative|above-maximum|far-above-maximum|integer-overflow-attempt]`
- oversized-title and oversized-description cases in the same module
- `tests/unit/test_ticket_service.py` — the repository clamp applies even when the service
  is called directly with an out-of-range limit.

### Final status

**Remediated and verified.** Residual risk: Low for amplification. Edge-level request
flooding remains a separate, accepted risk (T-13 / AR-05) because the function is shared
across tenants and there is no per-tenant quota.

---

<a id="f-010"></a>
## F-010 — Pagination cursor forwarded to the database unvalidated

| Field | Value |
|---|---|
| **Finding ID** | F-010 |
| **Affected component** | `application/app/repositories/pagination.py`; `application/app/repositories/ticket_repository.py` |
| **Severity** | Medium (High in combination with a key-scoped query, which is what makes the cursor the remaining lever) |
| **Relevant CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key); CWE-20 |
| **OWASP** | API1:2023; A01:2021 |
| **Security requirement** | SR-Z11 |
| **Threat** | T-05 |
| **Status** | **Remediated** · retested · regression test present |

### Description

The cursor was base64-decoded and passed directly to DynamoDB's `ExclusiveStartKey`. A
cursor is opaque only to a well-behaved client; `LastEvaluatedKey` is a plain dict of key
attributes, so an attacker can decode it, rewrite `"PK": "TENANT#victim-org"`, re-encode
and re-send.

Once the read path became a key-scoped `Query` (F-006), the cursor was the **one remaining
place where client input reached the key**, which is what elevates this from hygiene to a
tenant-isolation bypass.

There was also no bound on cursor length and no constraint on which attributes it could
contain, so the decoder could be probed with arbitrary structures.

### Root cause

"Opaque" was treated as a security property. It is an API-design convention; the value is
still attacker-controlled input and must be validated like any other.

### Potential impact

Cross-tenant read: resume a listing inside the victim's partition and page through their
tickets, bypassing the partition-key control the isolation design rests on.

### Evidence

```python
# application/app/repositories/pagination.py:26  (v1-pre-review)
def decode_cursor(cursor: str | None) -> dict[str, Any] | None:
    """Decode an opaque cursor back into a DynamoDB ``ExclusiveStartKey``."""
    # decoded and returned; no tenant check, no size bound, no attribute allow-list

# application/app/repositories/ticket_repository.py:70-71  (v1)
        if cursor:
            kwargs["ExclusiveStartKey"] = cursor      # <-- straight through
```

### Recommended remediation

Validate the decoded key against the **caller's own partition** before use, at both the
service and repository layers. Bound its size and constrain its attributes. Use one
identical error message for every rejection so the decoder cannot be probed.

### Implemented remediation

1. `decode_cursor(cursor, *, organization_id)` takes the organization **from the verified
   principal** and requires `key["PK"] == tenant_pk(organization_id)`. A mismatch raises
   `ValidationFailedError` and **the store is never called**.
2. Additional validation: length ≤ 1 KB; must decode as a JSON object; attributes
   restricted to `{PK, SK, GSI1PK, GSI1SK}`; all values must be strings; `PK` and `SK` must
   both be present.
3. Every rejection uses the identical message `"Invalid pagination cursor."`; the specific
   reason (`cursor_tenant_mismatch`, `cursor_too_long`, `cursor_not_decodable`,
   `cursor_unexpected_attributes`, …) goes only to the log.
4. `validate_cursor_key` is re-applied **inside the repository**, because the repository is
   a reusable component and must not assume its caller validated anything.
5. `encode_cursor` projects the outgoing key to the allow-listed attributes only.
6. **A signed cursor was considered and rejected**: a signature proves *we issued it*, not
   that we issued it *to this tenant*. Checking the partition directly is both simpler and
   a stronger statement, and needs no key management or rotation.

### Verification test

- `tests/security/test_tenant_isolation.py::test_pagination_cursor_from_another_tenant_is_rejected`
- `::test_malformed_pagination_cursor_is_rejected[missing-sk|empty-object|…]`
- `tests/unit/test_models_and_keys.py` — encode/decode round-trip and attribute projection.
- `tests/integration/test_tickets_api.py` — a legitimate multi-page walk still works.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-011"></a>
## F-011 — Unvalidated identifiers permit storage-key injection

| Field | Value |
|---|---|
| **Finding ID** | F-011 |
| **Affected component** | `application/app/routes/tickets.py`; `application/app/repositories/keys.py` |
| **Severity** | Medium |
| **Relevant CWE** | CWE-20 (Improper Input Validation); CWE-74 (Injection); CWE-706 (Use of Incorrectly-Resolved Name or Reference) |
| **OWASP** | API3:2023; A03:2021 Injection |
| **Security requirement** | SR-V3, SR-V4 |
| **Threat** | T-05 |
| **Status** | **Remediated** · retested · regression test present |

### Description

`ticket_id` was typed `str` in both the `GET` and `PATCH` route signatures and used
directly to build the DynamoDB sort key as `f"TICKET#{ticket_id}"`. `#` is the key
separator in this single-table design, so an identifier containing `#` composes a key the
application never intended to construct — for example
`ticket_id = "x#MEMBERSHIP#victim-org"` produces the sort key
`TICKET#x#MEMBERSHIP#victim-org`.

In this specific schema that does not reach a membership record (memberships live under a
`USER#` partition key), so the finding is Medium rather than High. But the property that
makes it safe is an accident of the current key layout, not a control — a future entity
sharing the tenant partition would make it exploitable. Empty and whitespace-only
identifiers were also accepted and produced malformed keys.

### Root cause

Identifiers were treated as opaque strings rather than as values with a format, and key
construction used string interpolation with no invariant asserted at the point of
composition.

### Potential impact

Access to keys outside the intended address space for a given entity type, with the ceiling
set by whatever else shares the partition. Malformed keys additionally produce confusing
`ValidationException`s rather than clean 4xx responses.

### Evidence

```python
# application/app/routes/tickets.py:58-70  (v1-pre-review)
@router.get("/{ticket_id}", response_model=Ticket, summary="Get a ticket by id")
def get_ticket(
    ticket_id: str,                # <-- no format validation
    ...

@router.patch("/{ticket_id}", response_model=Ticket, summary="Update a ticket")
def update_ticket(
    ticket_id: str,                # <-- same
```

```python
# application/app/repositories/keys.py  (v1) — interpolation with no invariant
def ticket_sk(ticket_id: str) -> str:
    return f"{TICKET_PREFIX}{ticket_id}"
```

### Recommended remediation

Validate the identifier's format at the HTTP edge so a malformed value never reaches a
handler, and assert the invariant again at the point of key construction.

### Implemented remediation

1. `ticket_id: UUID` in both route signatures. FastAPI rejects a malformed identifier with
   a 422 **before any handler runs**, so it can never reach key construction. Ids are
   server-generated `uuid4` values, so requiring a UUID costs nothing.
2. `keys._assert_no_separator(value, field)` raises `ValidationFailedError` for an empty,
   whitespace-only, or `#`-containing value, and is applied in **every** key builder:
   `tenant_pk`, `ticket_sk`, `user_pk`, `membership_sk`, `member_index_pk`. This module is
   the last line of defence before a key exists, so the invariant is asserted here even
   though the edge already checked it.
3. The rejection message is generic (`"Invalid identifier."`); the specific reason
   (`ticket_id_contains_separator`, `organization_id_empty`, …) goes only to the log.

### Verification test

- `tests/security/test_input_validation.py::test_ticket_identifier_must_be_a_uuid[not-a-uuid|embedded-key-prefix|embedded-separator|empty|whitespace|oversized|invalid-hex|encoded-null-byte|encoded-newline]`
- `tests/unit/test_models_and_keys.py` — every key builder rejects separator-bearing and
  empty identifiers.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-012"></a>
## F-012 — Insecure-by-default configuration

| Field | Value |
|---|---|
| **Finding ID** | F-012 |
| **Affected component** | `application/app/config.py`; `application/app/main.py` |
| **Severity** | Medium (the `identity_source` default is the Critical component and is counted under F-001) |
| **Relevant CWE** | CWE-1188 (Initialization of a Resource with an Insecure Default); CWE-16; CWE-605 (Multiple Bindings to the Same Port); CWE-942 (Permissive Cross-domain Policy) |
| **OWASP** | A05:2021 Security Misconfiguration |
| **Security requirement** | SR-A6, SR-A7, SR-E5, SR-H4, SR-H8 |
| **Threat** | T-01 |
| **Status** | **Remediated** · retested · regression test present |

### Description

Every security-relevant default was the **unsafe** value, so a missing environment variable
degraded *away* from security:

| Setting | Pass-1 default | Consequence |
|---|---|---|
| `identity_source` | `"header"` | The authentication bypass of F-001 was the **default** behaviour |
| `debug` | `True` | Enabled the branch that logged the `Authorization` header (F-007) |
| `cors_allow_origins` | `"*"` | Combined with `allow_credentials=True`, permits credentialed cross-origin reads from any site |
| `log_level` | `"DEBUG"` | Verbose logging in every environment |
| `environment` | `"local"` | Interactive docs and local affordances on by default |

There was also **no validation at load**: an invalid or dangerous combination started
successfully rather than failing closed. And `uvicorn.run(app, host="0.0.0.0")` bound the
development server to every interface (Bandit B104 / CWE-605) — notably with a `# noqa:
S104` comment suppressing the linter that flagged it.

### Root cause

Defaults were chosen for developer convenience rather than for the deployed case, and the
application had no notion of a configuration being *invalid* — only of values being
absent.

### Potential impact

A deployment that forgets one environment variable runs with authentication disabled,
tokens in logs, and wildcard credentialed CORS. The failure is silent: the service starts
and serves traffic normally.

### Evidence

```python
# application/app/config.py:17-39  (v1-pre-review)
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    environment: str = "local"
    debug: bool = True
    # "header"  -> read identity from request headers (used for local dev)
    identity_source: str = "header"
    cors_allow_origins: str = "*"
    log_level: str = "DEBUG"
```

```python
# application/app/main.py:85  (v1)
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104
```

### Recommended remediation

Make every default the safe value, validate the configuration at load, and fail to start
rather than start insecurely.

### Implemented remediation

1. **Safe defaults throughout:** `identity_source="gateway"`, `debug=False`,
   `cors_allow_origins=""` (no cross-origin access), `environment="dev"` (docs disabled),
   `log_level="INFO"`.
2. **Typed values:** `IdentitySource` and `Environment` are `Literal` types, so an
   unrecognised value is a load-time error rather than a silent fallback.
3. **Fail-closed guard:** `Settings._enforce_identity_source_guard` rejects
   `identity_source="local_test"` unless `environment=="local"`. The Lambda then **fails to
   initialise** rather than starting in an insecure state.
4. **Second, independent guard:** `LocalTestIdentityProvider.__init__` raises on the same
   condition, so removing the config guard is not sufficient to re-enable the bypass.
5. **CORS:** empty by default; when configured, explicit methods and headers are listed —
   never `*` with credentials.
6. `docs_url` / `redoc_url` / `openapi_url` are `None` unless `docs_enabled`.
7. `redirect_slashes=False`, so no implicit 307 changes the effective route.
8. Development server binds `127.0.0.1` by default (overridable by an explicit
   `APP_BIND_HOST`), and `server_header=False` so the server does not fingerprint itself.
   The `# noqa: S104` suppression is gone — the finding was fixed rather than silenced.
9. Terraform sets the security-relevant variables **explicitly** on the function, so their
   values never depend on a default.

### Verification test

- `tests/unit/test_config.py` — every default asserted; the fail-closed guard raises for
  `local_test` outside `environment=local`; invalid literals rejected at load.
- `tests/security/test_authentication.py` — the local adapter cannot be constructed outside
  a local environment.
- Bandit: 0 findings at medium severity or above; `nosec` count across the repository is 0.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-013"></a>
## F-013 — Missing ticket lifecycle controls

| Field | Value |
|---|---|
| **Finding ID** | F-013 |
| **Affected component** | `application/app/models/ticket.py`; `application/app/services/ticket_service.py` |
| **Severity** | Low |
| **Relevant CWE** | CWE-285 (Improper Authorization); CWE-841 (Improper Enforcement of Behavioral Workflow) |
| **OWASP** | API5:2023 Broken Function Level Authorization; A01:2021 |
| **Security requirement** | SR-Z6, SR-V9, SR-V8 |
| **Threat** | T-15, T-08 |
| **Status** | **Remediated** · retested · regression test present |

### Description

`status` was an unconstrained field on the update model with no state machine and no
role restriction, so:

- **Any member could close any ticket they could update.** Closing ends the support
  obligation and stops SLA measurement, so a member could suppress their organization's own
  support record — and an attacker holding one member account could close tickets to hide
  what they had done.
- **Any transition was legal**, including `closed → open`, so a terminal state was not
  terminal and a completed support record could be reopened and rewritten.
- **An empty `PATCH` was accepted**, bumping `updated_at` and emitting an audit event for a
  non-event — noise that makes the real audit trail harder to read.

### Root cause

The ticket lifecycle was modelled as a free-text field rather than as a state machine with
privileged transitions. Workflow enforcement was treated as a product concern rather than
as an authorization concern.

### Potential impact

Suppression of support records and of the evidence of activity on them; a degraded audit
trail. Low severity because the blast radius is one tenant's own records and the action is
logged — but it is a genuine authorization gap.

### Evidence

```python
# application/app/models/ticket.py:63-66  (v1-pre-review)
    priority: str | None = None
    status: str | None = None          # any value, any transition, any role
```

No `ALLOWED_STATUS_TRANSITIONS`, no `PRIVILEGED_STATUSES` and no
`authorize_status_change` existed in pass 1; the update path applied `status` like any
other field.

### Recommended remediation

Declare the lifecycle explicitly, make the terminal state terminal, and require the
administrator role for transitions that end a business obligation.

### Implemented remediation

1. `ALLOWED_STATUS_TRANSITIONS` declares the legal transitions for each of the five
   states. `CLOSED` maps to an **empty** frozenset — genuinely terminal. (Reopening is a
   new ticket, not a mutation of the old one; making the terminal state actually terminal
   also removes a whole class of "flip the record after the fact" abuse.)
2. `PRIVILEGED_STATUSES = frozenset({CLOSED})` and `authorize_status_change` deny a
   non-admin moving a ticket into a privileged status, returning
   `DENY_PRIVILEGED_STATUS` with reason `privileged_status_requires_admin`.
3. `ensure_transition_allowed` raises `ConflictError` (**409**, not 403) for an illegal
   transition — the caller is permitted to act, the ticket is simply not in a state that
   allows it. Distinguishing these is what makes the 403 metric meaningful for alerting.
4. `status` is typed `TicketStatus`, so an undeclared value is a 422.
5. `_require_at_least_one_change` rejects a no-op `PATCH` with a 422.
6. The ordering is deliberate: object-level authorization → status-change authorization →
   transition legality. A caller who may not touch the object learns nothing about its
   state.

### Verification test

- `tests/security/test_authorization_policy.py` — a member cannot close a ticket; an admin
  can; a closed ticket cannot be reopened by anyone.
- `tests/unit/test_authorization.py` — the full transition matrix.
- `tests/unit/test_models_and_keys.py` — empty-PATCH rejection.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-014"></a>
## F-014 — Missing HTTP security response headers

| Field | Value |
|---|---|
| **Finding ID** | F-014 |
| **Affected component** | `application/app/main.py`; `application/app/security/http.py` (added) |
| **Severity** | Low |
| **Relevant CWE** | CWE-693 (Protection Mechanism Failure); CWE-525 (Use of Web Browser Cache Containing Sensitive Information) |
| **OWASP** | A05:2021 Security Misconfiguration |
| **Security requirement** | SR-H1 – SR-H3, SR-H6, SR-L9 |
| **Threat** | T-09, T-10 |
| **Status** | **Remediated** · retested · regression test present |

### Description

No security headers were applied to any response. For a multi-tenant JSON API the
consequential omission is **`Cache-Control: no-store`**: without it an intermediate cache
or a browser may retain one tenant's ticket data and serve it to a subsequent request that
looks similar. Also absent: `X-Content-Type-Options` (so a JSON body containing
customer-supplied text could be re-interpreted as HTML), `X-Frame-Options`,
`Referrer-Policy`, a CSP, and HSTS.

There was additionally no `X-Request-Id` on responses, so a customer could not quote a
correlation id when reporting a problem — which is what makes the logging in F-007 useful
operationally.

### Root cause

Security headers are usually thought of as a browser-application concern, and this is a
JSON API — so they were skipped. But API responses pass through the same caches and
browsers, and the API is reachable from a browser.

### Potential impact

Cross-tenant disclosure via a shared cache (the realistic one); content-sniffing and
clickjacking vectors for any browser-based client; loss of request correlation for support
and incident response.

### Evidence

Pass 1 `main.py` registered `CORSMiddleware` and the exception handlers and nothing else.
`application/app/security/http.py` did not exist. No test asserted any response header.

### Recommended remediation

Apply a fixed header set to every response, including error responses raised outside the
normal middleware stack, and return a correlation id.

### Implemented remediation

1. `SECURITY_HEADERS` applied to every response: `X-Content-Type-Options: nosniff`,
   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
   `Pragma: no-cache`, `X-Permitted-Cross-Domain-Policies: none`,
   `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
2. `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none';
   form-action 'none'` — the strictest possible policy, since the API returns JSON only.
   Skipped for the interactive docs paths, which load CDN assets and are only ever enabled
   locally.
3. `X-Request-Id` on every response, matching the id on every log record.
4. Implemented as a **pure ASGI middleware**, not Starlette's `BaseHTTPMiddleware`:
   `BaseHTTPMiddleware` runs the downstream app in a separate task, which breaks
   `ContextVar` propagation — and the request id lives in a `ContextVar` that must be
   visible to every log call and to the error handlers.
5. Registered **first**, so it is the outermost middleware and stamps headers on whatever
   response comes back, including CORS short-circuits.
6. `apply_security_headers` is called **again** inside `_error_response`, because the
   unhandled-exception handler runs outside the user middleware stack (Starlette's
   `ServerErrorMiddleware` is outermost) and a 500 would otherwise ship without headers.
7. `server_header=False` on the development server so it does not fingerprint itself.

### Verification test

- `tests/security/test_api_behaviour.py` — every header asserted on a success response, a
  403, a 404, a 422 **and a 500**; `X-Request-Id` present on all of them; no server banner.
- `tests/unit/test_logging_and_context.py` — the response id matches the logged id.

### Final status

**Remediated and verified.** Residual risk: Low.

---

<a id="f-015"></a>
## F-015 — Unconditional writes silently replace records

| Field | Value |
|---|---|
| **Finding ID** | F-015 |
| **Affected component** | `application/app/repositories/ticket_repository.py` |
| **Severity** | Low |
| **Relevant CWE** | CWE-362 (Race Condition); CWE-471 (Modification of Assumed-Immutable Data) |
| **OWASP** | A04:2021 Insecure Design; API6:2023 |
| **Security requirement** | SR-V10 |
| **Threat** | T-08 |
| **Status** | **Remediated** · retested · regression test present |

### Description

Both the create and the update path used an unconditional `put_item`. `PutItem` replaces
whatever is at the key, which has three consequences:

1. A `ticket_id` collision **silently destroys** the existing record (low probability with
   `uuid4`, but the failure is silent data loss rather than an error).
2. A bug in the service layer can **create** a record through the update path, bypassing
   every create-time control — owner assignment, initial status, server-generated id.
3. A delete occurring between the read and the write **resurrects** the deleted record from
   stale in-memory state.

Since the update flow is read-modify-write with no condition, two concurrent updates also
silently clobber each other.

### Root cause

`put_item` was used as "save this object" without expressing the precondition each call
site actually assumes — that the item does not yet exist (create) or does (update).

### Potential impact

Loss of support history, which is part of the audit trail for a customer relationship. An
attacker able to overwrite can remove the evidence of what they did. Low severity because
exploitation needs another weakness to reach it.

### Evidence

```python
# application/app/repositories/ticket_repository.py:34-36 and 77-79  (v1-pre-review)
    def put_ticket(self, ticket: Ticket) -> None:
        """Insert a new ticket."""
        self._table.put_item(Item=_to_item(ticket))          # no condition

    def save_ticket(self, ticket: Ticket) -> None:
        """Persist an updated ticket."""
        self._table.put_item(Item=_to_item(ticket))          # no condition
```

### Recommended remediation

Make the precondition explicit with a DynamoDB `ConditionExpression` on each path, and
translate a conditional-check failure into a 409.

### Implemented remediation

1. `put_ticket`: `ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)"`
   — a collision now fails loudly instead of destroying data.
2. `save_ticket`: `ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)"` —
   the update path cannot create, and a record deleted between read and write is not
   resurrected.
3. `ConditionalCheckFailedException` is caught and translated to `ConflictError` (409) with
   a generic client message; the specific reason (`ticket_already_exists`,
   `ticket_missing_or_changed`) stays in the log. Any other `ClientError` is re-raised
   rather than swallowed.
4. Reinforced at the IAM layer: no `DeleteItem` grant **and** an explicit `Deny`, so
   records cannot be removed at all.
5. `CLOSED` is terminal (F-013), so a completed record cannot be reworked.
6. DynamoDB point-in-time recovery is enabled in Terraform.

### Verification test

- `tests/integration/test_dynamodb_repository.py` — against `moto`: creating a duplicate
  key raises 409; updating a missing item raises 409; a legitimate update succeeds.
- `tests/security/test_authorization_policy.py` — terminal-state enforcement.

### Final status

**Remediated and verified**, with one caveat: conditional-write semantics are asserted
against **`moto`'s emulation** of DynamoDB, not real DynamoDB. The expressions are
standard and reviewed, but the behaviour is unverified against the real service (limitation
L5). Residual risk: Low. Recommended further safeguard (not implemented): an
optimistic-concurrency version attribute, so two concurrent updates cannot silently clobber
each other's field-level changes (observation O-3).

---

## Appendix A — Severity rationale

Severity is assigned on **impact in the deployed shape**, not on exploit difficulty alone.

| ID | Why this severity |
|---|---|
| F-001 | Critical: unauthenticated, remote, attacker-chosen tenant and user, full read/write. No precondition beyond network reachability. |
| F-002, F-003, F-004, F-006 | High: each gives cross-tenant or cross-user access to data, but requires an authenticated account (F-002/F-003/F-004) or a code regression (F-006). F-004's create vector is arguably Critical — it is a cross-tenant *write* available to any authenticated user — and is rated High only because the attacker must already hold a valid account. |
| F-005 | Medium: not directly exploitable; requires another weakness to reach. Impact if chained is Critical, which is why it is remediated with explicit Denies and a permissions boundary rather than just tightened. |
| F-007 | Medium: a real data exposure, but into a store with narrower access than the public API. Would be High where the log group is broadly readable. |
| F-008, F-009, F-010, F-011, F-012 | Medium: each enables or amplifies another attack (enumeration, cost amplification, key manipulation, misconfiguration) rather than directly disclosing data. F-010 is at the top of this band because, once reads are key-scoped, the cursor is the only remaining path from client input to the key. |
| F-013, F-014, F-015 | Low: genuine weaknesses with narrow blast radius, needing another weakness or an unlikely precondition to matter. |

## Appendix B — Mapping to standards

| ID | CWE | OWASP Top 10 (2021) | OWASP API Top 10 (2023) | ASVS 4.0.3 |
|---|---|---|---|---|
| F-001 | CWE-290, CWE-807 | A07 | API2 | 2.1.1, 3.5.2 |
| F-002 | CWE-269, CWE-807 | A01 | API5 | 4.1.1 |
| F-003 | CWE-862, CWE-639 | A01 | API1 | 4.1.3 |
| F-004 | CWE-915, CWE-639 | A01, A04 | API3 | 5.1.1, 5.1.2 |
| F-005 | CWE-250, CWE-732 | A01, A05 | — | 1.2.2 |
| F-006 | CWE-639, CWE-1230 | A01 | API1 | 4.2.1 |
| F-007 | CWE-532, CWE-117 | A09 | API8 | 7.1.1, 8.3.4 |
| F-008 | CWE-209, CWE-204, CWE-497 | A05 | API3 | 7.4.1 |
| F-009 | CWE-770, CWE-1284 | A04 | API4 | 5.1.2 |
| F-010 | CWE-639, CWE-20 | A01 | API1 | 4.2.1 |
| F-011 | CWE-20, CWE-74, CWE-706 | A03 | API3 | 5.1.3 |
| F-012 | CWE-1188, CWE-16, CWE-605, CWE-942 | A05 | — | 14.1.3, 14.3.3 |
| F-013 | CWE-285, CWE-841 | A01 | API5 | 4.1.3, 11.1.1 |
| F-014 | CWE-693, CWE-525 | A05 | — | 14.4 |
| F-015 | CWE-362, CWE-471 | A04 | API6 | 11.1.2 |
