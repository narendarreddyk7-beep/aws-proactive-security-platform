# STRIDE Threat Model

**System:** Multi-Tenant Customer Support API
**Method:** STRIDE applied per data flow, against the flows enumerated in
[`data-flow.md`](data-flow.md) and the trust boundaries in
[`architecture.md`](architecture.md).
**Date of analysis:** 2026-10-23
**Analyst:** Security Engineering (this project)

---

## 1. Method and scope

STRIDE was applied **per data flow** rather than per component, because every interesting
threat in this system lives at a boundary crossing rather than inside a box. For each of
the ten cross-boundary flows (DF1–DF10) the six STRIDE categories were considered and
discarded where they did not apply. For example, Repudiation was discarded for DF1
(Client → Gateway) because the gateway's access log is written by AWS outside the
application's control, and retained for DF7 (Lambda → Logs) where the application chooses
what is attributable.

**16 threats** survived that filter. They are not padded to a target: categories that
produced nothing credible for a given flow are simply absent. Each threat below is
traceable to a specific file, a specific control, and a specific test.

### Scoring

| Likelihood | Meaning |
|---|---|
| High | Requires only a normal authenticated account and ordinary tooling |
| Medium | Requires a specific precondition (a code regression, a misconfiguration, stolen credentials) |
| Low | Requires compromise of AWS-managed infrastructure or a privileged operator |

| Severity | Meaning |
|---|---|
| Critical | Multi-tenant data breach, or full control of the data plane |
| High | Single-tenant breach, privilege escalation within a tenant, or integrity loss |
| Medium | Partial disclosure, availability loss, or degraded auditability |
| Low | Hygiene; needs chaining with another weakness to matter |

**Residual risk** is the rating *after* the implemented mitigations, assuming they work as
tested. It is deliberately never "none": a residual of Low still means "re-check this
after a refactor".

### Relationship to the code review

Ten of these threats were found **realised in the pre-review implementation** and are
cross-referenced to the finding IDs in
[`../assessments/security-findings.md`](../assessments/security-findings.md). That is the
point of the two-pass methodology: the threat model is not a parallel document that
asserts the system is safe, it is the thing the review was conducted against.

---

## 2. Threat summary

| ID | Category | Threat | Likelihood | Severity | Residual | Finding |
|---|---|---|---|---|---|---|
| T-01 | Spoofing | Identity asserted from a client-controlled source | High | Critical | Low | F-001, F-012 |
| T-02 | Spoofing | Access-token theft or replay | Medium | High | Medium | — |
| T-03 | Spoofing | Token not issued for this API is accepted | Low | Critical | Low | — |
| T-04 | Tampering | Mass assignment of server-controlled fields | High | Critical | Low | F-004 |
| T-05 | Tampering | Client input manipulates DynamoDB keys | Medium | High | Low | F-010, F-011 |
| T-06 | Tampering | Membership record manipulation | Low | Critical | Medium | — |
| T-07 | Repudiation | Loss of attribution or forged log records | Medium | Medium | Low | F-007 |
| T-08 | Repudiation | Silent overwrite destroys ticket history | Medium | High | Low | F-015 |
| T-09 | Info. disclosure | Cross-tenant read through an unscoped query | High | Critical | Low | F-006 |
| T-10 | Info. disclosure | Error responses disclose existence or internals | High | Medium | Low | F-008 |
| T-11 | Info. disclosure | Customer content or credentials written to logs | High | High | Low | F-007 |
| T-12 | Denial of service | Query amplification / unbounded result sets | High | Medium | Low | F-009 |
| T-13 | Denial of service | Concurrency and cost exhaustion | Medium | Medium | Medium | — |
| T-14 | Elev. of privilege | Privilege escalation via self-asserted role | High | High | Low | F-002 |
| T-15 | Elev. of privilege | Missing enforcement on a write path | High | High | Low | F-003, F-013 |
| T-16 | Elev. of privilege | Over-privileged execution role | Medium | Critical | Low | F-005 |

---

## 3. Threats

### T-01 — Identity asserted from a client-controlled source

| | |
|---|---|
| **Affected component** | C5 `app/security/identity.py`; C4 FastAPI application |
| **Category** | Spoofing |
| **Trust boundary** | TB2 (API Gateway → Lambda) |
| **Flow** | DF2 |
| **Likelihood** | High · **Severity** Critical · **Residual** Low |
| **Finding** | F-001 (header fallback), F-012 (local adapter reachable in a deployed config) |

**Preconditions.** Network reachability of the function's HTTP surface, plus either
(a) an application code path that reads identity from a request header, query parameter or
body when the authorizer context is absent, or (b) a deployed configuration in which the
local development identity adapter is active.

**Attack.** The caller sends `X-User-Id: victim` and `X-Org-Id: other-tenant` with no
bearer token. If the application falls back to headers, the request is served as that
user in that organization. Both vectors are a complete authentication bypass, not a
partial one — the attacker chooses the tenant *and* the user.

**Business impact.** Full read/write access to every tenant's tickets by an
unauthenticated caller. Multi-tenant breach, reportable, with no reliable way to
reconstruct what was taken because the attacker's "identity" is whatever they typed.

**Existing mitigations.**
1. `ApiGatewayJwtIdentityProvider.extract()` reads `requestContext.authorizer.jwt.claims`
   and nothing else; there is no header fallback, and the `authorizer.lambda` path is
   explicitly ignored so a REQUEST-authorizer context cannot substitute for JWT validation.
2. The local adapter reads only `X-Local-*` headers, which cannot be confused with a real
   identity header and can be stripped at the edge by a single WAF rule.
3. Three independent guards keep that adapter out of a deployed environment: `Settings`
   refuses to load `identity_source=local_test` unless `environment=local`; the adapter's
   constructor raises on the same condition; and `gateway` is the default so an unset
   variable is safe. Terraform sets `APP_IDENTITY_SOURCE=gateway` explicitly.
4. When constructed, the adapter logs `insecure_identity_adapter_enabled`, which has a
   CloudWatch alarm at threshold 1.

**Recommended further safeguards.** A WAF rule dropping `X-Local-*` at the edge; a
synthetic canary that asserts an unauthenticated request receives 401 from the deployed
stage.

**Verification.** `tests/security/test_authentication.py` (header-asserted identity is
rejected; `aws.event` without an authorizer yields 401), `tests/unit/test_config.py`
(fail-closed config guard). Live gateway rejection is an AWS-gated test in
`tests/integration/test_aws_gateway_contract.py` and is **unverified** in this
environment.

**Residual risk — Low.** The remaining exposure is a future code change reintroducing a
fallback. The regression tests fail loudly if it does.

---

### T-02 — Access-token theft or replay

| | |
|---|---|
| **Affected component** | C2 Cognito; C1 API Gateway |
| **Category** | Spoofing |
| **Trust boundary** | TB1 |
| **Flow** | DF1 |
| **Likelihood** | Medium · **Severity** High · **Residual** **Medium** |

**Preconditions.** The attacker obtains a valid, unexpired access token — from a phished
or malware-infected client, a logging proxy, a browser extension, or a client application
that stores tokens carelessly.

**Attack.** Replay the bearer token. Bearer tokens carry no proof of possession, so a
stolen token is indistinguishable from the legitimate user until it expires.

**Business impact.** Full compromise of one user's rights within one tenant: read and
modify that user's tickets, and if the user is an administrator, the whole tenant.

**Existing mitigations.**
1. Short access-token validity (`cognito_access_token_validity_minutes`, default 60,
   configurable per environment) bounds the replay window.
2. Cognito password policy and optional MFA (`cognito_mfa_configuration`) raise the bar on
   the credential-theft step.
3. Cognito advanced security mode (`cognito_advanced_security_mode`) can enable adaptive
   authentication and compromised-credential detection.
4. TLS in transit; `Cache-Control: no-store` prevents intermediaries caching responses.
5. Every request is logged with `principal_id`, so post-hoc reconstruction of what a
   stolen token did is possible from CloudWatch.

**Recommended further safeguards.** Shorter access-token TTL in production; mandatory MFA
for the administrator role; anomaly detection on `principal_id` + source IP (the Insights
query `authorization_denials_by_principal` is a starting point, but IP-based detection
needs the API access log joined in); DPoP or mTLS for high-assurance clients.

**Verification.** Not testable in this environment: it depends on Cognito configuration
and live token issuance. Covered by the AWS-gated tests and by review of `cognito.tf`.

**Residual risk — Medium, accepted.** Bearer-token replay is inherent to the OAuth
bearer model. Reducing it further requires proof-of-possession tokens, which the client
application would have to support. Recorded as an accepted risk (AR-03) in
[`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md).

---

### T-03 — A token not issued for this API is accepted

| | |
|---|---|
| **Affected component** | C1 API Gateway JWT authorizer |
| **Category** | Spoofing |
| **Trust boundary** | TB1, TB7 |
| **Flow** | DF1 |
| **Likelihood** | Low · **Severity** Critical · **Residual** Low |

**Preconditions.** The authorizer is misconfigured: `issuer` not pinned to this user
pool, or `audience` not pinned to this app client.

**Attack.** The attacker creates a user in *their own* Cognito user pool, sets
`custom:organization_id` to a victim tenant, and presents that token. A signature-only
check passes, because the token is genuinely signed — just by the wrong issuer. This is
the cloud-native form of "signature valid, therefore trusted".

**Business impact.** Attacker-chosen tenant and role, with a cryptographically valid
token. Equivalent to T-01 in effect but harder to spot, because the request looks
properly authenticated in every log.

**Existing mitigations.**
1. `aws_apigatewayv2_authorizer.cognito` pins `issuer` to the created user pool's endpoint
   and `audience` to the created app client id — both from Terraform resource references,
   so they cannot drift from the deployed pool.
2. The user pool denies the app client write access to `custom:organization_id` and
   `custom:role`, so even within the correct pool a user cannot self-assert tenancy.
3. Defence in depth: the membership record is authoritative (see T-14), so a token
   asserting an organization the user has no membership in is rejected with 403 regardless
   of how it was signed.

**Recommended further safeguards.** Optional scope enforcement
(`enable_scope_enforcement` with the Cognito resource server) so routes require an
explicit scope; a Checkov/Conftest policy asserting the authorizer always has a non-empty
`audience`.

**Verification.** `tests/integration/test_aws_gateway_contract.py` holds this as an
explicitly skipped AWS test — **unverified** without a deployment. The membership
defence-in-depth layer *is* verified by `tests/security/test_authorization_policy.py`.

**Residual risk — Low.** Two independent controls (authorizer pinning and server-side
membership) must both fail.

---

### T-04 — Mass assignment of server-controlled fields

| | |
|---|---|
| **Affected component** | C4 `app/models/ticket.py`; `app/services/ticket_service.py` |
| **Category** | Tampering |
| **Trust boundary** | TB2 |
| **Flow** | DF5 |
| **Likelihood** | High · **Severity** Critical · **Residual** Low |
| **Finding** | F-004 |

**Preconditions.** A request model that accepts unknown fields, or that declares a
server-controlled field as client-writable, combined with a service that merges the
validated payload into the stored object.

**Attack.** `POST /v1/tickets` with `{"title":"x","description":"y",
"organization_id":"victim-org"}` writes a ticket **into the victim tenant's partition**.
Or `PATCH /v1/tickets/{id}` with `{"created_by":"someone-else"}` or
`{"organization_id":"victim-org"}` moves an existing record across the tenant boundary.
This is a cross-tenant **write**, which is worse than a read: it corrupts another
tenant's data and can be used to plant content.

**Business impact.** Integrity loss across tenants, data planted in another customer's
account, and a corrupted audit trail. In the pre-review code this was reachable by any
authenticated user with a single extra JSON field.

**Existing mitigations.**
1. Every request model sets `extra="forbid"`: an unknown field is a 422, not a silent drop.
   A silent drop would also be *invisible*, letting an attacker map the schema at leisure.
2. `organization_id`, `created_by`, `ticket_id`, `status` and the timestamps are **absent
   from `TicketCreateRequest`** — there is no field to populate.
3. `TicketUpdateRequest` declares exactly four writable fields, and
   `CLIENT_UPDATABLE_FIELDS` constrains `changes()` to that allow-list, so even a model
   change cannot widen what the service applies.
4. `Ticket` itself is `frozen=True`; updates go through `model_copy(update=…)` with the
   allow-listed changes only.
5. The stored `organization_id` is written from `principal.organization_id`.

**Recommended further safeguards.** A schema test in CI asserting that no request model
declares a server-controlled field name (currently enforced by review plus the regression
tests).

**Verification.** `tests/security/test_tenant_isolation.py::test_create_cannot_target_another_tenant_via_request_body`,
`::test_update_cannot_move_a_ticket_to_another_tenant`;
`tests/security/test_input_validation.py` (unknown fields rejected).

**Residual risk — Low.**

---

### T-05 — Client input manipulates DynamoDB keys

| | |
|---|---|
| **Affected component** | C7 `app/repositories/pagination.py`, `app/repositories/keys.py` |
| **Category** | Tampering |
| **Trust boundary** | TB2 → TB4 |
| **Flow** | DF6, DF4 |
| **Likelihood** | Medium · **Severity** High · **Residual** Low |
| **Finding** | F-010 (cursor), F-011 (identifier) |

**Preconditions.** Client-supplied values reach key construction or
`ExclusiveStartKey` without validation.

**Attack — two vectors.**
1. **Cursor.** `LastEvaluatedKey` is a plain dict. Base64-decode the cursor, rewrite
   `"PK":"TENANT#victim-org"`, re-encode, and send it as `?cursor=…`. If it is forwarded
   to `ExclusiveStartKey`, the query resumes **inside the victim's partition**.
2. **Identifier.** `#` is the key separator. A `ticket_id` of
   `x#TICKET#other` or an `organization_id` containing `#` can address a key the
   application never intended to construct.

**Business impact.** Cross-tenant read, bypassing the partition-key control that the
whole isolation design rests on.

**Existing mitigations.**
1. `decode_cursor(cursor, organization_id=…)` requires `PK == TENANT#{caller's org}`,
   rejects unexpected attributes, non-string values, missing table keys, and anything over
   1 KB — with an identical generic message in every case so the decoder cannot be probed.
   The store is never called on a rejected cursor.
2. `validate_cursor_key` is re-applied **inside the repository**, because a repository is
   a reusable component and must not assume its caller validated anything.
3. `ticket_id` is typed `UUID` in the route signature, so a malformed identifier is
   rejected by FastAPI before any handler runs.
4. `keys._assert_no_separator` rejects empty values and any value containing `#` at the
   last point before a key is built.
5. A signed cursor was considered and rejected: a signature proves *we issued it*, not
   that we issued it *to this tenant*. Checking the partition directly is the stronger
   statement and needs no key management.

**Recommended further safeguards.** None material; the control is at the right layer.

**Verification.** `tests/security/test_tenant_isolation.py::test_pagination_cursor_from_another_tenant_is_rejected`,
`::test_malformed_pagination_cursor_is_rejected[…]`;
`tests/security/test_input_validation.py::test_ticket_identifier_must_be_a_uuid[embedded-separator|embedded-key-prefix|encoded-null-byte|…]`;
`tests/unit/test_models_and_keys.py`.

**Residual risk — Low.**

---

### T-06 — Membership record manipulation

| | |
|---|---|
| **Affected component** | C8 DynamoDB `USER#…/MEMBERSHIP#…` items; the out-of-band provisioning process |
| **Category** | Tampering → Elevation of privilege |
| **Trust boundary** | TB3 |
| **Flow** | DF3 |
| **Likelihood** | Low · **Severity** Critical · **Residual** **Medium** |

**Preconditions.** Write access to the membership items: the provisioning IAM principal
is compromised, or the API's own role is widened to allow writes to `USER#` keys.

**Attack.** Insert `{PK: USER#attacker, SK: MEMBERSHIP#victim-org, role: admin,
status: active}`. The application then treats the attacker as a legitimate administrator
of the victim organization, because the membership record is *by design* the authoritative
source of role.

**Business impact.** Full tenant takeover, with every subsequent request appearing
completely legitimate in the logs.

**Existing mitigations.**
1. The support API exposes **no endpoint** that creates or modifies a membership. There is
   no application-layer path at all.
2. The Lambda role's `PutItem` grant is scoped to the table, and the application only
   ever constructs `USER#` keys for *reads* — but see the honest limitation below.
3. Permissions boundary on the execution role prevents a change-management failure from
   widening it beyond the boundary's ceiling.
4. Explicit `Deny` on `dynamodb:DeleteItem`, `BatchWriteItem`, `DeleteTable` and
   `UpdateTable` means a compromised function cannot remove or bulk-rewrite memberships.
5. `role_claim_mismatch` is logged and alarmed, so a token whose role disagrees with the
   record is visible — which is one observable signature of a tampered record.
6. DynamoDB point-in-time recovery is enabled, so a tampered record can be identified
   against a known-good point in time.

**Honest limitation.** The execution role's `dynamodb:PutItem` grant is scoped to the
table ARN, **not** to the `TICKET#` sort-key prefix. IAM can express that constraint with
`dynamodb:LeadingKeys`, but only for the *partition* key — it cannot restrict a sort-key
prefix. So an arbitrary-write bug in the application could in principle write a membership
item. The compensating controls are the absence of any code path that writes a `USER#` key
and the conditional-write expressions, not IAM.

**Recommended further safeguards.** Move memberships to a **separate table** so the
execution role can be granted read-only access to it — this is the clean fix and is the
top-ranked next step in the final assessment. Alternatively, add a
`dynamodb:LeadingKeys` condition and split ticket/membership partitions accordingly.
CloudTrail data events on the table for forensic coverage.

**Verification.** `tests/security/test_data_access_scoping.py` asserts the application
never issues a write against a `USER#` partition. IAM enforcement itself is an AWS-gated
test (`test_aws_gateway_contract.py`) and is **unverified** here.

**Residual risk — Medium.** The architectural fix (separate table) is identified but not
implemented. Recorded as AR-04.

---

### T-07 — Loss of attribution or forged log records

| | |
|---|---|
| **Affected component** | C9 CloudWatch Logs; `app/observability/logging.py`, `request_context.py` |
| **Category** | Repudiation |
| **Trust boundary** | TB5 |
| **Flow** | DF7 |
| **Likelihood** | Medium · **Severity** Medium · **Residual** Low |
| **Finding** | F-007 |

**Preconditions.** Either security-relevant events are not logged with enough identity to
attribute them, or client-controlled text reaches a log line unescaped.

**Attack.** Supply `X-Request-Id: abc\n{"severity":"info","event_type":"ticket_read"}` to
inject a forged record into the log stream, masking a real denial. Or simply perform
actions on a path that emits no audit event, so there is nothing to attribute afterwards.

**Business impact.** A denial that is not logged cannot be alerted on and cannot be
investigated; a forged record can send an investigation in the wrong direction. Both
undermine the incident response in [`../runbooks/authorization-alert-triage.md`](../runbooks/authorization-alert-triage.md).

**Existing mitigations.**
1. `sanitize_request_id` accepts a client `X-Request-Id` only when it matches a strict
   pattern within a 64-character bound, and generates one otherwise.
2. `JsonFormatter` emits one JSON object per line with `json.dumps`, which escapes
   newlines — so even a multi-line traceback cannot terminate a record early and forge the
   next one.
3. Log messages are static strings by convention; variable data goes into allow-listed
   fields. Messages are additionally newline-stripped and truncated at 256 characters.
4. Every authorization denial emits `authorization_denied` with `principal_id`,
   `organization_id`, `role`, `resource_id` and a machine-readable `reason` — treated as a
   security control, not diagnostics.
5. `request_id` is on every record and returned in the response header, so a customer
   report can be tied to a log line.

**Recommended further safeguards.** CloudWatch Logs resource policy restricting who can
`PutLogEvents` to the group; log archival to an append-only S3 bucket with Object Lock for
tamper-evident retention.

**Verification.** `tests/security/test_logging_and_data_protection.py::test_request_id_is_returned_and_correlates_with_logs`,
`::test_authorization_denial_emits_a_security_event`,
`::test_authentication_failure_emits_a_security_event`;
`tests/unit/test_logging_and_context.py` (request-id sanitising, newline handling).

**Residual risk — Low.**

---

### T-08 — Silent overwrite destroys ticket history

| | |
|---|---|
| **Affected component** | C7 `app/repositories/ticket_repository.py` |
| **Category** | Repudiation / Tampering |
| **Trust boundary** | TB3 |
| **Flow** | DF4 |
| **Likelihood** | Medium · **Severity** High · **Residual** Low |
| **Finding** | F-015 |

**Preconditions.** Unconditional `PutItem` on both the create and update paths.

**Attack.** `PutItem` replaces whatever is at the key. Two consequences: a `ticket_id`
collision silently destroys the existing record; and a bug in the service layer can create
a record *through the update path*, bypassing every create-time check (owner assignment,
initial status). A concurrent delete-then-update resurrects a deleted record from stale
in-memory state.

**Business impact.** Loss of support history, which is part of the audit trail for a
customer relationship. An attacker who can overwrite can remove the evidence of what they
did.

**Existing mitigations.**
1. `put_ticket` asserts `attribute_not_exists(PK) AND attribute_not_exists(SK)`.
2. `save_ticket` asserts `attribute_exists(PK) AND attribute_exists(SK)`.
3. A `ConditionalCheckFailedException` is translated to a 409 with a generic message
   (`ticket_already_exists` / `ticket_missing_or_changed` stay in the log).
4. `CLOSED` is a terminal state in `ALLOWED_STATUS_TRANSITIONS`, so a closed ticket cannot
   be flipped back and re-worked.
5. No `DeleteItem` grant, plus an explicit `Deny`, so records cannot be removed at all.
6. Point-in-time recovery on the table.

**Recommended further safeguards.** An optimistic-concurrency version attribute so two
concurrent updates cannot silently clobber each other's field changes (currently
last-writer-wins at field granularity); an append-only audit item per change.

**Verification.** `tests/integration/test_dynamodb_repository.py` (conditional writes
against `moto`, including the collision and missing-item paths);
`tests/security/test_authorization_policy.py` (terminal-state enforcement).
Conditional-write semantics are asserted against moto's emulation, not real DynamoDB.

**Residual risk — Low.**

---

### T-09 — Cross-tenant read through an unscoped query

| | |
|---|---|
| **Affected component** | C7 `app/repositories/ticket_repository.py`; C13 IAM policy |
| **Category** | Information disclosure |
| **Trust boundary** | TB4 |
| **Flow** | DF4 |
| **Likelihood** | High · **Severity** Critical · **Residual** Low |
| **Finding** | F-006 |

**Preconditions.** A read path that uses `Scan` with a `FilterExpression`, or a `Query`
whose partition key is not derived from the verified principal.

**Attack.** `Scan` reads the whole table and relies on a filter to remove other tenants'
items. Isolation then depends on a filter expression that any refactor can drop, and the
items are read into the function's memory before being filtered out — so a serialisation
bug, a logging statement, or an off-by-one in pagination can expose them. Cost and latency
also scale with *every* tenant's data.

**Business impact.** Multi-tenant breach from a single-line regression.

**Existing mitigations.**
1. No `Scan` anywhere in a user-facing read path. Admin listing is
   `PK = TENANT#{org} AND SK begins_with TICKET#`; member listing is
   `GSI1PK = TENANT#{org}#USER#{user}`; single reads are an exact `(PK, SK)` `GetItem`.
2. The GSI1 partition key embeds **both** tenant and user. Keying it on the user alone
   would let a user's tickets from one organization surface in a query scoped to another —
   reintroducing the cross-tenant path through the index.
3. The role's enumerated actions are `GetItem`, `PutItem`, `Query` only, and there is an
   explicit `Deny` on `dynamodb:Scan`. An explicit Deny cannot be overridden by any later
   Allow, so a future broad policy attached to this role still cannot scan.
4. A member's role narrows the **query**, not the result set (`list_scope` returns the
   `created_by` filter that selects the index).

**Recommended further safeguards.** Per-tenant tables or accounts if a customer requires
hard isolation; a lint/CI rule failing on the literal `.scan(` in `application/`.

**Verification.** `tests/security/test_data_access_scoping.py` (a recording table fixture
asserts every call is a key-scoped `query`/`get_item`, that `scan` is never called, and
that key conditions always pin the caller's partition);
`tests/security/test_tenant_isolation.py`;
`tests/integration/test_dynamodb_repository.py`.

**Residual risk — Low.**

---

### T-10 — Error responses disclose existence or internals

| | |
|---|---|
| **Affected component** | C4 `app/main.py`, `app/security/authorization.py` |
| **Category** | Information disclosure |
| **Trust boundary** | TB2 |
| **Flow** | DF8 |
| **Likelihood** | High · **Severity** Medium · **Residual** Low |
| **Finding** | F-008 |

**Preconditions.** Error responses that differ between "does not exist" and "exists but
you may not have it", or that carry exception text, stack traces or submitted values.

**Attack — three vectors.**
1. **Existence oracle.** 403 for another tenant's ticket and 404 for a non-existent one
   lets an attacker enumerate valid ticket ids across tenants without reading any content.
2. **Internal disclosure.** `str(exc)` and `traceback.format_exc()` in a 500 body reveal
   file paths, library versions and sometimes data values.
3. **Value echo.** FastAPI's default 422 body includes `input` — the offending value. For
   a support API that widens where customer content ends up, because validation errors are
   routinely captured by gateways, proxies and client-side error reporters.

**Business impact.** Reconnaissance that makes every other attack cheaper, plus
inadvertent disclosure of customer content through error-reporting pipelines.

**Existing mitigations.**
1. Reads are partition-scoped, so "another tenant's ticket" and "no such ticket" produce
   the *same* `None` — and therefore the same 404. The indistinguishability is a property
   of the data access, not of a hand-written `if`.
2. One error envelope everywhere: `{error, message, request_id}` (+ `fields` for 422).
   No trace, no exception text, no module path, no library name.
3. `_sanitize_validation_errors` reduces Pydantic errors to field location + reason and
   **drops the submitted value**.
4. `enforce()` uses one identical generic message for every denial; the specific reason
   stays in `Decision.reason` for the log.
5. Framework 404/405/415 bodies are normalised into the same envelope, so routing hints do
   not leak.
6. The unhandled-exception handler logs the full trace and returns a fixed sentence; it
   also re-applies security headers, because it runs outside the user middleware stack.

**Recommended further safeguards.** Per-principal rate limiting on 404s to blunt
enumeration attempts (currently only global throttling).

**Verification.** `tests/security/test_error_handling.py` (no trace/exception text in any
error body; uniform envelope; 422 omits submitted values);
`tests/security/test_tenant_isolation.py::test_cross_tenant_denial_does_not_disclose_existence`;
`tests/security/test_api_behaviour.py`.

**Residual risk — Low.**

---

### T-11 — Customer content or credentials written to logs

| | |
|---|---|
| **Affected component** | C9 CloudWatch Logs; `app/observability/logging.py` |
| **Category** | Information disclosure |
| **Trust boundary** | TB5 |
| **Flow** | DF7 |
| **Likelihood** | High · **Severity** High · **Residual** Low |
| **Finding** | F-007 |

**Preconditions.** A formatter that renders arbitrary `extra=` fields, plus any developer
passing a request payload, a domain object or a header into it.

**Attack.** Not an attack so much as an inevitability: the pre-review code logged
`extra={"payload": payload.model_dump()}` on ticket creation, `extra={"changes": changes}`
on update, and the `Authorization` header in a debug branch. CloudWatch Logs is a second
data store with its own access controls, its own retention and a far wider readership than
the request that produced the entry — so anything written there has a much larger blast
radius than it appears to.

**Business impact.** Customer ticket content, and potentially bearer tokens, replicated
into a store with broader access and longer retention than the database. A log reader with
no application entitlement reads customer data; an exported log widens it again.

**Existing mitigations.**
1. **Allow-list, not deny-list.** `ALLOWED_LOG_FIELDS` enumerates every renderable key. A
   field is invisible unless explicitly reviewed and permitted, so the failure mode of
   forgetting is a missing dashboard field — not customer data in a log. A deny-list fails
   the moment someone adds a field.
2. Only identifiers and outcomes are permitted: `principal_id`, `organization_id`,
   `resource_id`, `changed_fields` (**names** only), `reason`, `outcome`, HTTP shape.
3. No `title`, `description`, `payload`, `changes`, `token` or `authorization` key exists
   on the allow-list, so passing one has no effect.
4. The debug branch that logged the `Authorization` header is gone, and `debug` now
   defaults to `False`.
5. `botocore`/`boto3`/`urllib3` loggers are pinned to WARNING, since their records carry
   URLs and headers.
6. Message text is truncated at 256 characters as a backstop against interpolated content.
7. Log groups are CMK-encrypted with a configured retention period.

**Recommended further safeguards.** A CloudWatch Logs data-protection policy with managed
data identifiers as a second, independent layer; periodic sampling of log lines against a
content detector.

**Verification.** `tests/security/test_logging_and_data_protection.py::test_ticket_content_is_never_logged`,
`::test_update_changes_are_logged_as_field_names_only`,
`::test_log_payloads_only_contain_allow_listed_fields`,
`::test_successful_access_is_auditable_without_content`.

**Residual risk — Low.**

---

### T-12 — Query amplification / unbounded result sets

| | |
|---|---|
| **Affected component** | C4 `app/routes/tickets.py`; C7 repository; C8 DynamoDB |
| **Category** | Denial of service |
| **Trust boundary** | TB1 → TB3 |
| **Flow** | DF3, DF4 |
| **Likelihood** | High · **Severity** Medium · **Residual** Low |
| **Finding** | F-009 |

**Preconditions.** An unbounded `limit` query parameter, or unbounded request field
lengths.

**Attack.** `GET /v1/tickets?limit=1000000` turns one cheap request into a
full-partition read: read-capacity consumption, Lambda duration, response size and cost
all scale with the attacker's chosen number. Similarly, a 10 MB `description` inflates the
item and the partition.

**Business impact.** Cost amplification and latency for the whole tenant from a single
authenticated account; a handful of accounts can degrade the service for everyone.

**Existing mitigations.**
1. `limit` is bounded at the HTTP edge with `ge=1, le=MAX_PAGE_SIZE` (100), so an
   out-of-range value is a 422 before any handler runs.
2. The repository independently clamps with `max(1, min(limit, MAX_PAGE_SIZE))` — defence
   in depth, because a repository must not trust its caller.
3. `MAX_TITLE_LENGTH` (200) and `MAX_DESCRIPTION_LENGTH` (10 000) bound item size with
   headroom against DynamoDB's 400 KB limit.
4. Cursor length is capped at 1 KB.
5. API Gateway throttling (`api_throttling_rate_limit`, `api_throttling_burst_limit`).
6. Lambda reserved concurrency caps the blast radius on spend and on downstream capacity.
7. Member listings read only the member's own index partition, which is far smaller than
   the organization's.

**Recommended further safeguards.** Per-principal (not just per-stage) throttling via
usage plans or a WAF rate rule; a CloudWatch billing alarm.

**Verification.** `tests/security/test_input_validation.py::test_pagination_limit_is_bounded[zero|negative|above-maximum|far-above-maximum|integer-overflow-attempt]`,
oversized-field cases in the same module; `tests/unit/test_ticket_service.py` (repository
clamping).

**Residual risk — Low** for amplification. Edge-level flooding is T-13.

---

### T-13 — Concurrency and cost exhaustion from request floods

| | |
|---|---|
| **Affected component** | C1 API Gateway; C3 Lambda; C8 DynamoDB |
| **Category** | Denial of service |
| **Trust boundary** | TB1 |
| **Flow** | DF1 |
| **Likelihood** | Medium · **Severity** Medium · **Residual** **Medium** |

**Preconditions.** Public endpoint (which it must be), and an attacker with ordinary
bandwidth.

**Attack.** Flood the endpoint. Unauthenticated requests are rejected at the authorizer,
which is cheap but not free; authenticated requests from a compromised account consume
Lambda concurrency and DynamoDB capacity.

**Business impact.** Availability loss for all tenants on a shared function; unplanned
spend.

**Existing mitigations.**
1. Stage-level throttling (rate + burst) on API Gateway, set per environment.
2. Reserved concurrency on the Lambda bounds both the concurrency and the spend.
3. Rejection happens at the authorizer, so an unauthenticated flood never reaches
   application code or the database.
4. DynamoDB on-demand billing absorbs bursts without a provisioned-capacity cliff, and the
   `dynamodb_throttles` alarm fires if it does throttle.
5. `lambda_throttles` alarm indicates the concurrency ceiling has been reached.

**Honest limitation.** Reserved concurrency protects the account but *is* the mechanism by
which one tenant's flood becomes everyone's outage — the function is shared. There is no
per-tenant quota.

**Recommended further safeguards.** AWS WAF rate-based rules in front of the API;
per-tenant usage plans; separate functions or per-tenant reserved concurrency for the
largest customers; a CloudWatch billing alarm.

**Verification.** Not verified. Load testing was out of scope and is not meaningful
without a deployment. Throttling values are reviewed in `api.tf` / `lambda.tf` only.

**Residual risk — Medium, accepted.** Recorded as AR-05.

---

### T-14 — Privilege escalation via self-asserted role

| | |
|---|---|
| **Affected component** | C5 `app/security/identity.py`; C2 Cognito |
| **Category** | Elevation of privilege |
| **Trust boundary** | TB2, TB7 |
| **Flow** | DF3 |
| **Likelihood** | High · **Severity** High · **Residual** Low |
| **Finding** | F-002 |

**Preconditions.** The application derives the caller's role from a token claim, and/or
the Cognito app client can write that claim.

**Attack.** Two steps, either of which suffices. (1) If the app client has write access to
`custom:role`, the user calls `UpdateUserAttributes` to set `admin`, re-authenticates, and
is an administrator. (2) Even without that, a token is a *cached snapshot*: a user demoted
or removed five minutes ago still presents a token asserting the old role, so
claim-derived authorization honours a revoked privilege until expiry.

**Business impact.** Organization-wide read and modify rights, plus the ability to close
tickets — which can be used to suppress the record of what was done.

**Existing mitigations.**
1. **The membership record is authoritative.** `resolve_principal` looks up
   `USER#{user}/MEMBERSHIP#{org}` and builds the `Principal` with the role from that
   record. The token's `custom:role` is held as `claimed_role` and never used for a
   decision.
2. Membership must exist **and** be `status == active`, so a revoked membership denies
   immediately rather than at token expiry.
3. The Cognito app client has **no write access** to `custom:organization_id` or
   `custom:role` (`cognito.tf`), so step (1) fails at the identity provider.
4. A disagreement between claim and record logs `role_claim_mismatch`, which has an alarm
   — the record still wins, but the mismatch is visible.
5. There is no API endpoint that can create or modify a membership.

**Recommended further safeguards.** Short-TTL caching of membership lookups with explicit
invalidation if the per-request read becomes a cost concern (today's design pays one
`GetItem` per request and is deliberately the safe side of that trade-off).

**Verification.** `tests/security/test_authorization_policy.py` (token claim cannot
elevate; record wins), `tests/security/test_authentication.py` (missing/inactive
membership → 403), `tests/unit/test_authorization.py` (full role × operation matrix).

**Residual risk — Low.**

---

### T-15 — Missing enforcement on a write path

| | |
|---|---|
| **Affected component** | C6 `app/security/authorization.py`; C4 `app/services/ticket_service.py` |
| **Category** | Elevation of privilege |
| **Trust boundary** | TB2 |
| **Flow** | DF2, DF4 |
| **Likelihood** | High · **Severity** High · **Residual** Low |
| **Finding** | F-003, F-013 |

**Preconditions.** A policy helper that returns a bare `bool` and a caller that forgets to
consult it.

**Attack.** In the pre-review code, `can_update_ticket()` was defined and **never
called** on the update path. Any authenticated member could `PATCH` any ticket in their
organization — a classic IDOR, invisible in review because the helper existed and looked
used. Separately, with no status state machine, a member could close their own ticket,
ending the support obligation and stopping SLA measurement.

**Business impact.** Horizontal privilege escalation within a tenant (modify colleagues'
tickets) and vertical escalation into an administrator-only operation. An attacker with
one member account could alter and then close records to hide activity.

**Existing mitigations.**
1. Authorization returns an explicit `Decision(allowed, reason)` rather than a `bool`, and
   callers must pass it to `enforce()`. An unused `Decision` stands out in review in a way
   an unused boolean does not.
2. Enforcement is concentrated in one layer — `TicketService` — so "is every operation
   guarded?" is answerable by reading one file. Routes hold no authorization logic.
3. Three checks on the update path, in order: may this principal touch the object at all
   (`authorize_update_ticket`); is this *state change* permitted for this role
   (`authorize_status_change`); is the transition legal at all
   (`ensure_transition_allowed`, a 409 rather than a 403 — the caller is permitted to act,
   the ticket is simply not in a state that allows it).
4. `PRIVILEGED_STATUSES = {CLOSED}` makes closure administrator-only; `CLOSED` is terminal.
5. Every denial emits `authorization_denied` with the machine-readable reason.
6. `list_scope()` returns the query scope rather than a post-filter, so the role shapes the
   query itself.

**Recommended further safeguards.** A coverage assertion that every service method with a
`principal` parameter calls `enforce()` at least once (currently guaranteed by review plus
the role × operation test matrix).

**Verification.** `tests/security/test_authorization_policy.py` (member cannot update
another member's ticket; member cannot close; admin can),
`tests/unit/test_authorization.py` (exhaustive policy matrix),
`tests/unit/test_ticket_service.py` (enforcement is invoked on every path).

**Residual risk — Low.**

---

### T-16 — Over-privileged execution role

| | |
|---|---|
| **Affected component** | C13 `infrastructure/terraform/iam.tf`, `policies/lambda-execution.json` |
| **Category** | Elevation of privilege |
| **Trust boundary** | TB3 |
| **Flow** | DF4 |
| **Likelihood** | Medium · **Severity** Critical · **Residual** Low |
| **Finding** | F-005 |

**Preconditions.** A broad execution-role policy, plus any code-execution or
request-forgery weakness in the function.

**Attack.** The pre-review infrastructure draft granted
`{"Action": "dynamodb:*", "Resource": <table arn>}` and
`{"Action": "logs:*", "Resource": "*"}`. That role can read every tenant's data with a
single `Scan`, delete the table, and read or delete any log group in the account. The
application's own controls are then irrelevant: the attacker is no longer going through
the application.

**Business impact.** Multi-tenant breach plus destruction of the data *and* of the logs
that would evidence it — the worst case in this system.

**Existing mitigations.**
1. Actions are enumerated: `GetItem`, `PutItem`, `Query` only. No `dynamodb:*`, no
   `logs:*`, no bare `*`.
2. Resources are scoped to the table ARN and `…/index/GSI1`; log access is scoped to the
   function's own log group ARN.
3. Actions the application does not perform are **omitted** — no `Scan`, `UpdateItem`,
   `DeleteItem`, `BatchWriteItem` or `CreateLogGroup`. A future change that needs one fails
   with `AccessDenied`, forcing the permission through review instead of letting it arrive
   silently.
4. Explicit `Deny` on the large-blast-radius actions (`Scan`, `DeleteItem`,
   `BatchWriteItem`, `DeleteTable`, `UpdateTable`, `ExportTableToPointInTime`, …) and on
   credential/policy self-modification (`iam:PutRolePolicy`, `iam:PassRole`,
   `sts:AssumeRole`, `kms:ScheduleKeyDeletion`, `logs:DeleteLogGroup`,
   `logs:PutRetentionPolicy`, …). An explicit Deny cannot be overridden by any Allow.
5. A **permissions boundary** caps the role, so a change-management failure cannot widen
   it beyond the ceiling.
6. KMS grants are constrained by a `kms:ViaService` condition.
7. The trust policy restricts `lambda.amazonaws.com` with a source-ARN style confused-deputy
   guard.
8. Policies are committed as JSON templates in `policies/` rather than rendered only at
   plan time, so **CI runs the project's own IAM analyzer against the policy that actually
   deploys** — there is no hand-maintained copy to drift.

**Recommended further safeguards.** A separate membership table so the role can hold
read-only rights to it (see T-06); IAM Access Analyzer policy validation in CI once an
AWS account is available.

**Verification.** `security-automation/iam_policy_checker.py` run against
`infrastructure/terraform/policies/` in CI stage 3 and in `scripts/run_security_checks.sh`.
Verified run on 2026-10-23: **1 INFO finding, 0 blocking** (`IAM003` /
`needs_context`, on the X-Ray policy where the actions genuinely do not support resource
scoping). The gate's own self-test confirms the insecure fixture in `sample-data/` is
rejected. Live IAM enforcement is an AWS-gated test and is **unverified** here.

**Residual risk — Low.**

---

## 4. Threats considered and discarded

Documented so the analysis is auditable rather than selectively reported.

| Candidate | Why discarded |
|---|---|
| SQL injection | No SQL. DynamoDB access uses the `boto3.dynamodb.conditions` key-expression builder, never string-built expressions. |
| Server-side template injection / XSS | The API returns `application/json` only, never renders templates, and sets `X-Content-Type-Options: nosniff` plus a `default-src 'none'` CSP. Any HTML rendering risk belongs to the (out-of-scope) client. |
| CSRF | No cookie-based authentication; the credential is an `Authorization` header, which a cross-site form cannot set. CORS is empty by default and never `*` with credentials. |
| Insecure deserialization | No `pickle`, `yaml.load`, `eval` or `exec` anywhere in the application. Input is parsed as JSON into Pydantic models. Confirmed by Bandit (0 medium+ findings) and by review. |
| Path traversal | No filesystem access in any request path. |
| SSRF | The application makes no outbound HTTP requests. |
| Dependency confusion / typosquatting | Dependencies come from PyPI with `pip-audit` in CI; no private index is configured, so there is no public/private resolution order to confuse. Lower-bound pinning is a known gap (see L4). |
| Secrets in source | No secrets exist in the design: Cognito issues tokens, there is no shared API key, and Terraform uses no secret variables. Scanned by Bandit and the custom Terraform linter's credential pattern check. |
| Compromise of AWS-managed infrastructure (Cognito signing keys, KMS, DynamoDB) | Out of scope: accepted as part of the shared-responsibility model. |
