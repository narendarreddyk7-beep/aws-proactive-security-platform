# Security Requirements

Derived from the threats in [`threat-model.md`](threat-model.md) and mapped to OWASP ASVS
4.0.3, the OWASP API Security Top 10 (2023) and the OWASP Top 10 (2021).

Each requirement is **testable**. The "Verified by" column names the test or tool run that
demonstrates it; `AWS-gated` means the requirement is implemented but can only be
demonstrated against a live deployment, and the corresponding test is present and
explicitly skipped rather than silently absent.

| State | Meaning |
|---|---|
| ✅ Verified | Implemented and demonstrated by a passing automated check in this environment |
| 🟡 AWS-gated | Implemented in configuration; verification needs a deployed AWS environment |
| ⬜ Not implemented | Identified, not built. Recorded as residual risk |

---

## 1. Authentication (SR-A)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-A1 | Every endpoint except `GET /v1/health` requires a verified authenticated identity. | T-01 | ASVS 2.1.1, API2:2023 | `tests/security/test_authentication.py` | ✅ |
| SR-A2 | JWT signature, issuer, audience and expiry are validated **before** the request reaches application code. | T-02, T-03 | ASVS 3.5.2, API2:2023 | `api.tf` review; `test_aws_gateway_contract.py` | 🟡 |
| SR-A3 | Identity is read only from `requestContext.authorizer.jwt.claims`. No header, query parameter, cookie or body field is ever an identity source. | T-01 | ASVS 2.1.1, A01:2021 | `tests/security/test_authentication.py`, `tests/unit/test_authorization.py` | ✅ |
| SR-A4 | A REQUEST/Lambda authorizer context (`authorizer.lambda`) is **not** accepted as a substitute for JWT validation. | T-01, T-03 | ASVS 3.5.2 | `tests/security/test_authentication.py` | ✅ |
| SR-A5 | Missing, malformed, expired or wrongly-issued credentials are rejected with 401 and no detail about why. | T-01, T-10 | ASVS 7.4.1, API2:2023 | `tests/security/test_authentication.py`, `test_error_handling.py` | ✅ |
| SR-A6 | The local test identity adapter cannot load outside `environment=local`, enforced independently at config load and at construction. | T-01 | ASVS 14.1.3, A05:2021 | `tests/unit/test_config.py`, `tests/security/test_authentication.py` | ✅ |
| SR-A7 | The secure identity source is the **default**, so an unset environment variable is safe. | T-01 | ASVS 14.1.3 | `tests/unit/test_config.py` | ✅ |
| SR-A8 | Enabling the insecure adapter emits an alarmable security event. | T-01 | ASVS 7.1.3 | `tests/security/test_authentication.py`; `monitoring.tf` | ✅ |
| SR-A9 | Password policy, optional MFA and advanced security mode are configurable at the user pool, with production defaults stronger than development. | T-02 | ASVS 2.1, 2.2 | `cognito.tf`; `environments/*/terraform.tfvars` | 🟡 |
| SR-A10 | Access-token lifetime is bounded and configurable. | T-02 | ASVS 3.3 | `cognito.tf` review | 🟡 |

## 2. Authorization and tenant isolation (SR-Z)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-Z1 | The caller's role is resolved from a server-side membership record, never from a token claim. | T-14 | ASVS 4.1.1, API5:2023 | `tests/security/test_authorization_policy.py` | ✅ |
| SR-Z2 | Membership must exist **and** be active; a revoked membership denies immediately rather than at token expiry. | T-14 | ASVS 4.1.1 | `tests/security/test_authentication.py` | ✅ |
| SR-Z3 | A mismatch between the token's role claim and the membership record is logged as a security event; the record wins. | T-06, T-14 | ASVS 7.1.3 | `tests/unit/test_logging_and_context.py`; `monitoring.tf` | ✅ |
| SR-Z4 | Every protected data operation makes an **explicit** authorization decision and enforces it. No operation relies on having reached the code path. | T-15 | ASVS 4.1.3, API1:2023 | `tests/unit/test_authorization.py`, `tests/unit/test_ticket_service.py` | ✅ |
| SR-Z5 | A member may read and update only tickets they created; an administrator may act on any ticket **in their own organization**. | T-15 | ASVS 4.1.3, API1:2023 | `tests/security/test_authorization_policy.py` | ✅ |
| SR-Z6 | Closing a ticket requires the administrator role, and `closed` is terminal. | T-08, T-15 | ASVS 4.1.3 | `tests/security/test_authorization_policy.py` | ✅ |
| SR-Z7 | The organization identifier used for data access is derived from the verified principal and can never come from client input. | T-04, T-09 | ASVS 4.2.1, API1:2023 | `tests/security/test_tenant_isolation.py`, `test_data_access_scoping.py` | ✅ |
| SR-Z8 | No read path uses `Scan`; every read is key-scoped to the caller's partition. | T-09 | ASVS 4.2.1 | `tests/security/test_data_access_scoping.py` | ✅ |
| SR-Z9 | A member's listing is narrowed in the key condition (GSI1), not by filtering results after reading them. | T-09 | ASVS 4.2.1 | `tests/security/test_data_access_scoping.py` | ✅ |
| SR-Z10 | A cross-tenant resource request is indistinguishable from a non-existent one (both 404). | T-10 | ASVS 4.2.1, API1:2023 | `tests/security/test_tenant_isolation.py::test_cross_tenant_denial_does_not_disclose_existence` | ✅ |
| SR-Z11 | Pagination cursors are validated against the caller's own partition before use, at both the service and repository layers. | T-05 | ASVS 4.2.1, API3:2023 | `tests/security/test_tenant_isolation.py` | ✅ |
| SR-Z12 | Denial messages returned to clients are generic and identical; the machine-readable reason is logged, not returned. | T-10 | ASVS 7.4.1 | `tests/security/test_error_handling.py` | ✅ |
| SR-Z13 | Authorization policy is pure and testable without HTTP, so the full role × operation matrix can be asserted. | T-15 | ASVS 4.1.5 | `tests/unit/test_authorization.py` | ✅ |

## 3. Input validation and data integrity (SR-V)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-V1 | All request models reject unknown fields (`extra="forbid"`). | T-04 | ASVS 5.1.1, API6:2023 | `tests/security/test_input_validation.py` | ✅ |
| SR-V2 | `organization_id`, `created_by`, `ticket_id`, `status` and timestamps are absent from create request models and unwritable on update. | T-04 | ASVS 5.1.2, API3:2023 | `tests/security/test_tenant_isolation.py` | ✅ |
| SR-V3 | `ticket_id` is validated as a UUID at the HTTP edge. | T-05 | ASVS 5.1.3 | `tests/security/test_input_validation.py` | ✅ |
| SR-V4 | Identifiers used in key construction are rejected if empty or containing the `#` separator. | T-05 | ASVS 5.1.3 | `tests/unit/test_models_and_keys.py` | ✅ |
| SR-V5 | Page size is bounded at the HTTP edge **and** independently in the repository. | T-12 | ASVS 5.1.2, API4:2023 | `tests/security/test_input_validation.py` | ✅ |
| SR-V6 | String fields have explicit maximum lengths chosen against the DynamoDB item limit. | T-12 | ASVS 5.1.2 | `tests/security/test_input_validation.py` | ✅ |
| SR-V7 | Enumerated fields accept only declared values. | T-04 | ASVS 5.1.3 | `tests/security/test_input_validation.py` | ✅ |
| SR-V8 | An update that changes nothing is rejected, so the audit trail carries no non-events. | T-07 | ASVS 7.1.1 | `tests/unit/test_models_and_keys.py` | ✅ |
| SR-V9 | Ticket status changes follow a declared state machine; illegal transitions return 409. | T-08 | ASVS 11.1.1 | `tests/security/test_authorization_policy.py` | ✅ |
| SR-V10 | Creates and updates use conditional writes so a record is never silently replaced or resurrected. | T-08 | ASVS 11.1.2 | `tests/integration/test_dynamodb_repository.py` | ✅ |
| SR-V11 | Validation errors identify the field and reason but never echo the submitted value. | T-10, T-11 | ASVS 7.4.1 | `tests/security/test_error_handling.py` | ✅ |

## 4. Error handling and information disclosure (SR-E)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-E1 | One error envelope for every failure: `{error, message, request_id}` plus `fields` for 422. | T-10 | ASVS 7.4.1 | `tests/security/test_error_handling.py` | ✅ |
| SR-E2 | No response body ever contains a stack trace, exception text, module path or library name. | T-10 | ASVS 7.4.1, A05:2021 | `tests/security/test_error_handling.py` | ✅ |
| SR-E3 | Unhandled exceptions return a fixed sentence and log the full trace server-side. | T-10 | ASVS 7.4.1 | `tests/security/test_error_handling.py` | ✅ |
| SR-E4 | Framework 404/405/415 responses are normalised into the same envelope. | T-10 | ASVS 7.4.1 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-E5 | Interactive API documentation is disabled outside local development. | T-10 | ASVS 14.3.3 | `tests/unit/test_config.py` | ✅ |
| SR-E6 | The server does not advertise its framework or version in response headers. | T-10 | ASVS 14.3.3 | `tests/security/test_api_behaviour.py` | ✅ |

## 5. Logging, monitoring and auditability (SR-L)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-L1 | Logs are structured JSON, one object per line, queryable by field. | T-07 | ASVS 7.1.3 | `tests/unit/test_logging_and_context.py` | ✅ |
| SR-L2 | Only allow-listed fields can be rendered; anything else is dropped even if passed by a developer. | T-11 | ASVS 8.3.4, A09:2021 | `tests/security/test_logging_and_data_protection.py` | ✅ |
| SR-L3 | Ticket titles and descriptions never appear in logs. | T-11 | ASVS 8.3.4 | `tests/security/test_logging_and_data_protection.py::test_ticket_content_is_never_logged` | ✅ |
| SR-L4 | Tokens, the `Authorization` header and passwords never appear in logs. | T-11 | ASVS 7.1.1 | `tests/security/test_logging_and_data_protection.py` | ✅ |
| SR-L5 | Updates log changed field **names** only, never values. | T-11 | ASVS 8.3.4 | `tests/security/test_logging_and_data_protection.py` | ✅ |
| SR-L6 | Every authentication failure and authorization denial emits a security event with actor, target and machine-readable reason. | T-07 | ASVS 7.1.3, A09:2021 | `tests/security/test_logging_and_data_protection.py` | ✅ |
| SR-L7 | A client-supplied `X-Request-Id` is honoured only when it matches a strict bounded pattern; otherwise one is generated. | T-07 | ASVS 7.1.1 | `tests/unit/test_logging_and_context.py` | ✅ |
| SR-L8 | Log records cannot be forged by newline injection. | T-07 | ASVS 7.1.1, CWE-117 | `tests/unit/test_logging_and_context.py` | ✅ |
| SR-L9 | The request id is returned on every response, including errors, for correlation. | T-07 | ASVS 7.1.4 | `tests/security/test_logging_and_data_protection.py` | ✅ |
| SR-L10 | Metric filters and alarms exist for authorization denials, role-claim mismatches, insecure-adapter activation, unhandled errors, gateway 401/403s, and Lambda/DynamoDB throttles. | T-07, T-13 | ASVS 7.2.1 | `monitoring.tf` review | 🟡 |
| SR-L11 | Log groups have an explicit retention period and are encrypted with a customer-managed key. | T-11 | ASVS 7.1.1 | `monitoring.tf`; Checkov | 🟡 |
| SR-L12 | Logs are append-only and tamper-evident. | T-07 | ASVS 7.3.3 | — | ⬜ |

## 6. Transport and HTTP security (SR-H)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-H1 | Security headers are applied to every response, including errors raised outside the middleware stack. | T-10 | ASVS 14.4 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-H2 | `Cache-Control: no-store` on every response, so no intermediary retains one tenant's data. | T-09 | ASVS 14.4.2 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-H3 | A restrictive CSP (`default-src 'none'`) is applied to API responses. | T-10 | ASVS 14.4.3 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-H4 | CORS is empty by default; a wildcard origin with credentials is never configured. | T-02 | ASVS 14.5.3 | `tests/unit/test_config.py` | ✅ |
| SR-H5 | Only the HTTP methods the API implements are routed; others return a normalised 405. | T-10 | ASVS 14.4.1 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-H6 | No implicit trailing-slash redirects, so the effective route is unambiguous. | T-10 | ASVS 14.4.1 | `tests/security/test_api_behaviour.py` | ✅ |
| SR-H7 | TLS is terminated at API Gateway with a current policy; no plaintext listener exists. | T-02 | ASVS 9.1.1 | `api.tf` review | 🟡 |
| SR-H8 | A development server binds to loopback by default, never `0.0.0.0`. | T-13 | ASVS 14.1.1, CWE-605 | Bandit (B104), code review | ✅ |

## 7. Cloud and infrastructure security (SR-C)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-C1 | The Lambda execution role enumerates actions; no `*` action and no service-wide wildcard. | T-16 | ASVS 1.2.2 | `iam_policy_checker.py` in CI | ✅ |
| SR-C2 | Data-plane permissions are scoped to the table ARN and its GSI; log permissions to the function's own log group. | T-16 | ASVS 1.2.2 | `iam_policy_checker.py` | ✅ |
| SR-C3 | Actions the application does not perform are omitted, so a new need fails closed and goes through review. | T-16 | ASVS 1.2.2 | Policy review; `policies/lambda-execution.json` | ✅ |
| SR-C4 | Explicit `Deny` on `dynamodb:Scan`, destructive table operations, and credential/policy self-modification. | T-06, T-16 | ASVS 1.2.2 | `policies/lambda-execution.json` | ✅ |
| SR-C5 | A permissions boundary caps the execution role. | T-16 | ASVS 1.2.2 | `iam.tf` | ✅ |
| SR-C6 | `AdministratorAccess` and equivalent are never used. | T-16 | ASVS 1.2.2 | `iam_policy_checker.py` (rule IAM001) | ✅ |
| SR-C7 | The role trust policy constrains the service principal against confused-deputy abuse. | T-16 | ASVS 1.2.2 | `iam_policy_checker.py` (rules IAM007, IAM008) | ✅ |
| SR-C8 | DynamoDB is encrypted at rest and has point-in-time recovery. | T-06 | ASVS 6.1.1 | Checkov; `dynamodb.tf` | ✅ |
| SR-C9 | Lambda environment variables are encrypted with a customer-managed key. | T-11 | ASVS 6.1.1 | Checkov; `lambda.tf` | ✅ |
| SR-C10 | KMS key rotation is enabled and the key policy grants only what is needed, condition-constrained. | T-16 | ASVS 6.2.1 | Checkov; `main.tf` | ✅ |
| SR-C11 | No resource is publicly accessible; no public S3, no unauthenticated data path other than `/v1/health`. | T-09 | ASVS 1.2.1 | Checkov; `api.tf` | ✅ |
| SR-C12 | Lambda has a bounded timeout, bounded memory and reserved concurrency. | T-13 | ASVS 1.2.2 | `lambda.tf` | ✅ |
| SR-C13 | API Gateway stage throttling is configured. | T-13 | ASVS 1.2.2, API4:2023 | `api.tf` | ✅ |
| SR-C14 | All resources are tagged with project, environment and ownership. | — | ASVS 1.1.1 | Custom Terraform linter; `main.tf` | ✅ |
| SR-C15 | No secrets, account identifiers or credentials in Terraform source. | — | ASVS 14.1.3, A05:2021 | Custom Terraform linter (TF011, credential patterns); Bandit | ✅ |
| SR-C16 | Development and production configurations are separated, with the posture difference explicit. | — | ASVS 14.1.1 | `environments/dev|prod/terraform.tfvars` | ✅ |
| SR-C17 | Optional and paid services are disabled by default. | — | — | `variables.tf` defaults; `security_hub.tf` | ✅ |
| SR-C18 | Infrastructure can be destroyed cleanly with no orphaned resources. | — | — | Documented in `docs/AWS_DEPLOYMENT.md` | 🟡 |
| SR-C19 | Terraform state is encrypted, access-controlled and locked. | — | ASVS 1.1.1 | `backend.tf.example`; documented | 🟡 |
| SR-C20 | Per-tenant hard isolation (separate table or account) for customers who require it. | T-06, T-13 | — | — | ⬜ |

## 8. Secure SDLC and supply chain (SR-S)

| ID | Requirement | Threat | ASVS / OWASP | Verified by | State |
|---|---|---|---|---|---|
| SR-S1 | Static analysis (Bandit + Ruff `S` rules) runs on every pull request and gates on medium severity and above. | — | ASVS 14.2.1 | `.github/workflows/security-ci.yml`; local run 2026-10-23 | ✅ |
| SR-S2 | Semantic code scanning (CodeQL) runs on every pull request. | — | ASVS 14.2.1 | `.github/workflows/security-ci.yml` | 🟡 |
| SR-S3 | Dependency vulnerability scanning (`pip-audit`) runs on every pull request against runtime and dev trees. | — | ASVS 14.2.1, A06:2021 | Local run: 21 packages, 0 vulnerabilities | ✅ |
| SR-S4 | Infrastructure-as-code scanning (Checkov) runs on every pull request. | — | ASVS 14.2.1 | Local run: 134 passed, 0 failed, 12 justified skips | ✅ |
| SR-S5 | The project's own IAM analyzer gates the policy documents that actually deploy. | T-16 | ASVS 1.2.2 | Local run: 0 blocking findings | ✅ |
| SR-S6 | Every confirmed security finding has a regression test that fails against the vulnerable code. | — | ASVS 14.2.1 | `assessments/regression-evidence.md` | ✅ |
| SR-S7 | Security findings are never auto-suppressed to make CI pass; a suppression is a targeted, justified, reviewable exception. | — | ASVS 14.2.1 | 12 inline Checkov skips, each with a written justification | ✅ |
| SR-S8 | CI uses least-privilege `GITHUB_TOKEN` permissions and pinned action references. | — | ASVS 14.1.4 | `.github/workflows/security-ci.yml` | ✅ |
| SR-S9 | No long-lived AWS credentials in source control or CI; deployment uses OIDC. | — | ASVS 14.1.4 | `.gitignore`; documented in `docs/AWS_DEPLOYMENT.md` | ✅ |
| SR-S10 | Unreviewed pull requests cannot deploy, and third-party pull requests do not execute with secrets. | — | ASVS 14.1.4 | `.github/workflows/security-ci.yml` (`pull_request` trigger, no deploy job) | ✅ |
| SR-S11 | Dependencies are pinned to exact versions in a lock file for reproducible builds. | — | ASVS 14.2.4 | — | ⬜ |

---

## 9. Coverage summary

| Area | Verified ✅ | AWS-gated 🟡 | Not implemented ⬜ | Total |
|---|---|---|---|---|
| Authentication | 6 | 4 | 0 | 10 |
| Authorization & tenancy | 13 | 0 | 0 | 13 |
| Input validation | 11 | 0 | 0 | 11 |
| Error handling | 6 | 0 | 0 | 6 |
| Logging & monitoring | 9 | 2 | 1 | 12 |
| Transport & HTTP | 7 | 1 | 0 | 8 |
| Cloud & infrastructure | 15 | 3 | 2 | 20 |
| Secure SDLC | 9 | 1 | 1 | 11 |
| **Total** | **76** | **11** | **4** | **91** |

The four unimplemented requirements (SR-L12 tamper-evident logs, SR-C20 per-tenant hard
isolation, SR-S11 lock file, and the membership-table split behind SR-C4/T-06) are carried
as residual risk in [`risk-register.csv`](risk-register.csv) and prioritised in
[`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md).
