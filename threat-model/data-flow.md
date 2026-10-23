# Data-Flow Analysis

Companion to [`architecture.md`](architecture.md). This document traces each flow that
crosses a trust boundary, states what is trusted at each hop, and names the file that
enforces it. The STRIDE analysis in [`threat-model.md`](threat-model.md) is derived from
these flows.

---

## 1. Primary request flow (authenticated read)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as API Gateway<br/>+ JWT authorizer
    participant L as Lambda / FastAPI
    participant I as identity.py
    participant M as MembershipRepository
    participant A as authorization.py
    participant R as TicketRepository
    participant D as DynamoDB
    participant W as CloudWatch Logs

    C->>G: GET /v1/tickets/{id}<br/>Authorization: Bearer <JWT>
    Note over G: TB1 — signature vs JWKS,<br/>issuer, audience/client_id, exp
    G--xC: 401 if invalid/expired/absent<br/>(request never reaches Lambda)
    G->>L: AWS_PROXY v2 event<br/>requestContext.authorizer.jwt.claims
    Note over L,I: TB2 — ONLY the authorizer context is trusted.<br/>Headers/body/query are attacker-controlled.
    L->>I: extract(request)
    I->>I: read sub + custom:organization_id
    I->>M: get_membership(user_id, organization_id)
    M->>D: GetItem PK=USER#{user} SK=MEMBERSHIP#{org}
    D-->>M: membership record (or none)
    alt no record, or status != active
        I->>W: event_type=authorization_denied<br/>reason=no_membership / membership_inactive
        I--xC: 403 (generic message)
    end
    I-->>L: Principal(user_id, organization_id, role from RECORD)
    Note over I: Token's custom:role is advisory only.<br/>Mismatch logs role_claim_mismatch.
    L->>R: get_ticket(principal.organization_id, ticket_id)
    Note over R,D: TB4 — PK is derived from the verified<br/>principal, never from client input
    R->>D: GetItem PK=TENANT#{org} SK=TICKET#{id}
    D-->>R: item or None
    alt None
        R-->>L: None
        L->>W: event_type=resource_not_found
        L--xC: 404 — identical for "absent" and "another tenant's"
    end
    L->>A: authorize_read_ticket(principal, ticket)
    A-->>L: Decision(allowed, reason)
    alt denied
        L->>W: event_type=authorization_denied<br/>reason=read:not_ticket_owner
        L--xC: 403 (generic message)
    end
    L->>W: event_type=ticket_read, outcome=allowed<br/>(identifiers only — no ticket content)
    L-->>C: 200 + ticket JSON<br/>+ security headers + X-Request-Id
```

### What is trusted where

| Hop | Input | Trusted? | Why / enforcement |
|---|---|---|---|
| C → G | bearer token | no | Gateway validates it (TB1) |
| G → L | `requestContext.authorizer.jwt.claims` | **yes** | Gateway-verified; `app/security/identity.py` reads only this |
| G → L | headers, query, body | **no** | Never an identity source; body is schema-validated with `extra="forbid"` |
| I → M | `user_id`, `organization_id` from claims | yes (as identifiers) | Used as *lookup keys*, not as authorization conclusions |
| M → I | membership record | **authoritative** | Server-side state; the role decision source (F-002) |
| L → R | `principal.organization_id` | yes | Derived from verified identity; becomes the partition key |
| R → D | key condition | — | Keys built by `repositories/keys.py`, which rejects `#` in identifiers (F-011) |

---

## 2. Write flow (create) — where tenancy is decided

```mermaid
flowchart LR
    A["POST /v1/tickets<br/>{title, description, priority}"] --> B{"TicketCreateRequest<br/>extra=forbid"}
    B -->|"unknown field<br/>(e.g. organization_id)"| R1["422 invalid_request<br/>values NOT echoed back"]
    B -->|valid| C["TicketService.create_ticket"]
    C --> D["organization_id ← principal<br/>created_by ← principal<br/>ticket_id ← uuid4()<br/>status ← open"]
    D --> E["PutItem<br/>ConditionExpression:<br/>attribute_not_exists(PK) AND attribute_not_exists(SK)"]
    E --> F[("DynamoDB")]
    D --> G["log: ticket_created<br/>ids only"]

    classDef reject fill:#fde2e2,stroke:#b42318,color:#1a1a1a
    classDef ok fill:#e4f5e9,stroke:#067647,color:#1a1a1a
    class R1 reject
    class D,E ok
```

The three fields an attacker would want to control — `organization_id`, `created_by`,
`ticket_id` — are **absent from the request model**. There is no code path from request
body to any of them. With `extra="forbid"`, attempting to supply one is a 422 rather
than a silently-dropped field.

> The pre-review implementation did the opposite: `TicketCreateRequest` declared an
> optional `organization_id`, and the service used
> `payload.organization_id or principal.organization_id`. That let any authenticated user
> **write a ticket into another tenant's partition**. Recorded as **F-004**; regression
> test: `tests/security/test_tenant_isolation.py::test_create_cannot_target_another_tenant_via_request_body`.

---

## 3. List flow — role decides the query, not a filter

```mermaid
flowchart TD
    A["GET /v1/tickets?limit&cursor"] --> B{"limit bounded 1..100<br/>(ge/le at the edge)"}
    B -->|out of range| E1["422"]
    B -->|ok| C["decode_cursor(cursor,<br/>organization_id=principal.organization_id)"]
    C -->|"PK != TENANT#{my org}"| E2["400 invalid_request<br/>store never called"]
    C -->|"malformed / oversized /<br/>unexpected attributes"| E2
    C -->|valid or absent| D{"principal.is_admin?"}
    D -->|yes| F["Query base table<br/>PK = TENANT#org<br/>SK begins_with TICKET#"]
    D -->|no| G["Query GSI1<br/>GSI1PK = TENANT#org#USER#user"]
    F --> H[("DynamoDB")]
    G --> H
    H --> I["page_size = min(limit, MAX_PAGE_SIZE)<br/>re-clamped in the repository"]
    I --> J["encode_cursor(LastEvaluatedKey)<br/>allow-listed key attributes only"]

    classDef reject fill:#fde2e2,stroke:#b42318,color:#1a1a1a
    class E1,E2 reject
```

Two properties worth naming:

1. **A member's listing is narrowed in the key condition, not after the fact.** Coworkers'
   tickets are never read from the database — not read, not billed, not held in memory.
   The pre-review version used `Scan` with a `FilterExpression` (**F-006**).
2. **The cursor is client-controlled input.** `LastEvaluatedKey` is a plain dict; a
   base64 cursor can be decoded, edited to point at another tenant's partition, and
   re-sent. `decode_cursor` therefore requires `PK == TENANT#{caller's org}` (**F-010**),
   and the repository re-validates any key handed to it directly.

---

## 4. Error and log flow (what leaves the system)

```mermaid
flowchart LR
    subgraph app["Lambda"]
        X["Exception raised"] --> H{"handler in main.py"}
        H --> Y["Client response:<br/>{error, message, request_id}<br/>+ fields[] for 422<br/>no trace, no exception text"]
        H --> Z["Log record:<br/>event_type, outcome, reason,<br/>ids, http_*, exception trace"]
    end
    Z --> F["JsonFormatter<br/>ALLOWED_LOG_FIELDS allow-list"]
    F -->|"non-allow-listed field<br/>dropped"| DROP["(discarded)"]
    F --> CW[("CloudWatch Logs<br/>TB5")]
    Y --> C["Client"]
    CW --> MF["Metric filters"] --> AL["Alarms"] --> SNS["SNS"]

    classDef drop fill:#f2f2f2,stroke:#888,color:#555
    class DROP drop
```

The split is deliberate and is the right way round: **the operator gets the diagnostics,
the caller gets a sentence.** The correlation key is `X-Request-Id`, returned on every
response and present on every log record.

The pre-review implementation returned `str(exc)` and `traceback.format_exc()` in the 500
body (**F-008**) and logged whole request payloads and the `Authorization` header
(**F-007**).

---

## 5. Cross-boundary flow summary

| Flow | From → To | Boundary | Primary risk | Control | Enforced in |
|---|---|---|---|---|---|
| DF1 | Client → Gateway | TB1 | Spoofing, DoS | JWT validation, throttling, TLS | `api.tf` |
| DF2 | Gateway → Lambda | TB2 | Identity spoofing via headers | Claims-only identity source | `security/identity.py` |
| DF3 | Lambda → Membership record | TB3 | Privilege escalation via token claim | Role from server-side record | `security/identity.py`, `repositories/membership_repository.py` |
| DF4 | Lambda → Tickets | TB3/TB4 | Cross-tenant read/write | Partition key from principal; GSI1; no `Scan`; explicit IAM `Deny` | `repositories/ticket_repository.py`, `policies/lambda-execution.json` |
| DF5 | Client body → Storage | TB2 | Mass assignment | `extra="forbid"`; server-set fields absent from request models | `models/ticket.py` |
| DF6 | Client cursor → Query | TB2/TB4 | Cross-tenant pagination | Cursor bound to caller's partition | `repositories/pagination.py` |
| DF7 | Lambda → Logs | TB5 | Sensitive-data exposure | Field allow-list, static messages, truncation | `observability/logging.py` |
| DF8 | Lambda → Client (errors) | TB2 | Information disclosure | Uniform envelope; 404 for cross-tenant; no values echoed | `main.py` |
| DF9 | CI → AWS | TB6 | Unreviewed infrastructure change | Branch protection, OIDC, security gates | `.github/workflows/security-ci.yml` |
| DF10 | Security Hub → Triage Lambda *(optional)* | TB3 | Malformed event / log injection | Schema-tolerant parsing, no finding content logged | `infrastructure/modules/security_hub_triage/src/handler.py` |
