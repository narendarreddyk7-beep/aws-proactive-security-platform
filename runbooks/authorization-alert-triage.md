# Runbook A — Suspicious Authentication or Authorization Activity

| | |
|---|---|
| **Runbook ID** | RB-A |
| **Severity range** | SEV-4 → SEV-1 (classified in step 4) |
| **Intended responder** | On-call engineer, any level. Steps 1–5 are safe to perform alone; **step 6 onward requires senior oversight** |
| **Expected time to initial classification** | 15 minutes |
| **Last reviewed** | 2026-10-23 |

---

## 1. Purpose

Triage alarms indicating that someone is being denied access repeatedly, that a token
disagrees with our own records, or that the insecure local identity adapter has activated.

The question this runbook answers is narrow and specific:

> **Is this a misconfigured client, or is somebody probing the tenant boundary?**

Those two have very different responses, and the cost of confusing them runs both ways —
paging a customer-success team for a broken SDK retry loop wastes a night, and dismissing a
real cross-tenant probe as "just a bad client" is how breaches get found by someone else
first.

**This runbook is defensive.** It covers observation, classification, containment and
recovery. It does not include offensive techniques, and it must not be used to access any
tenant's ticket content beyond what the identifiers in the log records already show.

---

## 2. Triggering conditions

| Alarm | Metric | Default threshold | What it means |
|---|---|---|---|
| `<prefix>-authorization-denied-burst` | `AuthorizationDenied` | **dev 3**, **prod 25** per 5 min | A principal is being refused access to objects. The most security-relevant alarm here |
| `<prefix>-role-claim-mismatch` | `RoleClaimMismatch` | **5** per 5 min | A token's `custom:role` disagrees with the membership record. The record wins, but a burst means stale tokens — or someone editing claims |
| `<prefix>-insecure-identity-adapter` | `InsecureIdentityAdapterEnabled` | **1** per 60 s | **Treat as SEV-1 immediately.** The local-development authentication bypass has been constructed in a deployed environment. This should be impossible (three independent guards) |
| `<prefix>-gateway-unauthorized-burst` | `GatewayUnauthorized` (401s) | per environment | Credential stuffing, an expired-token storm, or a scanner |
| Manual | — | — | A customer reports seeing data that is not theirs. **Go straight to step 4 and classify SEV-1** |

Metric namespace: `SupportPlatform/<environment>`. Alarms publish to the SNS topic
`<prefix>-security-alarms`.

---

## 3. Required log sources

| Source | Name | Use |
|---|---|---|
| Application logs | `/aws/lambda/<prefix>-api` | Authorization decisions, denial reasons, principal and org ids |
| API access logs | `/aws/apigateway/<prefix>-access` | Gateway-level 401/403, source IP, route, latency |
| Saved Insights queries | `<prefix>/authorization-denials-by-principal`, `<prefix>/cross-tenant-probe-candidates`, `<prefix>/request-trace`, `<prefix>/unhandled-errors-by-type` | Pre-written, use these first |
| CloudTrail | management events | Only if step 6 suggests control-plane activity |

### What the logs will and will not tell you

**Will:** which principal, which organization, which ticket id, the machine-readable
reason, the request id, the HTTP method and path, and the outcome.

**Will not:** ticket titles or descriptions, tokens, email addresses, or the values
submitted in a failed request. That is deliberate (finding F-007) — customer content is
excluded from logs by a field allow-list. **Do not attempt to retrieve ticket content to
"complete the picture".** The identifiers are sufficient for triage, and reading customer
data during an investigation needs its own authorization.

---

## 4. Initial verification — first 15 minutes

Work through these in order. Do not skip to containment.

### Step 4.1 — Confirm the alarm is real, not a deployment artefact

```bash
# Was anything deployed in the last hour? A deploy can produce a denial burst
# legitimately (e.g. clients holding tokens from a pool that was just replaced).
aws lambda get-function --function-name <prefix>-api \
  --query 'Configuration.LastModified'
```

If a deployment coincides with the alarm, note it — but **continue anyway**. A deployment
window is a convenient cover, not an exoneration.

### Step 4.2 — Identify the principals involved

Run the saved query `<prefix>/authorization-denials-by-principal`:

```
fields @timestamp, principal_id, organization_id, resource_id, reason
| filter event_type = "authorization_denied"
| stats count(*) as denials by principal_id, organization_id, reason
| sort denials desc
| limit 50
```

**Read the shape of the result, not just the total:**

| Shape | Most likely meaning |
|---|---|
| **One** principal, **one** `reason`, high count | Misconfigured client or a retry loop. Usually benign |
| **One** principal, **many** distinct `resource_id`s | **Identifier enumeration.** Escalate |
| **Many** principals, same organization | A broken client release, or a membership provisioning failure |
| **Many** principals, many organizations | Platform-wide problem, or a distributed probe |
| `reason = no_membership` or `membership_inactive` | Someone holds a valid token for an org they are not a member of. Could be a revoked user with a live token — or a token minted elsewhere (threat T-03) |
| `reason = read:not_ticket_owner` / `update:not_ticket_owner` | A member reaching for a colleague's ticket. Could be a UI bug or a curious insider |
| `reason = privileged_status_requires_admin` | A member trying to close tickets. Usually a UI that shows the wrong control |

### Step 4.3 — Check for cross-tenant probing

This is the most important query in this runbook. Run
`<prefix>/cross-tenant-probe-candidates`:

```
fields @timestamp, principal_id, organization_id, resource_id
| filter event_type = "resource_not_found"
| stats count(*) as misses, count_distinct(resource_id) as distinct_ids by principal_id
| filter misses > 20
| sort misses desc
| limit 50
```

**Why this query exists.** The API deliberately returns **404 for both** "this ticket does
not exist" and "this ticket belongs to another organization" (finding F-008), so there is
no 403 to count. A principal generating many `resource_not_found` events with many
**distinct** `resource_id`s is walking identifiers — and this query is the signal that
replaces the 403 the API intentionally does not return.

> `misses` high with `distinct_ids` **low** → a client retrying one deleted ticket. Benign.
> `misses` high with `distinct_ids` **high** → enumeration. **Escalate.**

### Step 4.4 — Correlate with the gateway logs

```
# log group: /aws/apigateway/<prefix>-access
fields @timestamp, status, httpMethod, routeKey, sourceIp, requestId
| filter status in [401, 403]
| stats count(*) as attempts, count_distinct(routeKey) as routes by sourceIp
| sort attempts desc
| limit 50
```

A single source IP across many principals suggests credential stuffing. One principal
across many source IPs suggests a shared or stolen token (threat T-02).

### Step 4.5 — Trace one request end to end

Pick a representative `request_id` and run `<prefix>/request-trace`. Every log record for a
request carries the same `request_id`, and it is returned to the client in the
`X-Request-Id` header — so a customer report can be tied to exact log lines.

---

## 5. Investigation checklist

Tick every item before classifying. Record each answer in the incident ticket.

- [ ] Alarm name, firing time, and the metric value that breached
- [ ] Deployment or configuration change in the preceding hour? (yes/no + detail)
- [ ] Distinct `principal_id` count involved
- [ ] Distinct `organization_id` count involved
- [ ] Dominant `reason` value(s)
- [ ] Distinct `resource_id` count per principal — **the enumeration indicator**
- [ ] Source IP distribution from the gateway log
- [ ] Any `role_claim_mismatch` events for the same principals? (indicates a stale or
      manipulated token)
- [ ] Any `insecure_identity_adapter_enabled` event, ever? (**automatic SEV-1**)
- [ ] Any successful (`outcome = allowed`) operations by the same principal in an
      organization they should not be in? Query:
      `filter principal_id = "<id>" | stats count(*) by organization_id, outcome`
- [ ] Is the principal's membership record present and `active`?
- [ ] Were there `unhandled_error` events in the same window? (a crash may be the real story)

### The question that decides everything

> **Did any request from the suspect principal return `outcome = allowed` for an
> `organization_id` that is not theirs?**

If **no** — the controls held. Denials are the system working. This is a client problem or
a contained probe.

If **yes** — this is a **confirmed cross-tenant access event**. Classify SEV-1, escalate
immediately, and go to step 6.

---

## 6. Severity classification

| Severity | Criteria | Response |
|---|---|---|
| **SEV-1** | Confirmed cross-tenant access (`allowed` outcome in a foreign org); **or** `insecure_identity_adapter_enabled` observed; **or** a customer reports seeing another tenant's data | Page the security lead **now**. Begin containment (step 7) with senior approval. Start an incident record |
| **SEV-2** | Enumeration confirmed (one principal, >20 misses, high distinct ids) with no successful foreign access; **or** a `role_claim_mismatch` burst with no benign explanation | Escalate to security lead within 30 min. Containment decision is theirs |
| **SEV-3** | Denials concentrated on one principal/org with a plausible client explanation, no enumeration pattern | Notify the owning team. Monitor for 24 h. No containment |
| **SEV-4** | Denials explained by a deployment, an expired-token storm, or a known client bug | Record and close. Consider whether the alarm threshold needs tuning |

**When uncertain, classify one level higher.** Over-escalation costs an engineer's
attention; under-escalation costs the company a reportable breach.

---

## 7. Containment decision framework

> **Containment requires senior approval. A responder acting alone should complete steps
> 1–6 and escalate.** Every action below is disruptive to a real customer.

Containment is a trade-off between stopping an attacker and taking the service away from
legitimate users. Work from least to most disruptive.

| Option | Action | Blast radius | Use when |
|---|---|---|---|
| **C1 — Observe** | Increase log retention; add a targeted Insights query; keep watching | None | SEV-3/4, or SEV-2 where the attacker is contained by working controls and more evidence is more valuable than speed |
| **C2 — Revoke the user's sessions** | Cognito `AdminUserGlobalSignOut` for the specific `principal_id` | One user | A single compromised or malicious account. **Preferred first action** for SEV-1/2 |
| **C3 — Deactivate the membership** | Set the membership record `status` to something other than `active` | One user, one org | Revokes authorization **immediately** rather than at token expiry — because role and membership are read from the record on every request, not from the token (finding F-002). This is why that design matters operationally |
| **C4 — Disable the Cognito user** | `AdminDisableUser` | One user, all orgs | Confirmed malicious insider |
| **C5 — Throttle the source** | Tighten API Gateway stage throttling, or add a WAF rule for the source IP | Potentially all tenants sharing the stage | A distributed flood. Note: WAF is **not currently deployed** (accepted risk AR-05) |
| **C6 — Reduce reserved concurrency to 0** | Effectively takes the API offline | **Every tenant** | **Last resort.** Only for an in-progress, confirmed, ongoing multi-tenant data exfiltration where nothing narrower works. Requires explicit senior sign-off and a customer-communication plan |

### What *not* to do

- **Do not delete log data or alarms** to "clean up". You are destroying evidence, and the
  execution role is explicitly denied `logs:DeleteLogGroup` for exactly this reason.
- **Do not modify the Lambda or IAM policy mid-incident** without recording the change.
  Pre-incident configuration is evidence.
- **Do not read tenant ticket content** to assess impact. Use identifier counts. Content
  access needs its own authorization and will itself appear in the audit trail.
- **Do not contact the suspect account holder** before the security lead decides. It
  destroys the investigation.

---

## 8. Escalation responsibilities

| Role | Owns | When engaged |
|---|---|---|
| On-call engineer | Steps 1–6, evidence collection, incident record | Immediately on alarm |
| Security lead | Severity confirmation, containment approval, breach-assessment decision | SEV-1/2 immediately; SEV-3 within business hours |
| Service owner (application) | Code-level root cause, fix, regression test | Once a control failure is suspected |
| Cloud/platform owner | IAM, Cognito, gateway and alarm changes | Containment options C2–C6 |
| Legal / privacy | Regulatory reportability | **Any confirmed cross-tenant data access** — engage early, do not wait for certainty |
| Customer success | Customer communication | Only after the security lead approves the message |

---

## 9. Recovery verification

Do not close the incident until **every** item passes.

- [ ] The denial / mismatch / 401 rate has returned to its pre-incident baseline
- [ ] Zero `outcome = allowed` records for the suspect principal in any foreign
      organization, for the whole incident window
- [ ] If a control failed: a **regression test** exists that fails against the vulnerable
      code and passes against the fix (the standard set in
      [`../assessments/regression-evidence.md`](../assessments/regression-evidence.md))
- [ ] Any containment action is either reverted or converted into a permanent, reviewed
      change — no temporary WAF rules or concurrency settings left behind undocumented
- [ ] Membership records for affected users verified correct
- [ ] If tokens were revoked: affected legitimate users can authenticate again
- [ ] Alarm thresholds reviewed — did they fire early enough? Too often?
- [ ] Full timeline recorded in
      [`incident-report-template.md`](incident-report-template.md)

---

## 10. Documentation requirements

Record, at minimum:

1. Alarm name, firing time (UTC), breaching metric value.
2. Every Insights query run, verbatim, with the time range.
3. Principal and organization identifiers involved — **identifiers only, never content**.
4. The answer to the step-5 decisive question, with the query that produced it.
5. Severity assigned, by whom, and when.
6. Containment actions: what, who approved, when applied, when reverted.
7. Root cause: client bug / misconfiguration / control failure / malicious activity.
8. If a control failed: the finding ID, the fix commit, and the regression test name.
9. Residual risk accepted on closure, with an owner.

---

## 11. Post-incident improvements

Every invocation of this runbook should produce at least one of:

- An **alarm threshold change**, if the alarm fired too late or too often.
- A **new saved Insights query**, if a query had to be written from scratch during triage.
- A **new regression test**, if a control failed.
- A **runbook amendment**, if a step was unclear, missing, or wrong.
- A **threat-model update**, if the activity was not an anticipated threat
  ([`../threat-model/threat-model.md`](../threat-model/threat-model.md)).

### Known detection gaps — be aware of these during triage

Stated honestly, because a responder needs to know what the tooling cannot see:

1. **A successful cross-tenant read through a control failure may look entirely normal.**
   The logs record `outcome = allowed` with the organization the code *believed* was
   correct. Detection relies on the org id looking wrong for that principal — which is why
   the step-5 question is phrased the way it is.
2. **Token theft is not directly detectable.** A replayed token is indistinguishable from
   legitimate use (threat T-02, accepted risk AR-03). Source-IP change is a weak signal
   only, and correlating it needs the application and gateway logs joined manually.
3. **No alarm exists for "a principal read an unusual volume of tickets."** Bulk read by a
   legitimately-authorized admin is not currently distinguishable from abuse.
4. **The alarms have never fired in a real environment.** Nothing here has been deployed
   (limitation L1), so thresholds are reasoned estimates, not tuned values. Expect the
   first week in production to require retuning.
