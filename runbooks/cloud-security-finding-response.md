# Runbook B — High-Severity Cloud Security Finding

| | |
|---|---|
| **Runbook ID** | RB-B |
| **Scope** | Findings against this project's AWS infrastructure or its IaC: Security Hub CSPM, Checkov, the project's own `iam_policy_checker.py`, Bandit, pip-audit, or a manual review |
| **Intended responder** | On-call or duty security engineer, any level. **Remediation requires a reviewed pull request — never a console change** |
| **Expected time to triage** | 1 business day for High/Critical; 5 days for Medium |
| **Last reviewed** | 2026-10-23 |

---

## 1. Purpose

Take a cloud security finding from "a tool said something" to "fixed, verified, and it
cannot come back". The emphasis throughout is that a finding is **not closed when the
resource is changed** — it is closed when the change is in version control, the scanner
agrees, and something would catch the regression.

> **A console fix is a temporary fix.** This infrastructure is Terraform-managed, so a
> change made in the AWS console is silently reverted by the next `terraform apply` — and
> the finding returns with nobody watching. Every remediation in this runbook goes through
> the IaC.

---

## 2. Finding intake

### 2.1 Where findings arrive

| Source | Path | Default state |
|---|---|---|
| **Checkov** (IaC) | CI stage 3e, blocks the pull request | Active |
| **`iam_policy_checker.py`** (own tool) | CI stage 3c against `infrastructure/terraform/policies/` | Active |
| **Bandit / pip-audit** | CI stage 2 | Active |
| **Security Hub CSPM** | Security Hub → EventBridge → triage Lambda → CloudWatch (+ optional SNS) | **Disabled by default** (`enable_security_hub = false`) — it is a paid service; enabling it is a cost decision |
| **Manual review** | Raised directly as a finding | — |

### 2.2 Normalise it first

Before triaging, put the finding through the project's triage engine so it has a stable id,
a normalised severity, an owner and a priority:

```bash
python3 security-automation/finding_triage.py \
  --input reports/checkov.json \
  --input reports/iam-findings.json \
  --input reports/bandit.json \
  --input reports/pip-audit.json \
  --previous reports/triage-report.json \
  --output reports/triage-report.json \
  --markdown reports/triage-report.md
```

Why bother rather than reading the tool output directly:

- **Stable finding ids** survive across runs, so "is this the same finding as last week?"
  is answerable.
- **Deduplication** stops one misconfiguration appearing four times because four tools saw
  it.
- **`--previous`** produces status tracking: `new`, `open`, `overdue`, `newly resolved` —
  which is what tells you whether a finding is regressing or genuinely new.
- **Owner assignment** by rule means it is routed, not just logged.

### 2.3 Record intake facts

- [ ] Normalised `finding_id` and source tool
- [ ] Tool-reported severity **and** the normalised severity (they often differ)
- [ ] Priority and risk score from the triage engine
- [ ] Status: new / open / overdue / newly-resolved
- [ ] `resource` identifier and the Terraform file that declares it
- [ ] Whether CI is currently blocked on it

---

## 3. Asset identification

Map the finding to a real resource and its real blast radius. A finding against the KMS key
is not the same as a finding against a log group, even at identical tool severity.

```bash
# Which Terraform file declares the resource?
grep -rn "<resource_name>" infrastructure/

# What does the resource touch?
grep -rn "<resource_name>" infrastructure/terraform/*.tf
```

### Asset criticality for this system

| Tier | Assets | Why |
|---|---|---|
| **1 — Critical** | `aws_dynamodb_table.main`, `aws_iam_role.lambda` + its policies, `aws_iam_policy.lambda_boundary` | Hold or grant access to **every tenant's** data |
| **2 — High** | `aws_cognito_user_pool.main`, `aws_cognito_user_pool_client.api`, `aws_apigatewayv2_authorizer.cognito`, `aws_kms_key.main` | Control authentication and decryption |
| **3 — Medium** | `aws_lambda_function.api`, `aws_apigatewayv2_api.main`, `aws_apigatewayv2_stage.main` | Execution and entry point |
| **4 — Low** | CloudWatch log groups, metric filters, alarms, SNS topic, dashboard | Detection. Degrades response, not confidentiality — **but a finding that disables detection is a Tier-1 problem in disguise** |

### Then ask the question tools cannot answer

> **Is this resource reachable from an untrusted boundary, and does it hold or grant access
> to tenant data?**

A tool scores a rule. Only you can score the context. Cross-reference
[`../threat-model/architecture.md`](../threat-model/architecture.md) §4 for the trust
boundary the resource sits behind.

---

## 4. Risk assessment

### 4.1 Is it a true positive?

Work through these in order. **Document the answer either way** — a dismissed finding with
no recorded reasoning is indistinguishable from a missed one.

1. **Does the flagged configuration actually exist in the IaC?** Scanners misattribute.
2. **Is the rule applicable to this resource type?** The canonical example in this
   repository: Checkov `CKV_AWS_109`/`CKV_AWS_111`/`CKV_AWS_356` flag `Resource: "*"` on
   the KMS **key policy**. In a key policy, `Resource: "*"` denotes *the key itself* — it is
   the only legal form, and the account-root statement is mandatory for key manageability.
   A true positive in an identity policy; a false positive here. Recorded as **AR-01**.
3. **Is the risk already mitigated by a compensating control?** Example: `CKV_AWS_116`
   (no Lambda DLQ) — invocations here are synchronous, so there is no asynchronous event to
   replay. Recorded as **AR-06**.
4. **Does the project's own analyzer agree?** `iam_policy_checker.py` classifies findings
   as `confirmed` or `needs_context`. A `needs_context` finding is a prompt to think, not a
   defect: `IAM003` on `lambda-xray.json` is `needs_context` precisely because X-Ray's
   `PutTraceSegments` genuinely does not support resource-level scoping.

### 4.2 Severity — adjust from the tool's score

| Factor | Raises severity | Lowers severity |
|---|---|---|
| Reachability | Internet-reachable | Requires existing account compromise |
| Data | Grants access to tenant data | Touches only metadata or logs |
| Authentication | Bypasses or weakens it | Behind a verified identity |
| Tenancy | Could cross the tenant boundary | Confined to one tenant |
| Blast radius | Account-wide (`Resource: "*"`) | Single ARN |
| Detection | Would disable or blind detection | Detection unaffected |
| Reversibility | Enables data destruction | Read-only exposure |

| Final severity | Remediation SLA | Gate behaviour |
|---|---|---|
| **Critical** | Same day | CI blocked; no merges to the affected area |
| **High** | 3 business days | CI blocked |
| **Medium** | 10 business days | CI blocked by default; may proceed with a recorded, targeted exception |
| **Low / Info** | Next planned work | Reported, not blocking |

---

## 5. Owner identification

```bash
# The triage engine assigns an owner from configurable rules
jq '.findings[] | {finding_id, category, severity, recommended_owner}' \
  reports/triage-report.json
```

| Category | Owner | Typical findings |
|---|---|---|
| `iam` | Cloud Security Engineering | Over-broad policies, missing boundaries, trust-policy gaps |
| `encryption` | Cloud Security Engineering | Missing SSE, unrotated keys, weak key policies |
| `network` / `api` | Cloud Security Engineering | Public endpoints, missing throttling, TLS policy |
| `logging` | Cloud Security Engineering | Missing retention, unencrypted groups, absent filters |
| `application` | Application Security | Bandit findings, insecure code patterns |
| `dependency` | Application Security | pip-audit advisories |

**An unowned finding is an unfixed finding.** If no rule matches, assign it to the security
lead rather than leaving it blank, and add an owner rule so it routes next time.

---

## 6. Mitigation planning

### 6.1 The rules

1. **Fix it in Terraform.** Never the console — the next `apply` reverts a console change
   and the finding silently returns.
2. **Prefer the narrowest change** that removes the finding. A finding about one statement
   is not a licence to restructure a policy.
3. **Prefer removing a permission over adding a condition.** If the application does not
   perform the action, delete it; a conditioned grant still has to be read and trusted by
   the next reviewer.
4. **Add an explicit `Deny`** where the blast radius is large. A `Deny` cannot be overridden
   by any later `Allow`, so it survives someone attaching a broad policy to the role later.
5. **Never suppress to make CI green.** If a suppression is genuinely correct, it must be
   inline, scoped to one check on one resource, and carry a written justification naming the
   accepted-risk ID.

### 6.2 The change

```bash
git checkout -b fix/security-<finding_id>
# edit the specific .tf file or policy JSON

# Verify locally, before pushing
python3 scripts/validate_terraform.py infrastructure/terraform
python3 security-automation/iam_policy_checker.py \
  --input infrastructure/terraform/policies/ --output reports/iam-findings.json
python3 -m checkov.main -d infrastructure/ --framework terraform --compact --quiet

# And where Terraform is available (not in the CI sandbox — see limitation L2)
terraform fmt -check -recursive
terraform validate
terraform plan        # READ THE PLAN. Confirm the diff is only what you intended.
```

### 6.3 If a suppression really is correct

The repository's existing suppressions are the template — inline, single-check,
single-resource, justified, and cross-referenced to an accepted risk:

```hcl
#checkov:skip=CKV_AWS_309:Intentionally public liveness probe. Returns a static payload
#  with no configuration disclosure, asserted by tests/security/test_api_behaviour.py.
#  Recorded in assessments/final-security-assessment.md §Accepted risks (AR-02).
```

Then add the accepted risk to
[`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md)
§11.1 with a rating, rationale, **named owner** and **review date**. An accepted risk with
no review date is just a suppression with better manners.

There is **no baseline file and no blanket `--skip-check`** in this repository, and that is
deliberate — both make the count of suppressed findings invisible.

---

## 7. Remediation verification

A finding is **not** closed until all of these pass:

- [ ] The originating tool no longer reports it
      → `grep '<finding_id>' reports/triage-report.json`
- [ ] The triage engine reports it as **`newly resolved`** on the next run with `--previous`
- [ ] **No new finding was introduced** — compare the full triage summary before and after,
      not just the one finding
- [ ] `./scripts/run_security_checks.sh` passes all stages
- [ ] `terraform plan` shows **only** the intended diff (where Terraform is available)
- [ ] The application test suite still passes: `python3 -m pytest -q`
- [ ] If a permission was removed: an AWS-gated test asserts the action is now denied
      (see `tests/integration/test_aws_gateway_contract.py` for the pattern), **or** the gap
      is recorded as unverified
- [ ] The change is merged through a **reviewed pull request**, not pushed directly
- [ ] If this finding could recur: a rule, test or policy exists that would catch it

### The regression question

> **What would catch this if someone reintroduced it next quarter?**

If the answer is "the same scanner that caught it this time", that is acceptable — the gate
is the control. If the answer is "nothing, because the scanner only sees the IaC and this
could be reintroduced another way", the remediation is **incomplete**: add the test.

---

## 8. Resolution criteria

| State | Criteria |
|---|---|
| **Resolved** | Fixed in IaC, merged via reviewed PR, tool no longer reports it, pipeline green, regression coverage identified |
| **Risk accepted** | True positive, not fixed, with: rating, written rationale, named owner, review date, entry in the final assessment §11.1, and an inline justified suppression |
| **False positive** | Reasoning documented in the finding record **and** the triage engine's suppression rules updated so it does not re-consume triage effort |
| **Deferred** | Fix identified but scheduled. Needs a ticket, an owner and a date. Deferral beyond the SLA requires security-lead sign-off |

**"Deferred" without a date is "ignored".** The triage engine's `overdue` status exists to
make that visible — use it.

---

## 9. Lessons learned

Within 5 business days of resolving any High or Critical finding, answer:

1. **How did it get in?** New resource, changed resource, or a new rule finding existing
   configuration? (The third is good news — it means coverage improved.)
2. **Why did CI not stop it?** Tool not run on that path? Rule not enabled? Gate set to
   non-blocking? Suppressed?
3. **Was the severity right?** Did the tool's score match the real blast radius? If not,
   adjust the severity mapping in `triage_config.json`.
4. **Was the owner right?** If it was misrouted, fix the owner rule.
5. **Is the detection now permanent?** Will the same class be caught next time, or only this
   instance?
6. **Does the threat model need updating?** If the finding represents a threat not in
   [`../threat-model/threat-model.md`](../threat-model/threat-model.md), add it — a finding
   outside the model means the model has a gap.

### Known limitations of this process

Stated so a responder is not misled about coverage:

1. **Security Hub is disabled by default.** Without it there is no continuous CSPM
   baseline — IaC scanning catches what is *declared*, not configuration drift made outside
   Terraform. Enabling it is a cost decision (see
   [`../docs/AWS_DEPLOYMENT.md`](../docs/AWS_DEPLOYMENT.md)).
2. **`terraform validate` and `plan` are not run in the project's CI sandbox**
   (limitation L2 — the Terraform binary cannot be installed there). Checkov's HCL parse
   plus the custom reference linter are partial substitutes and **not** provider-schema
   validation.
3. **No AWS deployment exists** (limitation L1), so no finding in this runbook has ever
   been triaged against live infrastructure. The process is reasoned and locally
   exercised, not operationally proven.
4. **`iam_policy_checker.py` is a pattern matcher, not an IAM policy evaluator.** It does
   not resolve policy interaction, SCPs, boundaries or resource policies, and it does not
   claim parity with IAM Access Analyzer. Its documented limitations are printed by
   `--list-rules`.
