# Incident Report — <short descriptive title>

> Copy this file to `incidents/YYYY-MM-DD-<slug>.md` and fill it in. Delete the guidance
> in blockquotes as you go. Leave a field as `unknown` rather than guessing — an honest
> gap is useful, a plausible invention is not.

---

## 1. Summary

| Field | Value |
|---|---|
| **Incident ID** | INC-YYYY-NNN |
| **Title** | |
| **Severity** | SEV-1 / SEV-2 / SEV-3 / SEV-4 |
| **Status** | Investigating / Contained / Resolved / Closed |
| **Detected at** (UTC) | |
| **Detected by** | Alarm name / customer report / manual review / scanner |
| **Contained at** (UTC) | |
| **Resolved at** (UTC) | |
| **Runbook used** | RB-A (authorization triage) / RB-B (cloud finding) / none |
| **Incident commander** | |
| **Scribe** | |
| **Tenants affected** | Count and identifiers |
| **Customer data accessed?** | **Yes / No / Undetermined** |
| **Reportable?** | Yes / No / Under legal review |

### Two-sentence summary

> What happened, and what the consequence was. Written for someone who will read nothing
> else on this page.

---

## 2. Impact

| Question | Answer |
|---|---|
| Was any cross-tenant data **read**? | |
| Was any cross-tenant data **written or modified**? | |
| How many tickets were involved? | |
| How many principals were involved? | |
| Which organizations? | |
| Was availability affected, and for how long? | |
| Were credentials or tokens exposed? | |
| Was the audit trail affected? | |

> **Base this on log evidence, not inference.** The decisive query is the one from
> Runbook A §5: did any request from the suspect principal return `outcome = allowed` for
> an `organization_id` that is not theirs? Paste the query and its result.
>
> If impact cannot be determined from logs, write **"Undetermined"** and say why. Do not
> write "no evidence of access" when what you mean is "we cannot tell" — those are
> different statements and the second one has legal consequences.

---

## 3. Timeline (UTC)

| Time | Actor | Event | Evidence |
|---|---|---|---|
| | | | |

> Include: first malicious/anomalous activity (often earlier than detection), detection,
> each escalation, each containment action and who approved it, the fix, and verification.
> "Evidence" should be a log query, a request id, a commit SHA or a ticket link.

---

## 4. Detection

| Field | Value |
|---|---|
| Detection mechanism | |
| Time from first activity to detection | |
| Did detection work as designed? | |
| Alarm threshold at the time | |
| Was the alarm tuned correctly? | Too sensitive / about right / too slow |

> If detection was a customer report rather than an alarm, say so explicitly. That is the
> single most important fact on this page for improving the system.

---

## 5. Investigation

### Queries run

```
# Paste each CloudWatch Logs Insights query verbatim, with its time range and row count.
```

### Findings

> What the evidence showed. Separate **observation** from **interpretation** — say
> "principal X generated 340 resource_not_found events across 338 distinct resource ids"
> and then, separately, "this is consistent with identifier enumeration".

### Identifiers involved

| Type | Value | Notes |
|---|---|---|
| `principal_id` | | |
| `organization_id` | | |
| `request_id` | | |
| Source IP | | |

> **Identifiers only. Never paste ticket content into this report.** Customer content is
> deliberately excluded from logs (finding F-007), and reproducing it here would defeat
> that control and widen the exposure the incident is about.

---

## 6. Root cause

| Field | Value |
|---|---|
| **Category** | Control failure / misconfiguration / client bug / credential compromise / malicious insider / dependency vulnerability / undetermined |
| **Root cause** | |
| **Why did the controls not prevent it?** | |
| **Was this an anticipated threat?** | Yes → threat ID `T-NN`. No → the threat model has a gap |
| **Was there a related prior finding?** | Yes → `F-NNN`. No |
| **Was a residual risk being accepted here?** | Yes → `AR-NN`. No |

> If the answer to "anticipated threat" is **no**, that is a finding in its own right:
> raise a threat-model update as a follow-up action in §9.
>
> If a previously **accepted** risk materialised, say so plainly. An accepted risk that
> turns into an incident means the acceptance was wrong, and that is worth more than a
> comfortable framing.

---

## 7. Containment and remediation

### Containment actions

| Action | Option (RB-A §7) | Applied at | Approved by | Reverted at |
|---|---|---|---|---|
| | C1–C6 | | | |

### Permanent fix

| Field | Value |
|---|---|
| Fix description | |
| Pull request | |
| Commit SHA | |
| Finding ID raised | `F-NNN` |
| Regression test added | Test name |
| Does the test fail against the vulnerable code? | **Yes / No** |

> **"Yes" is the standard.** A regression test that has never failed is not evidence that
> it tests anything. Record the before/after output the way
> [`../assessments/regression-evidence.md`](../assessments/regression-evidence.md) does.

---

## 8. Recovery verification

From Runbook A §9 / Runbook B §7 — tick only what was actually verified.

- [ ] Anomalous event rate returned to baseline
- [ ] No `outcome = allowed` records in a foreign organization across the whole window
- [ ] Regression test present and demonstrated to fail against the vulnerable code
- [ ] Containment actions reverted, or converted into reviewed permanent changes
- [ ] Affected legitimate users can authenticate and operate normally
- [ ] Membership records verified correct
- [ ] Full security pipeline passing: `./scripts/run_security_checks.sh`
- [ ] Alarm thresholds reviewed
- [ ] Risk register updated: [`../threat-model/risk-register.csv`](../threat-model/risk-register.csv)

---

## 9. Follow-up actions

| # | Action | Type | Owner | Due | Status |
|---|---|---|---|---|---|
| 1 | | Fix / test / alarm / runbook / threat model / process | | | |

> Every incident should produce at least one durable improvement. "Be more careful" is not
> an action. "Add a CI rule that fails on `.scan(` in `application/`" is.

---

## 10. Lessons learned

### What worked

> Controls that held, detections that fired, steps that were clear. Name them — they are
> the ones worth protecting in future refactors.

### What did not work

> Controls that failed, detections that were silent or too slow, runbook steps that were
> wrong or missing, information that was unavailable when needed.

### What we got lucky on

> The most valuable section, and the easiest to skip. What would have made this
> significantly worse, and was avoided by circumstance rather than by design?

---

## 11. Sign-off

| Role | Name | Date | Notes |
|---|---|---|---|
| Incident commander | | | |
| Security lead | | | |
| Service owner | | | |
| Legal / privacy | | | Required if §2 answers Yes or Undetermined to data access |

**Residual risk accepted on closure:**

> What remains unresolved, who owns it, and when it will be reviewed. If nothing remains,
> say so explicitly rather than leaving this blank.
