# Security Assessment — Executive Summary

**System:** Multi-Tenant Customer Support API · **Date:** 23 October 2026
**Version assessed:** `8cb87f5` · **Audience:** Engineering leadership
**Full report:** [`final-security-assessment.md`](final-security-assessment.md)

---

## What this system does, and the risk that matters

A support-ticket API shared by multiple customer organizations. One deployment, one
database, one function — serving every customer. That shape creates a single dominant
business risk:

> **If one customer can see or change another customer's tickets, the product cannot be
> sold, and the incident is legally reportable.**

Everything below is organised around that sentence.

---

## What was done

The system was designed, built, threat-modelled, security-reviewed, remediated and
re-tested. The review covered 2,058 statements of application code, 10 Terraform files and
3 IAM policy documents, against a 60-item checklist derived from a 16-threat STRIDE model.

---

## What was found

**15 confirmed security findings: 1 critical, 4 high, 7 medium, 3 low. All 15 are fixed.**

Three would have caused a breach:

| Finding | In plain terms | Business consequence |
|---|---|---|
| **F-001** (Critical) | The service accepted "I am user X at company Y" as a plain HTTP header when no valid login was present — and this insecure mode was the **default setting** | Anyone on the internet, with no password and no account, could read and modify **every customer's** tickets. Multi-tenant breach, reportable, and the logs would record whatever name the attacker typed |
| **F-004** (High) | Adding one extra field to a request let a logged-in user **write into another customer's** data | A customer could plant or corrupt records in a competitor's account. Verified: the test captured a successful "201 Created" placing a ticket in the victim's organization |
| **F-003** (High) | The permission check for editing a ticket was written, and then never actually called | Any employee of a customer could edit any colleague's tickets. The bug was invisible in review *because* the check existed — just unused |

The remaining 12 covered privilege escalation via a forgeable role claim, customer ticket
text and login tokens being written into log files, stack traces returned to callers,
unbounded queries that let one caller run up the bill, and an over-broad cloud permission
that could have deleted both the data and the logs proving it.

---

## How confident we are that they are fixed

Every fix is held in place by an automated test that was **first proven to fail** against
the broken code. That is the difference between "we fixed it" and "we believe we fixed it".

| Evidence | Result |
|---|---|
| Security tests run against the **pre-fix** code | **84 failed** |
| The same tests against the **current** code | **176 passed** |
| Full test suite | **584 passed**, 11 skipped (need a live AWS account) |
| Code coverage | 89% |
| Automated security scanners (5 tools) | 0 findings at actionable severity |
| Full security pipeline | **15 of 15 stages pass** |

Isolation between customers is now **structural rather than procedural**: the database
query is physically scoped to the calling customer, the cloud permission to read across all
customers is explicitly denied, and a caller's privilege level is read from our own records
rather than from anything they send us. The most common cause of multi-tenant breaches — "a
filter got dropped during a refactor" — no longer has a code path to travel down.

---

## What we are *not* claiming

Three gaps are worth leadership's attention, because they bound the confidence above:

1. **Nothing has been deployed to AWS.** The cloud configuration has been statically
   analysed and reviewed, but never run. Eleven tests that would prove the live behaviour
   are written and deliberately skipped rather than quietly omitted.
2. **The infrastructure code has not been validated by Terraform itself.** The tool could
   not be installed in the build environment. A configuration-syntax error would have been
   caught; an incorrect AWS argument name might not.
3. **The reviewer and the author are the same engineer.** This is the weakest form of
   review. An independent reviewer would find things this one did not.

---

## Remaining risk

| Residual risk level | Count |
|---|---|
| Critical / High | **0** |
| Medium | 3 |
| Low | 13 |

The three Medium risks are consciously accepted, each with a named owner and review date:
**stolen-login-token replay** (inherent to how bearer tokens work industry-wide),
**one shared service means one customer's traffic flood affects everyone** (availability,
not confidentiality), and **one cloud permission is scoped to the whole table rather than
to one record type** — which has a clean architectural fix, and it is our top priority.

---

## What we recommend next

| # | Action | Why |
|---|---|---|
| 1 | Separate the permissions data into its own table | Closes the last Medium confidentiality risk. No policy change can substitute — the cloud platform cannot express the needed constraint |
| 2 | Deploy to a sandbox AWS account and run the 11 skipped tests | Closes the largest assurance gap in one step |
| 3 | Run the pipeline on real infrastructure | One scanner (CodeQL) has produced no results at all until this happens |
| 4 | Require two-factor authentication for customer administrators | Narrows the window on the highest-privilege accounts |
| 5 | Commission an independent review | The one limitation no amount of self-review can close |

---

**Bottom line.** The system's tenant isolation is now enforced by its architecture rather
than by developer discipline, and every fix is backed by a test that demonstrably failed
before it. The code-level work is complete and verified. The cloud-level work is complete
and **reviewed but unproven**, because nothing has been deployed — and that, not the
application, is where the remaining uncertainty sits.
