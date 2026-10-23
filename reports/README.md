# reports/

**Generated tool output. Nothing here is committed.**

`.gitignore` excludes `reports/*` deliberately: committed, reviewed evidence lives in
[`../assessments/`](../assessments/), so that a generated artifact can never masquerade as a
reviewed finding. The two are different kinds of claim and should not share a directory.

## Regenerate everything

```bash
./scripts/run_security_checks.sh
```

Produces:

| File | Produced by |
|---|---|
| `local-security-run.txt` | the full pipeline transcript |
| `bandit.json` | Bandit SAST |
| `pip-audit.json` | pip-audit SCA |
| `checkov.json` | Checkov IaC scan |
| `iam-findings.json` | `security-automation/iam_policy_checker.py` |
| `coverage.xml`, `junit.xml` | pytest |
| `triage-report.json`, `triage-report.md` | `security-automation/finding_triage.py` |

## Regenerate the before/after regression evidence

The transcript quoted in
[`../assessments/regression-evidence.md`](../assessments/regression-evidence.md) comes from
running the current security suite against the pre-review implementation:

```bash
git worktree add /tmp/v1check v1-pre-review
cp -r tests /tmp/v1check/tests_current
cp pyproject.toml /tmp/v1check/pyproject.toml.cur
cd /tmp/v1check && rm -rf tests && mv tests_current tests && cp pyproject.toml.cur pyproject.toml
python -m pytest tests/security -p no:cacheprovider -q \
  > "$OLDPWD/reports/regression-v1-pre-review.txt" 2>&1
cd - && git worktree remove --force /tmp/v1check

# Expect: 93 failed, 102 passed
tail -1 reports/regression-v1-pre-review.txt

# Failures by module
grep '^FAILED' reports/regression-v1-pre-review.txt \
  | sed 's#^FAILED tests/security/##; s#::.*##' | sort | uniq -c | sort -rn
```
