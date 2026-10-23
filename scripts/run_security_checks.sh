#!/usr/bin/env bash
#
# Run the whole security pipeline locally, in the same order and with the same
# gating as .github/workflows/security-ci.yml.
#
# The point is that a developer can reproduce a CI failure on their laptop
# without pushing. If this script passes and CI fails, the two have drifted and
# that is a bug in the pipeline.
#
# Usage:
#   ./scripts/run_security_checks.sh              # everything, gated
#   ./scripts/run_security_checks.sh --no-gate    # report everything, exit 0
#   ./scripts/run_security_checks.sh --fast       # skip the slow IaC scan
#
# Reports are written to reports/ (gitignored).

set -uo pipefail   # deliberately NOT -e: every stage must run so the summary
                   # is complete, rather than stopping at the first failure.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"

GATE=true
FAST=false
for arg in "$@"; do
  case "$arg" in
    --no-gate) GATE=false ;;
    --fast)    FAST=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

FAILED_STAGES=()
PASSED_STAGES=()

hr() { printf '%s\n' "------------------------------------------------------------------------"; }

stage() {
  local name="$1"; shift
  hr
  printf '\033[1;34m[STAGE]\033[0m %s\n' "$name"
  hr
  if "$@"; then
    PASSED_STAGES+=("$name")
    printf '\033[1;32m  PASS\033[0m %s\n\n' "$name"
  else
    local code=$?
    FAILED_STAGES+=("$name (exit $code)")
    printf '\033[1;31m  FAIL\033[0m %s (exit %s)\n\n' "$name" "$code"
  fi
}

# --- Stage 1: code quality ------------------------------------------------
stage "1a. Ruff lint" ruff check . --output-format=concise
stage "1b. Ruff format check" ruff format --check .

# --- Stage 2: application security ----------------------------------------
# Bandit: `-ll` reports MEDIUM and above. LOW findings are reported in the
# JSON artifact but do not gate, because B101 (assert) and friends generate
# noise that would train people to add nosec comments.
stage "2a. Bandit (SAST)" bash -c '
  python3 -m bandit -c pyproject.toml -r application/ security-automation/ \
    -f json -o reports/bandit.json --quiet 2>/dev/null
  python3 -m bandit -c pyproject.toml -r application/ security-automation/ -ll --quiet
'

# pip-audit: advisories against the RUNTIME dependency set. A vulnerable dev
# tool is worth knowing about but does not ship to production, so the runtime
# tree is what gates.
stage "2b. pip-audit (runtime dependencies)" bash -c '
  # Audited against the LOCK, which is what actually ships to Lambda.
  python3 -m pip_audit --requirement application/requirements.lock \
    --format json --output reports/pip-audit.json || true
  python3 -m pip_audit --requirement application/requirements.lock --strict
'

# A lock file that has drifted from its source is a lock file nobody can trust:
# the audited tree and the deployed tree stop being the same thing. Rather than
# relying on a developer remembering, recompile and diff.
stage "2c. Lock file is in sync with requirements.txt" bash -c '
  if ! python3 -c "import piptools" 2>/dev/null; then
    echo "pip-tools not installed; skipping drift check (install: pip install pip-tools)" >&2
    exit 0
  fi
  python3 -m piptools compile --generate-hashes --strip-extras --quiet \
    --output-file /tmp/requirements.lock.check application/requirements.txt >/dev/null 2>&1
  # Ignore the header, which records the output path and so always differs.
  if diff <(grep -v "^#" application/requirements.lock) \
          <(grep -v "^#" /tmp/requirements.lock.check) >/dev/null; then
    echo "Lock file is in sync."
  else
    echo "ERROR: application/requirements.lock is stale." >&2
    echo "Regenerate it:" >&2
    echo "  python -m piptools compile --generate-hashes --strip-extras \\" >&2
    echo "    --output-file application/requirements.lock application/requirements.txt" >&2
    diff <(grep -v "^#" application/requirements.lock) \
         <(grep -v "^#" /tmp/requirements.lock.check) | head -20 >&2
    exit 1
  fi
'

# --- Stage 3: infrastructure security -------------------------------------
stage "3a. Terraform reference linter (root)" \
  python3 scripts/validate_terraform.py infrastructure/terraform

stage "3b. Terraform reference linter (module)" \
  python3 scripts/validate_terraform.py infrastructure/modules/security_hub_triage

# The project's own IAM analyzer against the policies that actually deploy.
stage "3c. Custom IAM policy analyzer" \
  python3 security-automation/iam_policy_checker.py \
    --input-dir infrastructure/terraform/policies \
    --output "$REPORTS_DIR/iam-findings.json" \
    --fail-on high

# Positive control: the insecure fixture MUST fail, otherwise the gate is fake
# and would pass a genuinely bad policy.
stage "3d. IAM analyzer gate self-test (insecure fixture must fail)" bash -c '
  if python3 security-automation/iam_policy_checker.py \
       --input sample-data/insecure-policy.json --quiet; then
    echo "ERROR: the insecure fixture passed. The IAM gate is not working." >&2
    exit 1
  fi
  echo "Confirmed: the insecure fixture is correctly rejected."
'

if [ "$FAST" = false ]; then
  stage "3e. Checkov (Terraform)" bash -c '
    # Checkov treats --output-file-path as a DIRECTORY, so the machine-readable
    # report is captured from stdout instead. Its exit code is preserved for the
    # human-readable run below, which is the one that gates the stage.
    python3 -m checkov.main -d infrastructure/ --framework terraform \
      --output json --quiet > reports/checkov.json 2>/dev/null
    python3 -m checkov.main -d infrastructure/ --framework terraform \
      --compact --quiet --output cli
  '
else
  printf '\033[1;33m[SKIP]\033[0m 3e. Checkov (--fast)\n\n'
fi

# --- Stage 4: tests --------------------------------------------------------
stage "4a. Unit tests" python3 -m pytest -m unit -q --no-header
stage "4b. Integration tests" python3 -m pytest -m integration -q --no-header
stage "4c. Security tests" python3 -m pytest -m security -q --no-header
stage "4d. Security regression tests" python3 -m pytest -m regression -q --no-header
stage "4e. Full suite with coverage" bash -c '
  python3 -m pytest -q --no-header \
    --cov --cov-report=term-missing:skip-covered --cov-report=xml:reports/coverage.xml
'

# --- Stage 5: reporting ----------------------------------------------------
stage "5a. Finding triage (aggregate every report)" bash -c '
  INPUTS=()
  for f in reports/checkov.json reports/bandit.json reports/pip-audit.json reports/iam-findings.json; do
    [ -s "$f" ] && INPUTS+=(--input "$f")
  done
  if [ ${#INPUTS[@]} -eq 0 ]; then
    echo "No tool reports to aggregate." ; exit 0
  fi
  python3 security-automation/finding_triage.py \
    "${INPUTS[@]}" \
    --previous reports/triage-report.json \
    --output reports/triage-report.json \
    --markdown reports/triage-report.md
'

# --- Summary ---------------------------------------------------------------
hr
printf '\033[1;34mSUMMARY\033[0m\n'
hr
for name in "${PASSED_STAGES[@]}"; do printf '  \033[1;32mPASS\033[0m  %s\n' "$name"; done
for name in "${FAILED_STAGES[@]}"; do printf '  \033[1;31mFAIL\033[0m  %s\n' "$name"; done
echo
printf 'Passed: %s   Failed: %s\n' "${#PASSED_STAGES[@]}" "${#FAILED_STAGES[@]}"
printf 'Reports: %s/\n\n' "$REPORTS_DIR"

if [ ${#FAILED_STAGES[@]} -gt 0 ] && [ "$GATE" = true ]; then
  echo "One or more stages failed. Nothing is auto-suppressed: fix the finding," >&2
  echo "or record it as an accepted risk in assessments/final-security-assessment.md" >&2
  echo "with a documented, targeted exception." >&2
  exit 1
fi
exit 0
