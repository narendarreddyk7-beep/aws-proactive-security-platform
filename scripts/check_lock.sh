#!/usr/bin/env bash
#
# Verify application/requirements.lock against the Lambda runtime, and against
# requirements.txt.
#
# Two separate assertions, deliberately. The first always runs; the second only
# runs where it is meaningful.
#
# 1. THE LOCK MUST TARGET THE LAMBDA RUNTIME.
#    pip-compile resolves against the running interpreter, so a lock generated
#    on 3.13 can differ from the tree 3.12 actually installs. It does here: on
#    3.12 starlette requires typing-extensions, on 3.13 it does not. A lock
#    pinned for the wrong interpreter is wrong for the deployed artifact, not
#    merely untidy.
#
# 2. DRIFT CAN ONLY BE DIFFED ON THAT SAME INTERPRETER.
#    The first real CI run of this gate failed for exactly this reason: the
#    lock was generated on 3.13 and CI recompiled on 3.12, so a correct lock
#    looked like drift. A gate whose verdict depends on which Python happens to
#    be installed is not a gate. So rather than fail spuriously on the wrong
#    interpreter -- or skip silently, which is worse -- this reports what it
#    could not check and why, while still enforcing assertion 1.
#
# Lives in its own file rather than inline in both the workflow and
# scripts/run_security_checks.sh, so the two cannot drift apart.
#
# Exit codes: 0 pass (or "verified what I could"), 1 fail.

set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOCK="application/requirements.lock"
SOURCE="application/requirements.txt"

RUNTIME_PY="$(grep -hoE 'python3\.[0-9]+' infrastructure/environments/*/terraform.tfvars 2>/dev/null |
  sort -u | head -1 | sed 's/python//')"
RUNTIME_PY="${RUNTIME_PY:-3.12}"

LOCK_PY="$(sed -n 's/.*pip-compile with Python \([0-9][0-9.]*\).*/\1/p' "$LOCK" | head -1)"
CURRENT_PY="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

REGEN="python${RUNTIME_PY} -m piptools compile --generate-hashes --strip-extras \\
    --output-file ${LOCK} ${SOURCE}"

printf 'Lambda runtime : python%s\n' "$RUNTIME_PY"
printf 'Lock generated : python%s\n' "${LOCK_PY:-unknown}"
printf 'This process   : python%s\n' "$CURRENT_PY"

# --- assertion 1: the lock targets the deployment runtime -------------------
if [ -z "$LOCK_PY" ]; then
  echo "ERROR: cannot determine which Python generated ${LOCK}." >&2
  echo "       Regenerate it so the header is present:" >&2
  printf '  %s\n' "$REGEN" >&2
  exit 1
fi

if [ "$LOCK_PY" != "$RUNTIME_PY" ]; then
  echo "ERROR: ${LOCK} was generated with Python ${LOCK_PY}, but the Lambda" >&2
  echo "       runtime is python${RUNTIME_PY}. The locked tree is not the tree" >&2
  echo "       that will be installed. Regenerate it:" >&2
  printf '  %s\n' "$REGEN" >&2
  exit 1
fi

echo "OK: the lock targets the Lambda runtime."

# --- assertion 2: no drift from requirements.txt ----------------------------
if ! python3 -c 'import piptools' 2>/dev/null; then
  echo "NOTE: pip-tools is not installed, so drift was not diffed."
  echo "      Install it to enable that check: pip install pip-tools"
  exit 0
fi

if [ "$CURRENT_PY" != "$RUNTIME_PY" ]; then
  echo "NOTE: drift not diffed. This process is python${CURRENT_PY}, the lock"
  echo "      targets python${RUNTIME_PY}, and pip-compile resolves per"
  echo "      interpreter -- so a diff here would report differences that are"
  echo "      not drift. CI runs on python${RUNTIME_PY} and does diff it."
  exit 0
fi

CHECK="$(mktemp)"
trap 'rm -f "$CHECK"' EXIT

if ! python3 -m piptools compile --generate-hashes --strip-extras --quiet \
    --output-file "$CHECK" "$SOURCE" >/dev/null 2>&1; then
  echo "ERROR: pip-compile failed; cannot verify drift." >&2
  exit 1
fi

if diff <(grep -v '^#' "$LOCK") <(grep -v '^#' "$CHECK") >/dev/null; then
  echo "OK: the lock is in sync with ${SOURCE}."
  exit 0
fi

echo "ERROR: ${LOCK} is stale. Regenerate it:" >&2
printf '  %s\n' "$REGEN" >&2
diff <(grep -v '^#' "$LOCK") <(grep -v '^#' "$CHECK") | head -20 >&2
exit 1
