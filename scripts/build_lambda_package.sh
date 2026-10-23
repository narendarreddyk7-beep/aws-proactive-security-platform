#!/usr/bin/env bash
#
# Build the Lambda deployment packages.
#
# Produces two directories that Terraform's `archive_file` data sources zip:
#
#   dist/lambda_build/                 the support API function
#   dist/security_hub_triage_build/    the optional Security Hub triage function
#
# Run this BEFORE `terraform plan`. The archive is hashed to decide whether the
# function needs updating, so a missing build directory makes `plan` fail with
# a clear archive error rather than silently deploying an empty function.
#
# Usage:
#   ./scripts/build_lambda_package.sh                 # both packages
#   ./scripts/build_lambda_package.sh --api-only
#   ./scripts/build_lambda_package.sh --triage-only
#   TARGET_PYTHON=python3.12 ./scripts/build_lambda_package.sh
#
# WHY NOT `pip install -t` WITH THE HOST PYTHON
# ---------------------------------------------
# Pydantic v2 ships a compiled core (`pydantic-core`), so the wheel must match
# the Lambda runtime's platform and Python version. Installing with the host
# interpreter on a developer's macOS laptop produces a macOS wheel that fails
# at import inside Lambda with a confusing "no module named pydantic_core._pydantic_core".
#
# `--platform manylinux2014_aarch64 --only-binary=:all:` forces the correct
# wheels regardless of the build host, which is what makes this script
# reproducible on any machine. The architecture must match
# `architectures = ["arm64"]` in lambda.tf.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_PYTHON_VERSION="${TARGET_PYTHON_VERSION:-3.12}"
TARGET_PLATFORM="${TARGET_PLATFORM:-manylinux2014_aarch64}"

API_BUILD_DIR="dist/lambda_build"
TRIAGE_BUILD_DIR="dist/security_hub_triage_build"

BUILD_API=true
BUILD_TRIAGE=true
NATIVE=false

for arg in "$@"; do
  case "$arg" in
    --api-only)    BUILD_TRIAGE=false ;;
    --triage-only) BUILD_API=false ;;
    # Build for the HOST platform instead of the Lambda target. Use this only
    # to smoke-test an import locally -- the resulting artifact must never be
    # deployed, because its compiled extensions are for the wrong architecture.
    --native)      NATIVE=true ;;
    -h|--help)     sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Support API function
# ---------------------------------------------------------------------------
if [ "$BUILD_API" = true ]; then
  log "Building the support API package into ${API_BUILD_DIR}"

  rm -rf "$API_BUILD_DIR"
  mkdir -p "$API_BUILD_DIR"

  # Application code. Only the `app` package -- never tests, never the tooling.
  cp -R application/app "$API_BUILD_DIR/"

  if [ "$NATIVE" = true ]; then
    warn "--native: building for the HOST platform. DO NOT DEPLOY this artifact."
    PIP_PLATFORM_ARGS=()
  else
    log "Installing runtime dependencies for ${TARGET_PLATFORM} / py${TARGET_PYTHON_VERSION}"
    PIP_PLATFORM_ARGS=(
      --platform "$TARGET_PLATFORM"
      --python-version "$TARGET_PYTHON_VERSION"
      --implementation cp
      --only-binary=:all:
    )
  fi

  # Installed from the LOCK, not from loose package names, and with
  # --require-hashes so pip refuses any artifact whose hash does not match.
  # That makes the deployed artifact reproducible and gives the install step a
  # supply-chain check: a tampered or substituted wheel fails the build instead
  # of shipping. Regenerate the lock with:
  #   python -m piptools compile --generate-hashes --strip-extras \
  #     --output-file application/requirements.lock application/requirements.txt
  if ! pip install \
      --quiet \
      --target "$API_BUILD_DIR" \
      "${PIP_PLATFORM_ARGS[@]}" \
      --require-hashes \
      -r application/requirements.lock; then
    warn "Cross-platform wheel install failed."
    warn "This usually means no manylinux wheel exists for a pinned version."
    warn "Check application/requirements.lock, or build inside a container:"
    warn "  docker run --rm -v \"\$PWD\":/w -w /w public.ecr.aws/lambda/python:${TARGET_PYTHON_VERSION} \\"
    warn "    ./scripts/build_lambda_package.sh --api-only"
    exit 1
  fi

  # boto3/botocore are provided by the managed runtime. Shipping them adds
  # ~45 MB to the artifact and slows every cold start for no benefit.
  rm -rf "$API_BUILD_DIR"/boto3* "$API_BUILD_DIR"/botocore* \
         "$API_BUILD_DIR"/s3transfer* "$API_BUILD_DIR"/dateutil* \
         "$API_BUILD_DIR"/python_dateutil* "$API_BUILD_DIR"/jmespath* \
         "$API_BUILD_DIR"/urllib3*

  # Strip build residue that bloats the artifact and the archive hash.
  find "$API_BUILD_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  find "$API_BUILD_DIR" -type d -name 'tests' -prune -exec rm -rf {} + 2>/dev/null || true
  find "$API_BUILD_DIR" -type f -name '*.pyc' -delete 2>/dev/null || true
  find "$API_BUILD_DIR" -type f -name 'RECORD' -delete 2>/dev/null || true

  # Fail loudly rather than deploying something that cannot import.
  if [ ! -f "$API_BUILD_DIR/app/main.py" ]; then
    echo "error: ${API_BUILD_DIR}/app/main.py is missing; the package would not import" >&2
    exit 1
  fi

  # Verify the compiled extension really is for the Lambda target. A wheel for
  # the wrong architecture fails at Lambda cold start with a confusing
  # "no module named pydantic_core._pydantic_core", long after deploy -- so it
  # is worth catching here, at build time, where the error is obvious.
  if [ "$NATIVE" = false ]; then
    EXPECTED_TAG="$(printf '%s' "$TARGET_PLATFORM" | sed 's/.*_//')"   # e.g. aarch64
    CORE_SO="$(find "$API_BUILD_DIR/pydantic_core" -name '_pydantic_core*.so' 2>/dev/null | head -1)"
    if [ -z "$CORE_SO" ]; then
      echo "error: pydantic_core compiled extension not found in the package" >&2
      exit 1
    fi
    case "$CORE_SO" in
      *"$EXPECTED_TAG"*) log "Verified compiled extension targets ${EXPECTED_TAG}: $(basename "$CORE_SO")" ;;
      *)
        echo "error: pydantic_core extension does not target ${EXPECTED_TAG}:" >&2
        echo "       $(basename "$CORE_SO")" >&2
        echo "       The artifact would fail at Lambda cold start. Rebuild, or build in" >&2
        echo "       a container matching the runtime." >&2
        exit 1
        ;;
    esac
    warn "This artifact targets ${TARGET_PLATFORM} and is NOT importable on this host."
    warn "To smoke-test an import locally, rebuild with --native (and do not deploy it)."
  fi

  log "API package size: $(du -sh "$API_BUILD_DIR" | cut -f1)"
fi

# ---------------------------------------------------------------------------
# Security Hub triage function
#
# The shared risk model is COPIED from security-automation/ rather than
# reimplemented, so the Lambda and the CLI cannot drift into scoring the same
# finding differently. The copy is asserted by
# security-automation/tests/test_security_hub_handler.py::
#   test_handler_uses_the_same_risk_model_as_the_cli
# ---------------------------------------------------------------------------
if [ "$BUILD_TRIAGE" = true ]; then
  log "Building the Security Hub triage package into ${TRIAGE_BUILD_DIR}"

  rm -rf "$TRIAGE_BUILD_DIR"
  mkdir -p "$TRIAGE_BUILD_DIR"

  cp infrastructure/modules/security_hub_triage/src/handler.py "$TRIAGE_BUILD_DIR/"
  cp security-automation/finding_triage.py "$TRIAGE_BUILD_DIR/"
  cp security-automation/triage_config.json "$TRIAGE_BUILD_DIR/"
  cp -R security-automation/schemas "$TRIAGE_BUILD_DIR/"

  # No third-party dependencies: the handler uses only the standard library
  # plus boto3 from the managed runtime. `jsonschema` is optional and the tool
  # degrades gracefully without it, which keeps this artifact tiny.

  find "$TRIAGE_BUILD_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  find "$TRIAGE_BUILD_DIR" -type f -name '*.pyc' -delete 2>/dev/null || true

  if [ ! -f "$TRIAGE_BUILD_DIR/handler.py" ] || [ ! -f "$TRIAGE_BUILD_DIR/finding_triage.py" ]; then
    echo "error: triage package is incomplete" >&2
    exit 1
  fi

  log "Triage package size: $(du -sh "$TRIAGE_BUILD_DIR" | cut -f1)"
fi

log "Done. Next:"
echo "    cd infrastructure/terraform"
echo "    terraform init"
echo "    terraform plan -var-file=../environments/dev/terraform.tfvars"
