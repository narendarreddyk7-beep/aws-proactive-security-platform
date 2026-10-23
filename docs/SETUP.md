# Local Setup

Everything in this project runs on a laptop with **no AWS account, no credentials and no
Docker**. That is deliberate: a security project nobody can run is a security project
nobody will check.

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | **3.12+** | `requires-python = ">=3.12"`. Verified on 3.13.17 |
| git | any recent | Needed for the before/after regression experiment |
| Terraform | 1.9+ | **Optional.** Only for `fmt`/`validate`/`plan`. Everything else works without it |

No AWS account. No Docker. No DynamoDB Local.

---

## 2. Install

```bash
git clone <repository-url>
cd aws-proactive-security-platform

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

`-e '.[dev]'` installs the runtime dependencies (`fastapi`, `pydantic`,
`pydantic-settings`, `mangum`, `boto3`) plus the full toolchain: `pytest`, `pytest-cov`,
`httpx`, `moto[dynamodb]`, `ruff`, `bandit`, `pip-audit`, `checkov`, `jsonschema`.

### Verify the install

```bash
python -m pytest -q
```

Expected:

```
603 passed, 13 skipped
```

The 13 skips are correct and expected — they require a deployed AWS environment and name
the missing prerequisite. See [`TESTING.md`](TESTING.md).

---

## 3. Run the API locally

```bash
python scripts/local_server.py
```

This starts the **real application** — real routes, real authorization policy, real
repository code — against an in-process mocked DynamoDB, seeded with synthetic membership
records. It prints the demo identities on startup.

```
==============================================================================
  Multi-Tenant Customer Support API — LOCAL DEMO
==============================================================================
  URL          http://127.0.0.1:8000
  Docs         http://127.0.0.1:8000/docs
  Storage      in-process moto (nothing persists, no AWS account used)

  IDENTITY IS READ FROM HEADERS. This is the F-012 local adapter and
  cannot load unless APP_ENVIRONMENT=local. Not a production path.
```

Smoke test it:

```bash
curl -s http://127.0.0.1:8000/v1/health
# {"status":"ok","service":"ticket-api","version":"1.0.0","environment":"local"}
```

Then follow [`DEMO.md`](DEMO.md) for the full walkthrough.

### How local authentication works, and why it is safe

In AWS, identity comes **only** from the API Gateway JWT authorizer context. There is no
gateway on a laptop, so the local server sets `APP_IDENTITY_SOURCE=local_test`, which
activates an adapter that reads identity from `X-Local-*` headers.

**That adapter is a deliberate authentication bypass** — it is the subject of finding
F-012 — and three independent controls keep it out of any deployed environment:

1. `Settings` **refuses to load** `identity_source=local_test` unless
   `APP_ENVIRONMENT=local`; the Lambda fails to initialise rather than starting insecurely.
2. `LocalTestIdentityProvider.__init__` raises on the same condition, so removing the
   config guard is not sufficient to re-enable it.
3. `gateway` is the **default**, and Terraform sets `APP_IDENTITY_SOURCE=gateway`
   explicitly on the function — so the value never depends on a default.

Constructing the adapter also emits `insecure_identity_adapter_enabled`, which has a
CloudWatch alarm at threshold 1. You will see that warning in the local log; in AWS it
should never appear.

The headers are prefixed `X-Local-` precisely so they cannot be confused with a real
identity header and can be stripped at the edge with a single WAF rule.

```bash
# Prove the guard works:
APP_ENVIRONMENT=production APP_IDENTITY_SOURCE=local_test python -c 'from app.config import get_settings; get_settings()'
# raises: identity_source='local_test' is only permitted when environment='local'
```

The local server binds to **loopback** by default. `--host 0.0.0.0` exists but exposing an
authentication-bypassed service to a network is a bad idea; do not.

---

## 4. Run the security checks

The whole pipeline, in the same order and with the same gating as CI:

```bash
./scripts/run_security_checks.sh
```

```
Passed: 16   Failed: 0
```

| Flag | Effect |
|---|---|
| *(none)* | Everything, gated — non-zero exit if any stage fails |
| `--no-gate` | Run everything, report, always exit 0. Useful for a first look |
| `--fast` | Skip the slow Checkov scan |

Reports are written to `reports/` (gitignored).

If this script passes and CI fails, the two have drifted — that is a bug in the pipeline,
not something to work around.

### Or run the tools individually

```bash
ruff check . && ruff format --check .                      # lint + format
python -m bandit -c pyproject.toml -r application/ security-automation/ -ll
python -m pip_audit --requirement application/requirements.txt --strict
python -m checkov.main -d infrastructure/ --framework terraform --compact --quiet
python scripts/validate_terraform.py infrastructure/terraform

python security-automation/iam_policy_checker.py \
  --input infrastructure/terraform/policies/ --output reports/iam-findings.json

python security-automation/finding_triage.py \
  --input sample-data/findings.json \
  --output reports/triage-report.json --markdown reports/triage-report.md
```

---

## 5. Configuration reference

All settings use the `APP_` prefix. **Every default is the safe value**, so a missing
variable degrades towards security rather than away from it (finding F-012).

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENVIRONMENT` | `dev` | `local` \| `test` \| `dev` \| `staging` \| `production`. Gates the local adapter and the interactive docs |
| `APP_IDENTITY_SOURCE` | **`gateway`** | `gateway` \| `local_test`. The most security-relevant setting in the project |
| `APP_DEBUG` | `False` | Never enable in a deployed environment |
| `APP_TABLE_NAME` | `support-platform-dev` | Ticket table |
| `APP_MEMBERSHIP_TABLE_NAME` | `support-platform-dev-memberships` | **Separate** membership table. The execution role holds `GetItem` on it and no write action, which is a boundary IAM can enforce — see `docs/ARCHITECTURE.md` D16 |
| `APP_AWS_REGION` | `us-east-1` | Region for the DynamoDB client |
| `APP_DYNAMODB_ENDPOINT_URL` | *(unset)* | Local DynamoDB override. Centralised in one factory so it cannot leak into a production path |
| `APP_DEFAULT_PAGE_SIZE` | `25` | Default page size; hard ceiling is 100 |
| `APP_CORS_ALLOW_ORIGINS` | `""` | **Empty = no cross-origin access.** Never `*` with credentials |
| `APP_LOG_LEVEL` | `INFO` | |
| `APP_BIND_HOST` | `127.0.0.1` | Development server bind address only |

Invalid values fail at load rather than falling back silently: `identity_source` and
`environment` are `Literal` types.

---

## 6. Repository layout

```
application/app/         FastAPI service — the code that is reviewed
  security/              identity, authorization policy, errors, HTTP headers
  repositories/          tenant-scoped DynamoDB access, keys, pagination
  services/              business rules + the single authorization enforcement layer
  models/                Pydantic request/response/domain models
  observability/         structured JSON logging with a field allow-list
infrastructure/terraform/  10 .tf files + committed IAM policy JSON
security-automation/     two CLI tools + their tests
tests/                   unit / integration / security / fixtures
threat-model/            architecture, data flow, STRIDE, requirements, risk register
assessments/             review checklist, findings, remediation, evidence, reports
runbooks/                incident response
scripts/                 local server, pipeline runner, HCL linter, Lambda packager
docs/                    this directory
```

---

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError: No module named 'app'` | Install the package: `pip install -e '.[dev]'`. `pytest` is configured with `pythonpath = ["application", "."]`, so tests work without it — the server needs it |
| `identity_source='local_test' is only permitted when environment='local'` | The guard working as designed. Use `scripts/local_server.py`, which sets both |
| `NoCredentialsError` when running the server directly | Use `scripts/local_server.py` — it starts the moto mock and sets placeholder credentials. Running `uvicorn app.main:app` alone has no backing store |
| Checkov is slow | Expected (~30–60 s). Use `./scripts/run_security_checks.sh --fast` while iterating |
| `terraform: command not found` | Optional. Everything except `fmt`/`validate`/`plan` works without it. See [`AWS_DEPLOYMENT.md`](AWS_DEPLOYMENT.md) |
| Port 8000 in use | `python scripts/local_server.py --port 8001` |
| Tests pass but the server 500s | Check the JSON log line — the `reason` field carries the exception type. Full trace is log-side only, by design (finding F-008) |
