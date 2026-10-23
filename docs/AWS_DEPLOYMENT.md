# AWS Deployment

> ## ⚠️ Verification status — read this first
>
> **Nothing in this project has been deployed to AWS.** No AWS account was used at any
> point. The commands below are written from the Terraform configuration, not transcribed
> from a run that happened.
>
> **`terraform fmt` and `terraform validate` have now been run** — on 2026-10-23, on a
> separate machine with Terraform 1.17.0 and AWS provider 6.70.0, because the binary cannot
> be installed in the environment this repository was authored in
> (`releases.hashicorp.com` is outside its egress allow-list; the proxy returns
> `403 to CONNECT`, and routing around a policy denial is not an option).
>
> `validate` **failed on the first run** and found a real defect: a `templatefile` vars map
> that had drifted from the policy document it renders. It is fixed, the configuration is
> canonically formatted, and `validate` now reports
> `Success! The configuration is valid` with two `key_schema` deprecation warnings.
>
> **`terraform plan` and `terraform apply` have still never been executed**, because that
> needs an AWS account. Everything below the "Deploy" heading is written from the
> configuration, not transcribed from a run.
>
> What **has** been verified statically:
>
> | Check | Result |
> |---|---|
> | Checkov parsed all 10 `.tf` files + the module | 137 passed, 0 failed, 12 justified skips |
> | Custom HCL reference linter (`scripts/validate_terraform.py`) | Pass — root and module |
> | IAM policy analysis of the deployed policy documents | 1 INFO, 0 blocking |
> | Hardcoded account ids / credential-shaped literals | None found |
>
> Checkov's HCL parser reading every file successfully is **partial** evidence that the
> configuration parses. It is **not** provider-schema validation: an incorrect AWS argument
> name or type would not have been caught. Expect to fix something on your first
> `terraform validate`.
>
> Recorded as limitations **L1** and **L2** in
> [`../assessments/final-security-assessment.md`](../assessments/final-security-assessment.md).

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| AWS account | A **sandbox** account. Do not deploy a portfolio project into anything shared |
| Terraform | 1.9+ |
| AWS CLI | v2, configured with a profile |
| Permissions | Create/manage API Gateway, Lambda, Cognito, DynamoDB, IAM, KMS, CloudWatch, SNS. IAM and KMS are the privileged parts |
| Python | 3.12+, to build the Lambda package |

**Never put AWS credentials in this repository.** `.gitignore` blocks `*.tfvars`,
`*.tfstate*`, `.env` and `*.pem`. Use a named profile, SSO, or an assumed role:

```bash
export AWS_PROFILE=my-sandbox
aws sts get-caller-identity          # confirm WHICH account before anything else
```

### Guard rail: pin the target account

`variables.tf` exposes `allowed_account_ids`. Set it. The provider then refuses to run
against any other account, which is the cheapest possible protection against a deploy into
the wrong place.

```hcl
allowed_account_ids = ["123456789012"]   # your sandbox, not an example
```

---

## 2. Terraform state

The default configuration uses **local state**, which is fine for a sandbox and wrong for
anything shared. `backend.tf.example` holds a commented S3 + DynamoDB-lock backend.

```bash
cp infrastructure/terraform/backend.tf.example infrastructure/terraform/backend.tf
# edit: bucket, key, region, dynamodb_table
```

### Why state security matters here

Terraform state contains every resource identifier and attribute — table ARNs, the user
pool id, the app client id, role ARNs. It is not a secret store in this configuration (no
secret variables exist), but it is a **complete map of the environment** and enough to
reshape it. So:

- **Encrypt the bucket** (SSE-KMS), enable **versioning**, block **all public access**.
- **Restrict the bucket policy** to the deploying principal only.
- **Use DynamoDB state locking** so two applies cannot race.
- Never commit `backend.tf` with real values, and never commit `*.tfstate`.

---

## 3. Build the Lambda package

```bash
./scripts/build_lambda_package.sh
```

This produces a deployment directory containing `application/app/` plus its runtime
dependencies, which `data "archive_file" "lambda"` zips. `security-automation/` is **not**
included — it is repository tooling, not part of the function.

---

## 4. Deploy

```bash
cd infrastructure/terraform

terraform fmt -check -recursive
terraform init
terraform validate
terraform plan -var-file=../environments/dev/terraform.tfvars -out=tfplan
```

**Read the plan.** Specifically confirm:

- The IAM role policy matches `policies/lambda-execution.json` — enumerated actions, no
  wildcards, and every `Deny` statement present.
- **The membership table grant is `dynamodb:GetItem` and nothing else**, with the
  `DenyAllWritesToAuthorizationSourceOfTruth` statement present. If the plan shows any
  write action against the membership table, stop — that is risk T-06.
- The Cognito app client has **no** write access to `custom:organization_id` or
  `custom:role`. This is the control that stops self-granted privilege (finding F-002); if
  the plan shows those as writable, stop.
- `APP_IDENTITY_SOURCE=gateway` on the Lambda environment. If it says `local_test`, stop —
  that is an authentication bypass (finding F-001).
- The authorizer's `issuer` and `audience` are both populated.
- No resource is unexpectedly public.

```bash
terraform apply tfplan
```

### Post-apply checklist

The configuration emits a `post_apply_checklist` output. At minimum:

```bash
# 1. The API answers, and only /v1/health is public
API=$(terraform output -raw api_endpoint)
curl -s "$API/v1/health"
curl -s -o /dev/null -w '%{http_code}\n' "$API/v1/tickets"     # expect 401

# 2. Confirm the identity source is NOT the local adapter
aws lambda get-function-configuration \
  --function-name "$(terraform output -raw lambda_function_name)" \
  --query 'Environment.Variables.APP_IDENTITY_SOURCE'          # expect "gateway"

# 3. Confirm the role genuinely cannot write a membership (T-06 / AR-04).
#    This SHOULD fail with AccessDeniedException. If it succeeds, stop.
aws lambda invoke --function-name "$(terraform output -raw lambda_function_name)" \
  --payload '{}' /dev/null 2>/dev/null || true
aws iam simulate-principal-policy \
  --policy-source-arn "$(terraform output -raw lambda_execution_role_arn)" \
  --action-names dynamodb:PutItem \
  --resource-arns "$(terraform output -raw membership_table_arn)" \
  --query 'EvaluationResults[0].EvalDecision'          # expect "explicitDeny"

# 4. Confirm the insecure-adapter alarm has never fired
aws cloudwatch describe-alarm-history \
  --alarm-name "$(terraform output -raw security_dashboard_url >/dev/null; echo '<prefix>-insecure-identity-adapter')" \
  --max-records 5
```

### Create a user and seed a membership

Authentication needs a Cognito user; authorization needs a **membership record**, which the
API deliberately cannot create — and, since 2026-10-23, deliberately *cannot be permitted*
to create: memberships live in their own table and the execution role holds `GetItem` on it
and no write action at all (see [`ARCHITECTURE.md`](ARCHITECTURE.md) D16). So the record
below is written with **your** credentials, not the function's.

```bash
POOL=$(terraform output -raw cognito_user_pool_id)
CLIENT=$(terraform output -raw cognito_user_pool_client_id)
TABLE=$(terraform output -raw dynamodb_table_name)
MEMBERSHIP_TABLE=$(terraform output -raw membership_table_name)

aws cognito-idp admin-create-user \
  --user-pool-id "$POOL" --username demo-member \
  --user-attributes Name=email,Value=demo@example.com Name=email_verified,Value=true \
                    Name=custom:organization_id,Value=org-acme Name=custom:role,Value=member

aws cognito-idp admin-set-user-password \
  --user-pool-id "$POOL" --username demo-member --password '<a strong password>' --permanent

SUB=$(aws cognito-idp admin-get-user --user-pool-id "$POOL" --username demo-member \
      --query 'UserAttributes[?Name==`sub`].Value' --output text)

# The authoritative role lives HERE, not in the token (finding F-002), and in the
# MEMBERSHIP table, which the Lambda can read but not write (T-06 / AR-04).
aws dynamodb put-item --table-name "$MEMBERSHIP_TABLE" --item "{
  \"PK\": {\"S\": \"USER#$SUB\"},
  \"SK\": {\"S\": \"MEMBERSHIP#org-acme\"},
  \"entity_type\": {\"S\": \"membership\"},
  \"role\": {\"S\": \"member\"},
  \"status\": {\"S\": \"active\"}
}"
```

> `custom:role` is set on the Cognito user for completeness, but the application ignores it
> for decisions. Set the token claim to `admin` and leave the record as `member`, and the
> caller is a member — with a `role_claim_mismatch` event logged. That is worth doing once
> as a live check of F-002.

Get a token and call the API:

```bash
TOKEN=$(aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH \
  --client-id "$CLIENT" \
  --auth-parameters USERNAME=demo-member,PASSWORD='<password>' \
  --query 'AuthenticationResult.AccessToken' --output text)

curl -s -X POST "$API/v1/tickets" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Deployment smoke test","description":"Synthetic","priority":"low"}'
```

### Run the AWS-gated tests

This is the whole point of deploying, and the highest-value step on this page:

```bash
cd ../..
export SUPPORT_API_BASE_URL="$API"
export SUPPORT_API_ACCESS_TOKEN="$TOKEN"
export SUPPORT_API_TABLE_NAME="$TABLE"
export SUPPORT_API_ROLE_ARN="$(cd infrastructure/terraform && terraform output -raw lambda_execution_role_arn)"
export SUPPORT_API_MEMBERSHIP_TABLE_ARN="$(cd infrastructure/terraform && terraform output -raw membership_table_arn)"
# For the expiry test, capture a token and wait for it to expire
export SUPPORT_API_EXPIRED_TOKEN="<an expired access token>"

python -m pytest -m aws -v
```

Those 13 tests cover exactly what cannot be proven locally: gateway rejection of expired
and wrongly-issued tokens, real IAM enforcement of the `Scan`/`DeleteItem` denials, and —
most importantly — that writes to the **membership table** evaluate to `explicitDeny` under
real IAM while `GetItem` still evaluates to `allowed` (T-06 / AR-04). Running them converts
the project's largest assurance gap into evidence.

---

## 5. Cost

The default development configuration is designed to sit inside the AWS Free Tier, and the
expensive options are **off by default**.

| Service | Dev configuration | Expected cost |
|---|---|---|
| Lambda | 512 MB, 10 s timeout, 5 reserved concurrency, arm64 | Free tier: 1M requests/month |
| API Gateway HTTP API | Throttled 20 rps / 40 burst | Free tier: 1M requests/month for 12 months |
| DynamoDB | On-demand, PITR on | Free tier: 25 GB + 25 WCU/RCU. PITR adds a small per-GB charge |
| Cognito | User pool, MFA optional, advanced security **OFF** | Free tier: 50,000 MAU. **Advanced security is billed per MAU — it is `OFF` in dev and `ENFORCED` in prod** |
| CloudWatch Logs | 30-day retention, CMK-encrypted | Free tier: 5 GB ingest. Retention is 365 days in prod |
| CloudWatch alarms | 8 alarms | First 10 alarms free |
| KMS | 1 customer-managed key | **~$1/month, not free tier.** Plus per-request charges |
| SNS | Topic, no subscription unless `alarm_email` is set | Effectively free |
| X-Ray | **`enable_xray = false`** in dev | Would be billed per trace |
| Security Hub | **Not enabled by this configuration at all** | See §7 |

**Realistic dev cost: roughly $1–3/month**, dominated by the KMS key, assuming light
traffic.

### Things that will surprise you if you are not careful

1. **KMS is not free tier.** One CMK is about $1/month whether used or not.
2. **Cognito advanced security is per-MAU.** `ENFORCED` in `prod.tfvars`. Fine for a real
   service, a waste for a demo.
3. **PITR is billed per GB of table size.** Tiny here, not zero.
4. **Enabling Security Hub usually enables AWS Config**, which bills per configuration item
   recorded. This is the single biggest cost trap in this stack, which is why the
   configuration refuses to do it for you (§7).
5. **X-Ray in `prod.tfvars` is `true`.** Deliberate for a production-like posture; it costs
   money.

---

## 6. Teardown

```bash
cd infrastructure/terraform
terraform destroy -var-file=../environments/dev/terraform.tfvars
```

### Things that block or survive a destroy

| Resource | Behaviour |
|---|---|
| DynamoDB table | `enable_deletion_protection = false` in dev (destroys cleanly); **`true` in prod** — you must disable it first |
| KMS key | Enters a **7–30 day pending-deletion window**; it is not billed during the wait but is not gone either |
| CloudWatch log groups | Terraform-managed, so destroyed. Any group auto-created by Lambda outside Terraform would survive |
| Cognito users | Destroyed with the pool. Export anything you need first |
| S3 state bucket | **Not managed by this configuration.** Delete it yourself if you created one |
| Security Hub / AWS Config | **Not managed here.** If you enabled them manually, disable them manually — this is where surprise bills come from |

Confirm nothing is left:

```bash
terraform state list                    # expect empty
aws dynamodb list-tables
aws cognito-idp list-user-pools --max-results 10
aws kms list-aliases | grep support     # expect the key pending deletion
```

---

## 7. Optional: Security Hub integration

The pipeline (EventBridge rule → triage Lambda → CloudWatch, optional SNS) is implemented in
`infrastructure/modules/security_hub_triage/` and is **off by default**.

**Two separate decisions, deliberately not conflated:**

1. **Deploying the triage pipeline** — cheap. An EventBridge rule, a small Lambda, and a
   DynamoDB table for notification deduplication. Controlled by
   `enable_security_hub_integration = true`.
2. **Enabling Security Hub itself** — **this configuration does not do it.** Security Hub
   bills per security check and per finding ingested, and in most useful configurations it
   also enables AWS Config, which bills per configuration item. Turning that on from a
   portfolio project's `terraform apply` would be a genuinely unpleasant surprise.

If you want it, enable it yourself, consciously:

```bash
aws securityhub enable-security-hub --enable-default-standards
# Then:  enable_security_hub_integration = true   and re-apply
```

To disable:

```bash
# Set enable_security_hub_integration = false, apply, then:
aws securityhub disable-security-hub
# And check AWS Config separately — it is the part that keeps billing:
aws configservice describe-configuration-recorders
```

The triage logic is fully unit-tested against synthetic ASFF events (38 tests in
`security-automation/tests/test_security_hub_handler.py`), so **the capability is
demonstrable with Security Hub never enabled**. End-to-end event delivery is unverified
(limitation L6).

---

## 8. Production hardening

`environments/prod/terraform.tfvars` makes the posture difference explicit. The delta is
the interesting part:

| Setting | dev | prod | Why |
|---|---|---|---|
| `lambda_memory_mb` | 512 | 1024 | Throughput |
| `lambda_reserved_concurrency` | 5 | 50 | Capacity, still capped |
| `enable_xray` | `false` | `true` | Tracing is worth paying for in production |
| `api_throttling_rate_limit` | 20 | 200 | |
| `enable_scope_enforcement` | `false` | `true` | Routes require an explicit Cognito scope |
| `cognito_mfa_configuration` | `OPTIONAL` | **`ON`** | T-02: token theft needs a harder credential step |
| `cognito_advanced_security_mode` | `OFF` | **`ENFORCED`** | Adaptive auth + compromised-credential detection |
| `enable_deletion_protection` | `false` | **`true`** | A destroy must not be casual |
| `log_retention_days` | 30 | 365 | Investigation window |
| `authorization_denied_alarm_threshold` | 3 | 25 | Dev is noisy; prod needs a real signal |
| `alarm_email` | `""` | on-call address | |
| `enable_security_hub_integration` | `false` | `true` | |

### Before a real production deployment

Not optional, and not yet done in this project:

- [ ] **Run `terraform validate` and `plan`** — never done here (L2)
- [ ] **Run the 13 AWS-gated tests** — the only way to verify D1 and the IAM denials
- [x] ~~**Separate the membership table** so the execution role is read-only on it~~ —
      done 2026-10-23 (AR-04 closed)
- [ ] Remote state with encryption, versioning and locking
- [ ] CI/CD deployment via **OIDC** — no long-lived AWS keys anywhere
- [ ] AWS WAF rate-based rules in front of the API (AR-05)
- [ ] CloudWatch **billing alarm**
- [ ] Subscribe a real on-call address to the SNS topic and **test that it delivers**
- [ ] Tune the alarm thresholds against real traffic — the current values are reasoned
      estimates that have never fired
- [ ] An independent security review (limitation L7)
