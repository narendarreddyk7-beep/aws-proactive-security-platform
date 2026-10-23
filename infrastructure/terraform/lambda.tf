# ---------------------------------------------------------------------------
# AWS Lambda: the FastAPI application behind Mangum.
#
# Handler: app.main.handler  (see application/app/main.py)
#
# PREREQUISITE: the deployment package contents must exist at
# `var.lambda_build_dir` before `terraform plan`, because the archive is
# hashed to decide whether the function needs updating. Build it with:
#
#     ./scripts/build_lambda_package.sh
#
# A missing build directory produces a clear archive_file error rather than a
# silently empty function.
# ---------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_build_dir
  output_path = "${path.module}/.build/${local.name_prefix}-lambda.zip"

  # Deterministic timestamps so an unchanged build produces an unchanged hash
  # and `terraform plan` stays empty. Without this, every plan shows a
  # function update and real changes become invisible in the noise.
  excludes = [
    "**/__pycache__",
    "**/*.pyc",
    "**/*.pyo",
    "**/*.dist-info/RECORD",
    "**/tests",
  ]
}

resource "aws_lambda_function" "api" {
  function_name = "${local.name_prefix}-api"
  description   = "Multi-tenant customer support API (FastAPI via Mangum)"

  role    = aws_iam_role.lambda.arn
  handler = "app.main.handler"
  runtime = var.lambda_runtime

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  # Memory determines CPU on Lambda, so this is really a latency knob. 512 MB
  # imports FastAPI + Pydantic at cold start without paying for idle capacity.
  memory_size = var.lambda_memory_mb

  # Short on purpose. Every request is a couple of single-digit-millisecond
  # DynamoDB calls, so a long timeout only buys an attacker a cheaper
  # denial-of-wallet lever and holds concurrency open during an incident.
  timeout = var.lambda_timeout_seconds

  # Caps both the blast radius of a runaway loop and the maximum spend from a
  # request flood. Without a reservation, one API can consume the whole
  # account's concurrency and take unrelated functions down with it.
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  architectures = ["arm64"]

  environment {
    variables = {
      # --- Identity -----------------------------------------------------
      # Set EXPLICITLY to `gateway`, never left to the default. The
      # application also defaults to `gateway` and refuses to load
      # `local_test` outside `environment=local` (finding F-012), so this is
      # the third independent control on the same bypass.
      APP_IDENTITY_SOURCE = "gateway"
      APP_ENVIRONMENT     = var.environment

      # --- Storage ------------------------------------------------------
      APP_TABLE_NAME            = aws_dynamodb_table.main.name
      APP_MEMBERSHIP_TABLE_NAME = aws_dynamodb_table.memberships.name
      APP_AWS_REGION            = local.region

      # --- Behaviour ----------------------------------------------------
      APP_DEBUG              = "false"
      APP_LOG_LEVEL          = local.is_production ? "INFO" : "INFO"
      APP_CORS_ALLOW_ORIGINS = join(",", var.cors_allowed_origins)
      APP_DEFAULT_PAGE_SIZE  = "25"
      APP_SERVICE_NAME       = "ticket-api"
    }
  }

  # Environment variables are encrypted at rest with an AWS-managed key by
  # default; this upgrades them to the customer-managed key so the same key
  # policy governs configuration and data.
  #
  # Note: nothing secret is stored here. Anything secret would belong in
  # Secrets Manager or SSM Parameter Store and be fetched at cold start --
  # Lambda environment variables are visible to anyone with
  # `lambda:GetFunctionConfiguration`.
  kms_key_arn = local.kms_key_arn

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  # Terraform owns the log group (monitoring.tf) so that retention and
  # encryption are set from the start. Without this dependency, the first
  # invocation can create an unencrypted, never-expiring group first and win
  # the race.
  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_execution,
  ]

  tags = {
    Name = "${local.name_prefix}-api"
  }

  # ---- Documented Checkov exceptions ------------------------------------
  #
  # These are engineering decisions, not suppressions of inconvenient
  # findings. Each is recorded with its reasoning in
  # `assessments/final-security-assessment.md` §Accepted risks, and each is
  # scoped to this single resource rather than disabled repository-wide.
  #
  # CKV_AWS_117 (Lambda in a VPC): this function talks only to DynamoDB,
  #   CloudWatch Logs and KMS -- all AWS service endpoints. A VPC would add
  #   NAT gateway cost (~USD 32/month), ENI cold-start latency, and a subnet
  #   and route table to misconfigure, in exchange for no reduction in the
  #   reachable attack surface. Revisit if the function ever needs to reach a
  #   private resource such as RDS.
  #
  # CKV_AWS_116 (dead-letter queue): a DLQ only applies to asynchronous
  #   invocations. Every invocation here is synchronous from API Gateway, so a
  #   failure is returned to the caller as a 500 and recorded in CloudWatch --
  #   there is no event to replay. Adding one would be theatre.
  #
  # CKV_AWS_272 (code signing): worthwhile for a published artifact, but it
  #   requires a Signer profile and a signing step in CI. Recorded as a
  #   planned improvement rather than silenced.
  #
  #checkov:skip=CKV_AWS_117:No private resources are reached; a VPC adds cost and latency with no security gain. See assessments/final-security-assessment.md
  #checkov:skip=CKV_AWS_116:Synchronous API invocations only; a DLQ has no event to replay. See assessments/final-security-assessment.md
  #checkov:skip=CKV_AWS_272:Code signing requires a Signer profile and CI signing step; tracked as a planned improvement.
}

# ---------------------------------------------------------------------------
# Invoke permission
#
# `source_arn` is scoped to this API's execution ARN. Without it, ANY API
# Gateway API in the account could invoke this function -- a common and quiet
# over-permission.
# ---------------------------------------------------------------------------

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowInvokeFromThisHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}
