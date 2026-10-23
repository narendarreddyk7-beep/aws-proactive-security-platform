# ---------------------------------------------------------------------------
# Security Hub finding triage pipeline (optional module).
#
#   Security Hub CSPM -> EventBridge -> triage Lambda -> CloudWatch + SNS
#
# IMPORTANT: this module does NOT enable Security Hub. Enabling Security Hub is
# billed per security check and per finding ingested, and in a useful
# configuration it also enables AWS Config with its own per-configuration-item
# charge. That is a deliberate account-level decision, documented in
# docs/AWS_DEPLOYMENT.md §"Optional: Security Hub", not something a module
# should turn on as a side effect.
#
# With Security Hub disabled this module deploys cleanly and simply never
# receives an event, which is exactly the behaviour you want from an optional
# integration.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0, < 7.0.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0, < 3.0.0"
    }
  }
}

locals {
  function_name = "${var.name_prefix}-sh-triage"
}

# ---------------------------------------------------------------------------
# Deduplication table
#
# Security Hub re-imports a finding on every evaluation cycle. Without
# deduplication, one unremediated misconfiguration notifies the on-call every
# twelve hours forever, until they mute the topic -- at which point the
# alerting is worse than useless because it looks like it is working.
#
# TTL-expired so the table does not grow without bound and so a finding that
# reappears after the window is treated as news again.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "dedup" {
  name         = "${local.function_name}-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "fingerprint"

  attribute {
    name = "fingerprint"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # Unconditional. See the kms_key_arn variable description for why this is
  # not feature-flagged.
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # Deliberately no point-in-time recovery: this table holds only notification
  # fingerprints with a 24-hour TTL. Losing it causes at most one duplicate
  # notification, so paying for continuous backup would be waste.
  #
  #checkov:skip=CKV_AWS_28:Ephemeral notification-deduplication state with a 24h TTL; losing it costs one duplicate email.
  point_in_time_recovery {
    enabled = false
  }

  tags = merge(var.tags, { Name = "${local.function_name}-dedup" })
}

# ---------------------------------------------------------------------------
# Triage function
# ---------------------------------------------------------------------------

data "archive_file" "triage" {
  type        = "zip"
  source_dir  = var.lambda_build_dir
  output_path = "${path.module}/.build/${local.function_name}.zip"

  excludes = ["**/__pycache__", "**/*.pyc", "**/tests"]
}

resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${local.function_name}-logs" })
}

resource "aws_lambda_function" "triage" {
  function_name = local.function_name
  description   = "Normalizes, scores and deduplicates AWS Security Hub findings"

  role    = aws_iam_role.triage.arn
  handler = "handler.lambda_handler"
  runtime = var.lambda_runtime

  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256

  memory_size = 256
  timeout     = 30

  architectures = ["arm64"]

  # Bounded so a sudden flood of findings (someone enables a new standard
  # across 200 accounts) cannot consume the account's whole concurrency pool
  # and take the support API down with it.
  reserved_concurrent_executions = 2

  environment {
    variables = {
      DEDUP_TABLE_NAME  = aws_dynamodb_table.dedup.name
      SNS_TOPIC_ARN     = var.sns_topic_arn
      NOTIFY_SEVERITIES = join(",", [for s in var.notify_severities : lower(s)])
      DEDUP_TTL_HOURS   = tostring(var.dedup_ttl_hours)
      ENVIRONMENT       = var.environment
      LOG_LEVEL         = "INFO"
    }
  }

  kms_key_arn = var.kms_key_arn

  depends_on = [
    aws_cloudwatch_log_group.triage,
    aws_iam_role_policy.triage,
  ]

  tags = merge(var.tags, { Name = local.function_name })

  # Same documented exceptions as the API function; see
  # assessments/final-security-assessment.md §Accepted risks.
  #
  #checkov:skip=CKV_AWS_117:Reaches only DynamoDB, SNS and CloudWatch service endpoints; a VPC adds cost and latency with no security gain.
  #checkov:skip=CKV_AWS_116:EventBridge already retries and can dead-letter at the rule; a function-level DLQ would duplicate that.
  #checkov:skip=CKV_AWS_272:Code signing requires a Signer profile and a CI signing step; tracked as a planned improvement.
  #checkov:skip=CKV_AWS_50:X-Ray tracing on an asynchronous triage path adds cost without aiding this function's failure modes (which are logged).
}

# ---------------------------------------------------------------------------
# EventBridge rule
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${local.function_name}-imported-findings"
  description = "Route newly-imported Security Hub findings to the triage function"

  # Filtered at the rule, not in the function: a filtered-out event costs
  # nothing, whereas invoking the function to decide to ignore something costs
  # an invocation and a log line per finding.
  #
  # Only ACTIVE records are routed -- an ARCHIVED finding is one Security Hub
  # has already determined is no longer present.
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = [for s in var.route_severities : upper(s)]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })

  tags = merge(var.tags, { Name = "${local.function_name}-rule" })
}

resource "aws_cloudwatch_event_target" "triage" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SecurityHubTriageLambda"
  arn       = aws_lambda_function.triage.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  # An event that cannot be delivered after retries goes here rather than
  # being dropped. Losing a critical finding silently is the failure mode this
  # prevents.
  dead_letter_config {
    arn = aws_sqs_queue.triage_dlq.arn
  }
}

resource "aws_sqs_queue" "triage_dlq" {
  name = "${local.function_name}-dlq"

  message_retention_seconds = 1209600 # 14 days, the maximum
  kms_master_key_id         = var.kms_key_arn

  tags = merge(var.tags, { Name = "${local.function_name}-dlq" })
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid    = "AllowEventBridgeToSendFailedEvents"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.triage_dlq.arn]

    # Scoped to this one rule: without it, any EventBridge rule in the account
    # could write to this queue.
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.security_hub_findings.arn]
    }
  }

  statement {
    sid    = "DenyNonTlsAccess"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.triage_dlq.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "triage_dlq" {
  queue_url = aws_sqs_queue.triage_dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowInvokeFromSecurityHubRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"

  # Scoped to this specific rule, so no other rule in the account can invoke
  # the function.
  source_arn = aws_cloudwatch_event_rule.security_hub_findings.arn
}

# ---------------------------------------------------------------------------
# Alarm: a DLQ with anything in it means findings are not being triaged
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name = "${local.function_name}-dlq-not-empty"
  alarm_description = join(" ", [
    "Security Hub findings failed delivery to the triage function and are sitting",
    "in the dead-letter queue. Findings are NOT being triaged while this is firing.",
  ])

  namespace   = "AWS/SQS"
  metric_name = "ApproximateNumberOfMessagesVisible"
  statistic   = "Maximum"

  dimensions = {
    QueueName = aws_sqs_queue.triage_dlq.name
  }

  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  tags = merge(var.tags, {
    Name     = "${local.function_name}-dlq-not-empty"
    Severity = "high"
    Runbook  = "cloud-security-finding-response"
  })
}
