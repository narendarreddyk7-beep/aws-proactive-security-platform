# ---------------------------------------------------------------------------
# CloudWatch: log groups, metric filters, alarms, saved queries, dashboard.
#
# DESIGN PRINCIPLE
# The application emits one JSON object per log line with a stable
# `event_type` field (see application/app/observability/logging.py). Metric
# filters turn specific `event_type` values into CloudWatch metrics, and
# alarms turn those metrics into pages. That chain is why the application
# logs `authorization_denied` as a structured event rather than a sentence:
# a denial that is not countable cannot be alerted on.
#
# WHAT THIS CAN AND CANNOT DETECT is documented in docs/SECURITY.md
# §"Monitoring coverage and blind spots" -- stating the blind spots is part
# of the control, because an alarm nobody understands the limits of produces
# false confidence.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Log groups
#
# Created by Terraform, not by first invocation, so retention and encryption
# are set from the very first log line. A group auto-created by Lambda has
# "Never expire" retention and no CMK.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn

  tags = {
    Name = "${local.name_prefix}-api-logs"
  }
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-access"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn

  tags = {
    Name = "${local.name_prefix}-access-logs"
  }
}

# ---------------------------------------------------------------------------
# SNS: alarm destination
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "security_alarms" {
  name = "${local.name_prefix}-security-alarms"

  # Encrypted so alarm payloads -- which carry tenant and principal
  # identifiers -- are not sitting in an unencrypted topic.
  kms_master_key_id = local.kms_key_arn

  tags = {
    Name = "${local.name_prefix}-security-alarms"
  }
}

data "aws_iam_policy_document" "sns_topic" {
  statement {
    sid    = "AllowCloudWatchAlarmsToPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alarms.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }

  # Without this, the topic's default policy permits publish from anything in
  # the account. Denying non-TLS access is cheap and closes a plaintext path.
  statement {
    sid    = "DenyNonTlsAccess"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["SNS:Publish", "SNS:Subscribe"]
    resources = [aws_sns_topic.security_alarms.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alarms" {
  arn    = aws_sns_topic.security_alarms.arn
  policy = data.aws_iam_policy_document.sns_topic.json
}

# Email subscriptions require the recipient to click a confirmation link, so
# the alarm is silent until they do. Left unset by default so an apply never
# emails anyone unexpectedly.
resource "aws_sns_topic_subscription" "security_alarms_email" {
  count = var.alarm_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ---------------------------------------------------------------------------
# Metric filters: structured security events -> metrics
# ---------------------------------------------------------------------------

locals {
  metric_namespace = "SupportPlatform/${var.environment}"

  # Each entry becomes a metric filter and (below) an alarm. The pattern
  # matches the JSON `event_type` field the application emits.
  security_metric_filters = {
    authorization_denied = {
      pattern     = "{ $.event_type = \"authorization_denied\" }"
      metric_name = "AuthorizationDenied"
      description = "A principal was refused access to a resource it is not permitted."
    }
    authentication_failed = {
      pattern     = "{ $.event_type = \"authentication_failed\" }"
      metric_name = "AuthenticationFailed"
      description = "A request arrived with no trusted identity."
    }
    unhandled_error = {
      pattern     = "{ $.event_type = \"unhandled_error\" }"
      metric_name = "UnhandledError"
      description = "An unexpected exception reached the global handler."
    }
    role_claim_mismatch = {
      pattern     = "{ $.event_type = \"role_claim_mismatch\" }"
      metric_name = "RoleClaimMismatch"
      description = "A token's role claim disagreed with the membership record."
    }
    # If this ever fires in a deployed environment, the insecure local
    # identity adapter is active and authentication is effectively disabled.
    # It should be impossible (config refuses to load), which is exactly why
    # it is worth a metric: it monitors the control, not just the traffic.
    insecure_identity_adapter = {
      pattern     = "{ $.event_type = \"insecure_identity_adapter_enabled\" }"
      metric_name = "InsecureIdentityAdapterEnabled"
      description = "CRITICAL: the header-trusting local identity adapter is enabled."
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "security_events" {
  for_each = local.security_metric_filters

  name           = "${local.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.lambda.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = local.metric_namespace
    value     = "1"
    # Report 0 when nothing matches, so the alarm has data and sits in OK
    # rather than INSUFFICIENT_DATA. An alarm stuck in INSUFFICIENT_DATA is
    # indistinguishable from an alarm that is not working.
    default_value = "0"
    unit          = "Count"
  }
}

# Counts 401s the authorizer rejected. These never reach Lambda, so the
# application log cannot see them -- the gateway access log is the only
# source. This is what distinguishes "someone is probing with bad tokens"
# from "our authorization policy is denying people".
resource "aws_cloudwatch_log_metric_filter" "gateway_unauthorized" {
  name           = "${local.name_prefix}-gateway-unauthorized"
  log_group_name = aws_cloudwatch_log_group.api_access.name
  pattern        = "{ $.status = 401 }"

  metric_transformation {
    name          = "GatewayUnauthorized"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "authorization_denied" {
  alarm_name = "${local.name_prefix}-authorization-denied-burst"
  alarm_description = join(" ", [
    "Sustained authorization denials.",
    "A handful is normal (a bookmarked link, a stale client).",
    "A burst is either a broken deployment or enumeration.",
    "Triage: runbooks/authorization-alert-triage.md",
  ])

  namespace   = local.metric_namespace
  metric_name = "AuthorizationDenied"
  statistic   = "Sum"

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = var.authorization_denied_alarm_threshold

  comparison_operator = "GreaterThanOrEqualToThreshold"

  # Absence of denials is a good state, not a missing-data problem.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]
  ok_actions    = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-authorization-denied-burst"
    Severity = "medium"
    Runbook  = "authorization-alert-triage"
  }
}

resource "aws_cloudwatch_metric_alarm" "role_claim_mismatch" {
  alarm_name = "${local.name_prefix}-role-claim-mismatch"
  alarm_description = join(" ", [
    "A token asserted a role that disagrees with the membership record.",
    "Benign cause: a user was demoted and still holds an old token.",
    "Malicious cause: someone is tampering with claims.",
    "Either way the membership record wins, so this is a signal, not a breach.",
  ])

  namespace   = local.metric_namespace
  metric_name = "RoleClaimMismatch"
  statistic   = "Sum"

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = 5

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-role-claim-mismatch"
    Severity = "medium"
    Runbook  = "authorization-alert-triage"
  }
}

# Threshold of 1: this must never happen in a deployed environment. The
# configuration refuses to load with the local adapter enabled, so a single
# occurrence means that control has been bypassed or removed.
resource "aws_cloudwatch_metric_alarm" "insecure_identity_adapter" {
  alarm_name = "${local.name_prefix}-insecure-identity-adapter"
  alarm_description = join(" ", [
    "CRITICAL: the header-trusting local identity adapter is enabled in a",
    "deployed environment. Authentication is effectively disabled.",
    "Act immediately: set reserved concurrency to 0 to stop traffic, then",
    "redeploy with APP_IDENTITY_SOURCE=gateway.",
  ])

  namespace   = local.metric_namespace
  metric_name = "InsecureIdentityAdapterEnabled"
  statistic   = "Sum"

  period             = 60
  evaluation_periods = 1
  threshold          = 1

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-insecure-identity-adapter"
    Severity = "critical"
    Runbook  = "authorization-alert-triage"
  }
}

resource "aws_cloudwatch_metric_alarm" "unhandled_errors" {
  alarm_name = "${local.name_prefix}-unhandled-errors"
  alarm_description = join(" ", [
    "Unexpected exceptions reaching the global handler.",
    "Each one returned a 500 to a caller.",
    "Correlate by request_id in the Lambda log group.",
  ])

  namespace   = local.metric_namespace
  metric_name = "UnhandledError"
  statistic   = "Sum"

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = var.error_rate_alarm_threshold

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-unhandled-errors"
    Severity = "high"
  }
}

# Lambda's own Errors metric catches what the application cannot log: an
# import-time crash, an out-of-memory kill, a timeout. Those produce no
# application log line at all, so the application-level alarm above would
# stay silent.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name = "${local.name_prefix}-lambda-errors"
  alarm_description = join(" ", [
    "Lambda-reported invocation errors, including cold-start import failures,",
    "timeouts and out-of-memory kills -- failures the application itself",
    "cannot log. A spike right after a deploy usually means a bad release;",
    "consider rolling back.",
  ])

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  statistic   = "Sum"

  dimensions = {
    FunctionName = aws_lambda_function.api.function_name
  }

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = var.error_rate_alarm_threshold

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-lambda-errors"
    Severity = "high"
  }
}

# Throttles mean the reserved concurrency ceiling was hit: either genuine load
# growth or a flood. Both need a human decision, and both are invisible in the
# application log because the invocation never started.
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name = "${local.name_prefix}-lambda-throttles"
  alarm_description = join(" ", [
    "The function is being throttled against its reserved concurrency.",
    "Either legitimate growth (raise lambda_reserved_concurrency) or a flood",
    "(check the gateway access log for a single source IP or principal).",
  ])

  namespace   = "AWS/Lambda"
  metric_name = "Throttles"
  statistic   = "Sum"

  dimensions = {
    FunctionName = aws_lambda_function.api.function_name
  }

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = 10

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-lambda-throttles"
    Severity = "medium"
  }
}

resource "aws_cloudwatch_metric_alarm" "gateway_unauthorized" {
  alarm_name = "${local.name_prefix}-gateway-unauthorized-burst"
  alarm_description = join(" ", [
    "A burst of 401s rejected by the JWT authorizer. These never reach",
    "Lambda, so nothing appears in the application log. Usually an expired",
    "client credential; a sustained burst from many IPs suggests token",
    "guessing or a leaked-then-rotated credential still in use.",
  ])

  namespace   = local.metric_namespace
  metric_name = "GatewayUnauthorized"
  statistic   = "Sum"

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = 50

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-gateway-unauthorized-burst"
    Severity = "medium"
    Runbook  = "authorization-alert-triage"
  }
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  alarm_name        = "${local.name_prefix}-dynamodb-throttles"
  alarm_description = "DynamoDB is throttling requests -- usually a hot partition (one very busy tenant)."

  namespace   = "AWS/DynamoDB"
  metric_name = "ThrottledRequests"
  statistic   = "Sum"

  dimensions = {
    TableName = aws_dynamodb_table.main.name
  }

  period             = var.alarm_evaluation_period_seconds
  evaluation_periods = 1
  threshold          = 5

  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alarms.arn]

  tags = {
    Name     = "${local.name_prefix}-dynamodb-throttles"
    Severity = "medium"
  }
}

# ---------------------------------------------------------------------------
# Saved CloudWatch Logs Insights queries
#
# Free, and they are the exact queries the runbooks tell an engineer to run.
# Saving them means a responder at 03:00 does not have to write a query
# against a log format they have never seen.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_query_definition" "authorization_denials_by_principal" {
  name = "${local.name_prefix}/authorization-denials-by-principal"

  log_group_names = [aws_cloudwatch_log_group.lambda.name]

  query_string = <<-QUERY
    fields @timestamp, principal_id, organization_id, resource_id, reason
    | filter event_type = "authorization_denied"
    | stats count(*) as denials by principal_id, organization_id, reason
    | sort denials desc
    | limit 50
  QUERY
}

resource "aws_cloudwatch_query_definition" "cross_tenant_probe_candidates" {
  name = "${local.name_prefix}/cross-tenant-probe-candidates"

  log_group_names = [aws_cloudwatch_log_group.lambda.name]

  # A principal generating many `resource_not_found` events is walking
  # identifiers. Because a cross-tenant read is indistinguishable from a
  # miss (finding F-008), this is the signal that replaces the 403 the API
  # deliberately does not return.
  query_string = <<-QUERY
    fields @timestamp, principal_id, organization_id, resource_id
    | filter event_type = "resource_not_found"
    | stats count(*) as misses, count_distinct(resource_id) as distinct_ids by principal_id
    | filter misses > 20
    | sort misses desc
    | limit 50
  QUERY
}

resource "aws_cloudwatch_query_definition" "request_trace" {
  name = "${local.name_prefix}/trace-one-request"

  log_group_names = [
    aws_cloudwatch_log_group.lambda.name,
    aws_cloudwatch_log_group.api_access.name,
  ]

  # Replace REPLACE_ME with the X-Request-Id the caller reported. This joins
  # the gateway's view and the application's view of one request.
  query_string = <<-QUERY
    fields @timestamp, @logStream, event_type, outcome, reason, http_status, message
    | filter request_id = "REPLACE_ME" or requestId = "REPLACE_ME"
    | sort @timestamp asc
    | limit 200
  QUERY
}

resource "aws_cloudwatch_query_definition" "unhandled_errors_by_type" {
  name = "${local.name_prefix}/unhandled-errors-by-type"

  log_group_names = [aws_cloudwatch_log_group.lambda.name]

  query_string = <<-QUERY
    fields @timestamp, reason, http_method, http_path, request_id
    | filter event_type = "unhandled_error"
    | stats count(*) as occurrences by reason, http_path
    | sort occurrences desc
    | limit 50
  QUERY
}

# ---------------------------------------------------------------------------
# Dashboard
#
# The first three dashboards in an account are free. One dashboard that shows
# the security signal next to the traffic signal is what makes "is this spike
# an attack or a launch?" answerable in seconds.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "${local.name_prefix}-security"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Security events (application)"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metric_namespace, "AuthorizationDenied"],
            [local.metric_namespace, "AuthenticationFailed"],
            [local.metric_namespace, "RoleClaimMismatch"],
            [local.metric_namespace, "InsecureIdentityAdapterEnabled"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Gateway rejections (401 at the authorizer)"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metric_namespace, "GatewayUnauthorized"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Function health"
          region = local.region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.api.function_name],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.api.function_name],
            ["AWS/Lambda", "Throttles", "FunctionName", aws_lambda_function.api.function_name],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Latency (p50 / p99)"
          region = local.region
          view   = "timeSeries"
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.api.function_name, { stat = "p50" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.api.function_name, { stat = "p99" }],
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        properties = {
          title  = "Recent authorization denials"
          region = local.region
          query = join(" ", [
            "SOURCE '${aws_cloudwatch_log_group.lambda.name}'",
            "| fields @timestamp, principal_id, organization_id, reason, resource_id",
            "| filter event_type = \"authorization_denied\"",
            "| sort @timestamp desc",
            "| limit 20",
          ])
          view = "table"
        }
      },
    ]
  })
}
