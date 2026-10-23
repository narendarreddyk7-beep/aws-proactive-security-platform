# ---------------------------------------------------------------------------
# Shared locals, data sources and the customer-managed KMS key.
#
# Resource-type files: dynamodb.tf, cognito.tf, lambda.tf, api.tf, iam.tf,
# monitoring.tf. Everything cross-cutting lives here.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = var.aws_region

  is_production = var.environment == "prod"

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "aws-proactive-security-platform"
      # Tagged so that a cost or security review can tell at a glance which
      # resources hold customer data and which are plumbing.
      DataClassification = "internal-synthetic"
    },
    var.tags
  )

  # Resolved once so every consumer references the same value, whether or not
  # the customer-managed key was created.
  kms_key_arn = var.create_kms_key ? aws_kms_key.main[0].arn : null
}

# ---------------------------------------------------------------------------
# KMS
#
# One key for DynamoDB, CloudWatch Logs, SNS and Lambda environment
# variables. A single key keeps the key policy reviewable; separate keys per
# service would be better isolation but triples the monthly cost and the
# number of policies to get right, which is the wrong trade at this scale.
# ---------------------------------------------------------------------------

resource "aws_kms_key" "main" {
  count = var.create_kms_key ? 1 : 0

  description = "${local.name_prefix}: encryption at rest for DynamoDB, logs, SNS and Lambda env vars"

  # Annual automatic rotation. Old key material is retained so previously
  # encrypted data stays readable.
  enable_key_rotation = true

  # 7 days in dev so a mistaken destroy can be undone quickly without paying
  # for a long window; 30 in production to leave room to notice.
  deletion_window_in_days = local.is_production ? 30 : 7

  policy = data.aws_iam_policy_document.kms_key_policy.json

  tags = {
    Name = "${local.name_prefix}-key"
  }
}

resource "aws_kms_alias" "main" {
  count = var.create_kms_key ? 1 : 0

  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.main[0].key_id
}

data "aws_iam_policy_document" "kms_key_policy" {
  # The account root retains administrative control. Without this statement the
  # key becomes unmanageable -- there is no "break glass" for a KMS key whose
  # policy denies everyone.
  statement {
    sid    = "AllowAccountAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CloudWatch Logs encrypts log data with the key on our behalf, so the
  # service principal needs these actions. The two conditions are what stop
  # this from being a general grant to the logs service: it may only act for
  # this account, and only for log groups belonging to this deployment.
  statement {
    sid    = "AllowCloudWatchLogsEncryption"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}*",
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/apigateway/${local.name_prefix}*",
      ]
    }
  }

  # CloudWatch Alarms publish to the SNS topic, which is encrypted with this
  # key, so the alarm service must be able to generate a data key.
  statement {
    sid    = "AllowCloudWatchAlarmsToPublishToEncryptedTopic"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# ---------------------------------------------------------------------------
# Deployment-time guard rails
#
# `check` blocks surface a warning on every plan/apply without blocking it.
# Used here for posture choices that are acceptable in dev but should be
# noticed, rather than for hard failures (which belong in variable
# validation).
# ---------------------------------------------------------------------------

check "production_hardening" {
  assert {
    condition = !local.is_production || var.cognito_mfa_configuration == "ON"
    error_message = join(" ", [
      "Production deployment without mandatory MFA.",
      "Set cognito_mfa_configuration = \"ON\" in the production tfvars.",
    ])
  }

  assert {
    condition = !local.is_production || var.cognito_advanced_security_mode == "ENFORCED"
    error_message = join(" ", [
      "Production deployment without Cognito threat protection.",
      "Set cognito_advanced_security_mode = \"ENFORCED\" (note: billed per monthly active user).",
    ])
  }

  assert {
    condition = !local.is_production || var.enable_deletion_protection
    error_message = "Production deployment without DynamoDB deletion protection."
  }

  assert {
    condition     = !local.is_production || var.create_kms_key
    error_message = "Production deployment without a customer-managed KMS key."
  }

  assert {
    condition = !local.is_production || length(var.allowed_account_ids) > 0
    error_message = join(" ", [
      "Production deployment with no allowed_account_ids guard.",
      "Set it so a dev plan cannot be applied to the production account.",
    ])
  }
}
