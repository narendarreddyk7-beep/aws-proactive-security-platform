# ---------------------------------------------------------------------------
# IAM for the triage function.
#
# Same principles as the API function's role (infrastructure/terraform/iam.tf):
# enumerate actions, scope resources, omit what the code does not call, and
# deny explicitly where the blast radius is large.
#
# Note what is absent: the function has NO Security Hub permissions at all. It
# receives findings pushed by EventBridge; it never calls GetFindings and never
# calls BatchUpdateFindings. Granting `securityhub:*` here -- the obvious thing
# to do -- would let a compromise of this function suppress findings across the
# account, which is precisely how an attacker would hide their activity.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "triage_assume_role" {
  statement {
    sid     = "AllowLambdaServiceToAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "triage" {
  name        = "${local.function_name}-role"
  description = "Execution role for the Security Hub finding triage function"

  assume_role_policy = data.aws_iam_policy_document.triage_assume_role.json

  max_session_duration = 3600

  tags = merge(var.tags, { Name = "${local.function_name}-role" })
}

data "aws_iam_policy_document" "triage" {
  # PutItem only. The function writes a deduplication fingerprint with a
  # conditional expression; it never reads the table back (the conditional
  # write IS the read) and never deletes -- TTL handles expiry.
  statement {
    sid    = "WriteDeduplicationFingerprints"
    effect = "Allow"

    actions = ["dynamodb:PutItem"]

    resources = [aws_dynamodb_table.dedup.arn]
  }

  statement {
    sid    = "WriteOwnLogsOnly"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.triage.arn}:*"]
  }

  dynamic "statement" {
    for_each = var.sns_topic_arn != "" ? [1] : []

    content {
      sid    = "PublishHighSeverityNotifications"
      effect = "Allow"

      actions   = ["sns:Publish"]
      resources = [var.sns_topic_arn]
    }
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []

    content {
      sid    = "DecryptOwnConfigurationAndData"
      effect = "Allow"

      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey",
      ]

      resources = [var.kms_key_arn]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values = [
          "lambda.${data.aws_region.current.name}.amazonaws.com",
          "dynamodb.${data.aws_region.current.name}.amazonaws.com",
          "sns.${data.aws_region.current.name}.amazonaws.com",
        ]
      }
    }
  }

  # Explicit denies. An explicit Deny cannot be overridden by an Allow in any
  # policy, so these stay shut regardless of what is attached later.
  statement {
    sid    = "DenySecurityHubMutationAndBulkReads"
    effect = "Deny"

    actions = [
      # Suppressing or archiving findings is how an attacker hides. This
      # function has no business doing either.
      "securityhub:BatchUpdateFindings",
      "securityhub:BatchImportFindings",
      "securityhub:UpdateFindings",
      "securityhub:DisableSecurityHub",
      "securityhub:DeleteInsight",
      "securityhub:GetFindings",
      # Reading the whole dedup table, or any other table.
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:DeleteTable",
      # Self-modification.
      "iam:*",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
    ]

    resources = ["*"]
  }
}

data "aws_region" "current" {}

resource "aws_iam_role_policy" "triage" {
  name   = "${local.function_name}-execution"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage.json
}
