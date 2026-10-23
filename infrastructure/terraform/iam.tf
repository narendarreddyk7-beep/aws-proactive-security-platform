# ---------------------------------------------------------------------------
# IAM: the Lambda execution role.
#
# This file is the remediation for finding F-005. The first draft granted:
#
#     { "Effect": "Allow", "Action": "dynamodb:*", "Resource": <table arn> }
#     { "Effect": "Allow", "Action": "logs:*",     "Resource": "*"         }
#
# That is a role which can delete the table, read every tenant's data with a
# single Scan, and read or delete any log group in the account. The project's
# own `security-automation/iam_policy_checker.py` flags both statements; the
# before/after documents and the real checker output are in
# `assessments/security-findings.md` (F-005).
#
# WHY THE POLICIES ARE JSON FILES, NOT `aws_iam_policy_document`
# ---------------------------------------------------------------
# `aws_iam_policy_document` is only rendered by the provider at plan time, so
# the resulting policy cannot be inspected without running Terraform against
# an AWS account. Keeping the documents as committed JSON templates in
# `policies/` means:
#
#   * CI stage 3 runs the IAM checker against the policy that is actually
#     deployed, with no hand-maintained copy to drift (see
#     `.github/workflows/security-ci.yml`);
#   * the diff of a permission change is reviewable in a pull request as a
#     policy diff rather than as HCL;
#   * `${table_arn}`-style placeholders sit inside JSON string values, so the
#     files remain valid JSON and any policy linter can read them.
#
# PRINCIPLES APPLIED
# ------------------
# 1. Enumerate actions. No `dynamodb:*`, no `logs:*`, no bare `*`.
# 2. Scope resources to ARNs.
# 3. Omit what the application does not do: no `Scan`, `DeleteItem`,
#    `UpdateItem`, `BatchWriteItem`, or `CreateLogGroup`. A future change that
#    needs one fails with AccessDenied, which forces the permission through
#    review instead of letting it arrive silently.
# 4. Deny explicitly where the blast radius is large. An explicit Deny cannot
#    be overridden by an Allow in any policy, so `Scan` and `DeleteTable` stay
#    shut even if someone attaches a broad policy to this role later.
# 5. Cap the role with a permissions boundary, so a change-management failure
#    still cannot widen it.
# 6. Put the authorization source of truth in its own table, so "read
#    memberships, write only tickets" is expressible in IAM at all.
#
# WHY #6 REQUIRED A SECOND TABLE
# ------------------------------
# The function needs `PutItem` to create tickets. While memberships shared the
# ticket table, that grant was necessarily table-wide: `dynamodb:LeadingKeys`
# constrains only the PARTITION key, and IAM has no condition key for a
# sort-key prefix. So nothing in IAM stopped a membership write -- only the
# application never constructing a `USER#` key did, which is a compensating
# control, not a boundary.
#
# With a separate table the boundary is real: `GetItem` on the membership
# table, no write action, plus an explicit Deny on every write to it. This
# resolves accepted risk AR-04 / threat T-06 / register row R-06.
# ---------------------------------------------------------------------------

locals {
  # When no customer-managed key is created, DynamoDB and Lambda fall back to
  # AWS-owned/AWS-managed keys. The role needs no KMS grant in that case, but
  # the policy template always carries the statement; pointing it at the
  # AWS-managed DynamoDB alias keeps the document valid and the grant inert.
  policy_kms_key_arn = coalesce(
    local.kms_key_arn,
    "arn:${local.partition}:kms:${local.region}:${local.account_id}:alias/aws/dynamodb"
  )

  policy_template_vars = {
    table_arn            = aws_dynamodb_table.main.arn
    membership_table_arn = aws_dynamodb_table.memberships.arn
    log_group_arn        = aws_cloudwatch_log_group.lambda.arn
    kms_key_arn          = local.policy_kms_key_arn
    region               = local.region
    account_id           = local.account_id
    partition            = local.partition
  }
}

# ---------------------------------------------------------------------------
# Trust policy
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "AllowLambdaServiceToAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    # Confused-deputy guard: the Lambda service may only assume this role on
    # behalf of this account.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name        = "${local.name_prefix}-lambda-role"
  description = "Execution role for the ${local.name_prefix} support API function"

  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  # Hard ceiling on what this role can ever hold, independent of what is
  # attached to it.
  permissions_boundary = aws_iam_policy.lambda_boundary.arn

  max_session_duration = 3600

  tags = {
    Name = "${local.name_prefix}-lambda-role"
  }
}

# ---------------------------------------------------------------------------
# Execution policy
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_execution" {
  name = "${local.name_prefix}-lambda-execution"
  role = aws_iam_role.lambda.id

  policy = templatefile(
    "${path.module}/policies/lambda-execution.json",
    local.policy_template_vars
  )
}

# X-Ray permissions are a separate attachment rather than a conditional
# statement, so the base policy stays a plain static document and tracing
# access is granted only when tracing is actually on.
#
# `xray:PutTraceSegments` does not accept a resource ARN -- the API is
# account-scoped for segment submission -- so `Resource: "*"` here is a
# limitation of the AWS API, not a shortcut. It is constrained with an
# `aws:SourceAccount` condition and recorded as an accepted exception in
# `assessments/final-security-assessment.md`.
resource "aws_iam_role_policy" "lambda_xray" {
  count = var.enable_xray ? 1 : 0

  name = "${local.name_prefix}-lambda-xray"
  role = aws_iam_role.lambda.id

  policy = templatefile(
    "${path.module}/policies/lambda-xray.json",
    local.policy_template_vars
  )
}

# ---------------------------------------------------------------------------
# Permissions boundary
#
# The execution policy describes what the role *does*. The boundary describes
# what it *could ever* do. If an over-permissive policy is attached later --
# by hand, or by an automation bug -- the effective permissions are still
# capped by this document. It costs one extra policy and removes a whole class
# of change-management incident.
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "lambda_boundary" {
  name        = "${local.name_prefix}-lambda-boundary"
  description = "Permissions boundary capping what the support API execution role can ever hold"

  # Uses the SAME variable map as the execution policy, deliberately.
  #
  # This call previously carried its own inline copy of the map, which drifted
  # the moment a new placeholder (`membership_table_arn`) was added to the
  # boundary document: `terraform validate` failed with "vars map does not
  # contain key". One source of truth means the two cannot disagree again.
  #
  # The boundary is attached to the role at creation, before the table ARNs are
  # strictly needed, but Terraform resolves the dependency order from these
  # references.
  policy = templatefile(
    "${path.module}/policies/lambda-permissions-boundary.json",
    local.policy_template_vars
  )

  tags = {
    Name = "${local.name_prefix}-lambda-boundary"
  }
}
