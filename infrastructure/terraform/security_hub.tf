# ---------------------------------------------------------------------------
# OPTIONAL: AWS Security Hub finding-triage pipeline.
#
#   Security Hub CSPM
#          |
#     EventBridge  (Security Hub Findings - Imported)
#          |
#   Finding Triage Lambda   -- normalize, score, assign an owner, deduplicate
#          |
#   CloudWatch Logs  +  SNS (high severity only)
#
# OFF BY DEFAULT (`enable_security_hub_integration = false`).
#
# TWO SEPARATE DECISIONS, DELIBERATELY NOT CONFLATED
#
#   1. Deploying this pipeline. Cheap: EventBridge rule, a small Lambda, a
#      DynamoDB table for deduplication. Controlled by the variable below.
#
#   2. Enabling Security Hub itself. NOT done by this configuration. Security
#      Hub is billed per security check and per finding ingested, and enabling
#      it also enables AWS Config in most useful configurations, which has its
#      own per-configuration-item charge. Turning that on from a portfolio
#      project's `terraform apply` would be a genuinely unpleasant surprise,
#      so it stays a conscious manual step documented in
#      docs/AWS_DEPLOYMENT.md §"Optional: Security Hub".
#
# The triage logic is fully unit-tested against synthetic ASFF events
# (`security-automation/tests/`), so the whole capability is demonstrable with
# this left off and Security Hub never enabled.
# ---------------------------------------------------------------------------

module "security_hub_triage" {
  count  = var.enable_security_hub_integration ? 1 : 0
  source = "../modules/security_hub_triage"

  name_prefix = local.name_prefix
  environment = var.environment

  # Reuse the parent's alarm topic and key so there is one place to subscribe
  # and one key policy to review.
  sns_topic_arn = aws_sns_topic.security_alarms.arn
  kms_key_arn   = local.kms_key_arn

  log_retention_days = var.log_retention_days
  lambda_runtime     = var.lambda_runtime

  # Only CRITICAL and HIGH findings notify. Everything is logged and scored;
  # paging on MEDIUM would train the on-call to ignore the topic, which is a
  # worse outcome than not alerting at all.
  notify_severities = ["CRITICAL", "HIGH"]

  tags = local.common_tags
}
