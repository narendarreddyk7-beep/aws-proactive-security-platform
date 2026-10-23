variable "name_prefix" {
  description = "Resource name prefix, normally \"<project>-<environment>\"."
  type        = string
}

variable "environment" {
  description = "Deployment environment, recorded on every log line the function emits."
  type        = string
}

variable "sns_topic_arn" {
  description = <<-EOT
    SNS topic for high-severity notifications and the DLQ alarm. Empty string
    disables notification: findings are still normalized, scored and logged, so
    the pipeline remains useful (and testable) without a topic.
  EOT
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = <<-EOT
    Customer-managed KMS key for the dedup table, log group, DLQ and Lambda
    environment variables. Null falls back to AWS-managed keys.
  EOT
  type        = string
  default     = null
}

variable "lambda_build_dir" {
  description = <<-EOT
    Directory containing the triage function's deployment package contents:
    `handler.py`, plus `finding_triage.py`, `triage_config.json` and `schemas/`
    copied from `security-automation/`.

    Produced by `scripts/build_lambda_package.sh`. The shared risk model is
    copied rather than reimplemented so the Lambda and the CLI cannot drift
    into scoring the same finding differently.
  EOT
  type        = string
  default     = "../../dist/security_hub_triage_build"
}

variable "lambda_runtime" {
  description = "Managed Lambda Python runtime."
  type        = string
  default     = "python3.12"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the function."
  type        = number
  default     = 30
}

variable "notify_severities" {
  description = <<-EOT
    Severities that trigger an SNS notification. Everything routed to the
    function is logged and scored regardless; this controls only who gets
    woken up.

    Keep this short. Notifying on MEDIUM trains the on-call to ignore the
    topic, which is a worse outcome than not alerting at all.
  EOT
  type        = list(string)
  default     = ["CRITICAL", "HIGH"]

  validation {
    condition = alltrue([
      for s in var.notify_severities :
      contains(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], upper(s))
    ])
    error_message = "notify_severities must be drawn from CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL."
  }
}

variable "route_severities" {
  description = <<-EOT
    Severities the EventBridge rule routes to the function at all. Broader than
    `notify_severities` on purpose: MEDIUM findings are worth normalizing,
    scoring and logging for trend analysis even though they do not page anyone.

    Filtering at the rule rather than in the function means a filtered-out
    event costs nothing.
  EOT
  type        = list(string)
  default     = ["CRITICAL", "HIGH", "MEDIUM"]
}

variable "dedup_ttl_hours" {
  description = <<-EOT
    How long a notified finding is suppressed from re-notification.

    24 hours matches Security Hub's typical re-evaluation cadence: long enough
    that one unremediated misconfiguration does not page twice a day, short
    enough that a genuinely persistent problem resurfaces daily rather than
    disappearing.
  EOT
  type        = number
  default     = 24

  validation {
    condition     = var.dedup_ttl_hours >= 1 && var.dedup_ttl_hours <= 720
    error_message = "dedup_ttl_hours must be between 1 and 720 (30 days)."
  }
}

variable "tags" {
  description = "Tags applied to every resource in the module."
  type        = map(string)
  default     = {}
}
