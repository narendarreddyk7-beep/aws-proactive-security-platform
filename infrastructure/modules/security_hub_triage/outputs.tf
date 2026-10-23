output "function_name" {
  description = "Name of the triage function."
  value       = aws_lambda_function.triage.function_name
}

output "function_arn" {
  description = "ARN of the triage function."
  value       = aws_lambda_function.triage.arn
}

output "role_arn" {
  description = "Execution role ARN, for IAM least-privilege review."
  value       = aws_iam_role.triage.arn
}

output "log_group_name" {
  description = "CloudWatch log group holding the structured triage output."
  value       = aws_cloudwatch_log_group.triage.name
}

output "event_rule_name" {
  description = "EventBridge rule routing Security Hub findings to the function."
  value       = aws_cloudwatch_event_rule.security_hub_findings.name
}

output "dedup_table_name" {
  description = "DynamoDB table holding notification-deduplication fingerprints."
  value       = aws_dynamodb_table.dedup.name
}

output "dead_letter_queue_url" {
  description = <<-EOT
    SQS queue holding findings that could not be delivered to the function.
    A non-empty queue means findings are NOT being triaged; the
    `-dlq-not-empty` alarm fires on it.
  EOT
  value       = aws_sqs_queue.triage_dlq.url
}

output "prerequisites" {
  description = "What must be true outside this module for the pipeline to receive anything."
  value = [
    "AWS Security Hub must be enabled in this account and region. This module does NOT enable it: Security Hub is billed per security check and per finding ingested, and in a useful configuration it also enables AWS Config with its own per-configuration-item charge.",
    "At least one Security Hub standard must be enabled (AWS Foundational Security Best Practices is the usual starting point).",
    "The EventBridge rule only routes findings whose Severity.Label is in route_severities and whose RecordState is ACTIVE.",
    "With Security Hub disabled this module deploys cleanly and simply receives no events, which is the intended behaviour for an optional integration.",
  ]
}
