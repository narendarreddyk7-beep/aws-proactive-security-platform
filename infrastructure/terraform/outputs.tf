# ---------------------------------------------------------------------------
# Outputs
#
# These are the values an operator needs after an apply: where the API is, how
# to authenticate against it, and where to look when something breaks.
#
# Nothing here is secret. A Cognito user pool id and app client id are public
# identifiers -- the app client has no secret, and possession of either grants
# nothing without valid credentials. Terraform state, by contrast, IS
# sensitive (see docs/AWS_DEPLOYMENT.md §"Terraform state security").
# ---------------------------------------------------------------------------

output "api_endpoint" {
  description = "Base URL of the deployed HTTP API. Append /v1/health to smoke test."
  value       = aws_apigatewayv2_stage.main.invoke_url
}

output "api_id" {
  description = "API Gateway HTTP API id, for CLI and console lookups."
  value       = aws_apigatewayv2_api.main.id
}

output "cognito_user_pool_id" {
  description = "Cognito user pool id. Needed to create demo users with the AWS CLI."
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_client_id" {
  description = <<-EOT
    Cognito app client id. Used as the OAuth client and as the audience the
    JWT authorizer validates. Public by design -- this client has no secret
    and relies on the authorization-code flow with PKCE.
  EOT
  value       = aws_cognito_user_pool_client.api.id
}

output "cognito_issuer_url" {
  description = "The `iss` value the JWT authorizer requires. Useful for debugging a 401."
  value       = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}

output "cognito_hosted_ui_domain" {
  description = "Hosted UI domain, when created. Empty string when create_cognito_domain is false."
  value       = var.create_cognito_domain ? aws_cognito_user_pool_domain.main[0].domain : ""
}

output "dynamodb_table_name" {
  description = "Name of the single DynamoDB table."
  value       = aws_dynamodb_table.main.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table, for IAM policy review."
  value       = aws_dynamodb_table.main.arn
}

output "membership_table_name" {
  description = "Name of the membership table. Read-only to the API; populated by the out-of-band provisioning process."
  value       = aws_dynamodb_table.memberships.name
}

output "membership_table_arn" {
  description = "ARN of the membership table (the authorization source of truth)."
  value       = aws_dynamodb_table.memberships.arn
}

output "lambda_function_name" {
  description = "Name of the API function."
  value       = aws_lambda_function.api.function_name
}

output "lambda_execution_role_arn" {
  description = <<-EOT
    ARN of the Lambda execution role. Export as SUPPORT_API_ROLE_NAME (name
    part only) to run the IAM least-privilege checks in
    tests/integration/test_aws_gateway_contract.py.
  EOT
  value       = aws_iam_role.lambda.arn
}

output "lambda_log_group_name" {
  description = "CloudWatch log group holding the structured application logs."
  value       = aws_cloudwatch_log_group.lambda.name
}

output "api_access_log_group_name" {
  description = <<-EOT
    CloudWatch log group holding API Gateway access logs. This is the ONLY
    place a 401 rejected by the authorizer is recorded -- those requests never
    reach Lambda. Runbook A reads this first.
  EOT
  value       = aws_cloudwatch_log_group.api_access.name
}

output "security_alarm_topic_arn" {
  description = "SNS topic that CloudWatch alarms publish to."
  value       = aws_sns_topic.security_alarms.arn
}

output "kms_key_arn" {
  description = "Customer-managed KMS key ARN, or null when create_kms_key is false."
  value       = local.kms_key_arn
}

output "security_dashboard_url" {
  description = "Direct link to the CloudWatch security dashboard."
  value = join("", [
    "https://",
    local.region,
    ".console.aws.amazon.com/cloudwatch/home?region=",
    local.region,
    "#dashboards:name=",
    aws_cloudwatch_dashboard.security.dashboard_name,
  ])
}

# ---------------------------------------------------------------------------
# Posture summary
#
# A single output that states what the deployed security posture actually is.
# Printed after every apply, so a drifted or cost-reduced environment is
# visible immediately rather than discovered during an incident.
# ---------------------------------------------------------------------------

output "security_posture" {
  description = "Effective security posture of this deployment. Review after every apply."
  value = {
    environment                 = var.environment
    identity_source             = "gateway (API Gateway JWT authorizer)"
    mfa                         = var.cognito_mfa_configuration
    cognito_threat_protection   = var.cognito_advanced_security_mode
    customer_managed_kms        = var.create_kms_key
    point_in_time_recovery      = var.enable_point_in_time_recovery
    deletion_protection         = var.enable_deletion_protection
    log_retention_days          = var.log_retention_days
    xray_tracing                = var.enable_xray
    scope_enforcement           = var.enable_scope_enforcement
    cors_origins_configured     = length(var.cors_allowed_origins)
    api_rate_limit_per_second   = var.api_throttling_rate_limit
    lambda_reserved_concurrency = var.lambda_reserved_concurrency
    security_hub_triage         = var.enable_security_hub_integration
    alarm_email_subscribed      = var.alarm_email != ""
  }
}

output "post_apply_checklist" {
  description = "Manual steps an apply cannot perform. Read this after every first apply."
  value = [
    "1. Confirm the SNS email subscription (check the inbox for ${var.alarm_email == "" ? "<no address configured>" : var.alarm_email}); alarms are silent until confirmed.",
    "2. Create Cognito users, then set custom:organization_id and custom:role with admin-set-user-attributes.",
    "3. Replace the synthetic demo membership items in DynamoDB with the real Cognito `sub` values (see docs/DEMO.md).",
    "4. Smoke test: curl ${aws_apigatewayv2_stage.main.invoke_url}/v1/health",
    "5. Verify a request with no Authorization header returns 401.",
    "6. Run the AWS-gated tests: pytest tests/integration/test_aws_gateway_contract.py -m aws",
    "7. Review the security_posture output above against docs/SECURITY.md.",
  ]
}
