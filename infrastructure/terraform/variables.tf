# ---------------------------------------------------------------------------
# Core identity of the deployment
# ---------------------------------------------------------------------------

variable "project_name" {
  description = "Short project slug used as a prefix for every resource name."
  type        = string
  default     = "support-platform"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.project_name))
    error_message = "project_name must be 3-31 lowercase alphanumeric or hyphen characters, starting with a letter."
  }
}

variable "environment" {
  description = "Deployment environment. Drives naming and the security posture defaults."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "allowed_account_ids" {
  description = <<-EOT
    AWS account IDs this configuration is permitted to apply to. Leave empty to
    disable the check (only sensible for a throwaway sandbox). Setting this is
    the cheapest guard against applying a dev plan to a production account.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Additional tags merged into every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

variable "lambda_build_dir" {
  description = <<-EOT
    Directory containing the built Lambda deployment package contents
    (the `app/` package plus vendored runtime dependencies).

    Produced by `scripts/build_lambda_package.sh`. This must exist before
    `terraform plan`, because the archive is hashed to decide whether the
    function needs updating.
  EOT
  type        = string
  default     = "../../dist/lambda_build"
}

variable "lambda_runtime" {
  description = <<-EOT
    Managed Lambda Python runtime. `python3.12` is the conservative default
    because it has the longest remaining support window; `python3.13` is also
    available and is what the test suite runs on locally.
  EOT
  type        = string
  default     = "python3.12"

  validation {
    condition     = contains(["python3.12", "python3.13"], var.lambda_runtime)
    error_message = "lambda_runtime must be python3.12 or python3.13."
  }
}

variable "lambda_memory_mb" {
  description = <<-EOT
    Memory, which on Lambda also determines CPU. 512 MB is enough for FastAPI
    plus Pydantic import at cold start without paying for idle capacity.
  EOT
  type        = number
  default     = 512

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 3008
    error_message = "lambda_memory_mb must be between 128 and 3008."
  }
}

variable "lambda_timeout_seconds" {
  description = <<-EOT
    Execution timeout. Kept low deliberately: every request here is a couple
    of single-digit-millisecond DynamoDB calls, so a long timeout only buys an
    attacker a cheaper denial-of-wallet lever and holds concurrency open.
  EOT
  type        = number
  default     = 10

  validation {
    condition     = var.lambda_timeout_seconds >= 1 && var.lambda_timeout_seconds <= 29
    error_message = "lambda_timeout_seconds must be 1-29 (API Gateway caps integration timeout at 29s)."
  }
}

variable "lambda_reserved_concurrency" {
  description = <<-EOT
    Reserved concurrent executions. Bounds both the blast radius of a runaway
    loop and the maximum spend from a request flood. -1 disables the
    reservation (NOT recommended: it lets one API consume the whole account's
    concurrency).
  EOT
  type        = number
  default     = 10
}

variable "enable_xray" {
  description = <<-EOT
    Enable AWS X-Ray active tracing. Off by default because X-Ray is billed
    per trace beyond the free tier and is not needed to demonstrate the
    security controls. Recommended ON for a real production deployment.
  EOT
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# API behaviour
# ---------------------------------------------------------------------------

variable "cors_allowed_origins" {
  description = <<-EOT
    Exact origins permitted to call the API from a browser. MUST NOT contain
    "*": the API is credentialed, so a wildcard would let any site read a
    signed-in user's tickets (finding F-012). An empty list disables CORS,
    which is correct for a server-to-server API.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.cors_allowed_origins, "*")
    error_message = "cors_allowed_origins must not contain '*'. List exact origins."
  }

  validation {
    condition     = alltrue([for o in var.cors_allowed_origins : can(regex("^https://", o))])
    error_message = "Every CORS origin must be an https:// URL."
  }
}

variable "api_throttling_rate_limit" {
  description = "Steady-state request rate per second across the stage."
  type        = number
  default     = 50
}

variable "api_throttling_burst_limit" {
  description = "Burst capacity for the stage. Keep close to the rate limit for a small API."
  type        = number
  default     = 100
}

variable "enable_scope_enforcement" {
  description = <<-EOT
    Enforce OAuth 2.0 scopes per route at the API Gateway authorizer
    (`support/tickets.read` for reads, `support/tickets.write` for writes).

    Off by default for a practical reason: Cognito only puts custom scopes in
    access tokens issued by the OAuth2 token endpoint (hosted UI or
    client-credentials). Tokens obtained through `InitiateAuth` with SRP --
    which is how the demo in docs/DEMO.md authenticates -- do not carry them,
    so enforcing scopes would reject those tokens.

    Turn this ON for a production deployment that uses the hosted UI, and
    see docs/SECURITY.md for the trade-off.
  EOT
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Cognito
# ---------------------------------------------------------------------------

variable "cognito_password_minimum_length" {
  description = "Minimum password length. 12 reflects current NIST SP 800-63B guidance over complexity rules."
  type        = number
  default     = 12

  validation {
    condition     = var.cognito_password_minimum_length >= 8
    error_message = "cognito_password_minimum_length must be at least 8."
  }
}

variable "cognito_mfa_configuration" {
  description = <<-EOT
    MFA enforcement: OFF, OPTIONAL or ON. "ON" requires every user to
    register a factor, which blocks the scripted demo, so OPTIONAL is the
    default and prod tfvars sets ON.
  EOT
  type        = string
  default     = "OPTIONAL"

  validation {
    condition     = contains(["OFF", "OPTIONAL", "ON"], var.cognito_mfa_configuration)
    error_message = "cognito_mfa_configuration must be OFF, OPTIONAL or ON."
  }
}

variable "cognito_advanced_security_mode" {
  description = <<-EOT
    Cognito threat protection: OFF, AUDIT or ENFORCED. AUDIT and ENFORCED are
    billed per monthly active user, so the default is OFF to keep the dev
    environment inside the free tier. ENFORCED is strongly recommended for
    production -- it is what detects credential stuffing and impossible travel.
  EOT
  type        = string
  default     = "OFF"

  validation {
    condition     = contains(["OFF", "AUDIT", "ENFORCED"], var.cognito_advanced_security_mode)
    error_message = "cognito_advanced_security_mode must be OFF, AUDIT or ENFORCED."
  }
}

variable "cognito_access_token_validity_minutes" {
  description = <<-EOT
    Access-token lifetime. Short lifetimes matter here because the application
    treats a verified token's claims as current; 60 minutes bounds how long a
    stale claim can circulate. Membership and role are re-read from DynamoDB on
    every request, so a revoked membership takes effect immediately regardless.
  EOT
  type        = number
  default     = 60
}

variable "cognito_refresh_token_validity_days" {
  description = "Refresh-token lifetime in days."
  type        = number
  default     = 30
}

variable "create_cognito_domain" {
  description = <<-EOT
    Create a Cognito hosted-UI domain. Free, and required for the OAuth
    authorization-code flow used in the demo walkthrough.
  EOT
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Data protection
# ---------------------------------------------------------------------------

variable "create_kms_key" {
  description = <<-EOT
    Create a customer-managed KMS key for DynamoDB, CloudWatch Logs, SNS and
    Lambda environment-variable encryption.

    ON by default. DynamoDB and Lambda encrypt at rest with an AWS-owned key
    regardless, but a customer-managed key is what gives you an auditable key
    policy, independent rotation, and the ability to revoke access to the data
    by revoking the key.

    Cost: approximately USD 1.00/month for the key plus per-request charges
    (both are small at this scale). Setting this to false saves that dollar and
    will cause Checkov CKV_AWS_119 (DynamoDB CMK) to report a finding -- which
    is the honest outcome, not something to suppress.
  EOT
  type        = bool
  default     = true
}

variable "enable_point_in_time_recovery" {
  description = <<-EOT
    DynamoDB point-in-time recovery (35-day continuous backup). This is the
    control that makes ransomware or a bad migration recoverable. Billed per
    GB of table size -- negligible for this workload.
  EOT
  type        = bool
  default     = true
}

variable "enable_deletion_protection" {
  description = <<-EOT
    DynamoDB deletion protection. Deliberately OFF by default so that
    `terraform destroy` succeeds and the demo environment can be torn down
    cleanly. Production tfvars sets this to true.
  EOT
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = <<-EOT
    CloudWatch Logs retention. Never leave this unset: "Never expire" is both
    an unbounded cost and an unbounded data-retention liability for logs that
    contain tenant identifiers.
  EOT
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days
    )
    error_message = "log_retention_days must be a retention period CloudWatch Logs supports."
  }
}

# ---------------------------------------------------------------------------
# Monitoring and alerting
# ---------------------------------------------------------------------------

variable "alarm_email" {
  description = <<-EOT
    Email address subscribed to the security alarm topic. Leave empty to
    create the topic without a subscription (the default, so that an apply
    does not send a confirmation email to anyone).

    Note: an email subscription requires manual confirmation; the alarm is
    silent until someone clicks the link.
  EOT
  type        = string
  default     = ""
}

variable "authorization_denied_alarm_threshold" {
  description = <<-EOT
    Number of `authorization_denied` events in the evaluation window that
    raises an alarm. A handful of denials is normal (a member clicking a
    colleague's bookmarked link); a sustained burst is either a broken client
    or someone enumerating. Tune this against observed traffic -- see
    runbooks/authorization-alert-triage.md.
  EOT
  type        = number
  default     = 10
}

variable "error_rate_alarm_threshold" {
  description = "Number of Lambda errors in the evaluation window that raises an alarm."
  type        = number
  default     = 5

}

variable "alarm_evaluation_period_seconds" {
  description = "Period over which alarm metrics are evaluated."
  type        = number
  default     = 300
}

# ---------------------------------------------------------------------------
# Optional integrations (off by default -- see docs/AWS_DEPLOYMENT.md §Costs)
# ---------------------------------------------------------------------------

variable "enable_security_hub_integration" {
  description = <<-EOT
    Deploy the optional Security Hub finding-triage pipeline
    (EventBridge rule -> triage Lambda -> CloudWatch/SNS).

    OFF by default. This module does NOT enable Security Hub itself -- that is
    a separate, chargeable account-level decision (per-check and per-finding
    pricing) and must be made deliberately. The triage logic is fully
    unit-tested against synthetic ASFF events either way, so the project is
    completely demonstrable with this left off.
  EOT
  type        = bool
  default     = false
}
