# ---------------------------------------------------------------------------
# Amazon API Gateway HTTP API + Cognito JWT authorizer.
#
# THIS FILE IS THE AUTHENTICATION TRUST BOUNDARY.
#
# The authorizer validates the token's signature (against the Cognito JWKS),
# its issuer, its audience, and its expiry, BEFORE Lambda is invoked. A
# request with a missing, expired, malformed or wrongly-signed token never
# reaches application code -- so that entire category of bug is designed out
# rather than tested for.
#
# When validation succeeds, the verified claims are published to the Lambda
# event at:
#
#     requestContext.authorizer.jwt.claims
#
# which is the ONLY place `app/security/identity.py` reads identity from
# (finding F-001). `tests/integration/test_lambda_handler.py` asserts that
# plumbing end to end.
#
# HTTP API is chosen over REST API deliberately: it has a native JWT
# authorizer (no custom authorizer Lambda to write, secure and pay for), and
# it costs roughly a third as much per million requests. The trade-off is no
# WAF attachment and no request/response transformation -- neither of which
# this API needs, and the WAF gap is recorded as a residual risk.
# ---------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "main" {
  name          = "${local.name_prefix}-api"
  description   = "Multi-tenant customer support API"
  protocol_type = "HTTP"

  # CORS is handled by the gateway rather than the application so a preflight
  # never spends a Lambda invocation. `allow_credentials` with an explicit
  # origin list only -- API Gateway rejects `allow_credentials` together with
  # a `*` origin, and `var.cors_allowed_origins` forbids `*` anyway
  # (finding F-012).
  dynamic "cors_configuration" {
    for_each = length(var.cors_allowed_origins) > 0 ? [1] : []

    content {
      allow_origins = var.cors_allowed_origins
      allow_methods = ["GET", "POST", "PATCH", "OPTIONS"]
      allow_headers = ["authorization", "content-type", "x-request-id"]
      expose_headers = ["x-request-id"]
      allow_credentials = true
      max_age           = 600
    }
  }

  tags = {
    Name = "${local.name_prefix}-api"
  }
}

# ---------------------------------------------------------------------------
# JWT authorizer
# ---------------------------------------------------------------------------

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id = aws_apigatewayv2_api.main.id
  name   = "${local.name_prefix}-cognito-jwt"

  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    # Must match the `iss` claim exactly. This is what binds the API to one
    # specific user pool: a validly-signed token from a different Cognito
    # pool -- including an attacker's own pool -- fails here.
    issuer = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"

    # Checked against `aud`, falling back to `client_id` for Cognito access
    # tokens (which carry `client_id` rather than `aud`). This stops a token
    # minted for a *different* app client in the same pool -- say a client
    # with weaker auth flows -- from being replayed against this API.
    audience = [aws_cognito_user_pool_client.api.id]
  }
}

# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "lambda" {
  api_id = aws_apigatewayv2_api.main.id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  integration_method     = "POST"
  # Payload format 2.0 is what puts the verified claims at
  # `requestContext.authorizer.jwt.claims`. Format 1.0 shapes the event
  # differently and would break identity extraction.
  payload_format_version = "2.0"

  timeout_milliseconds = var.lambda_timeout_seconds * 1000
}

# ---------------------------------------------------------------------------
# Routes
#
# Routes are declared individually rather than with a `$default` catch-all.
# A catch-all would route every path -- including paths that do not exist --
# to Lambda, which means paying for 404s and losing the ability to attach the
# authorizer per route. Explicit routes also make "which endpoints are
# public?" answerable by reading this file.
# ---------------------------------------------------------------------------

locals {
  # `authorization_scopes` is only meaningful when scope enforcement is on.
  # See `var.enable_scope_enforcement` for why it defaults to off.
  read_scopes = var.enable_scope_enforcement ? ["support/tickets.read"] : []
  write_scopes = var.enable_scope_enforcement ? ["support/tickets.write"] : []

  protected_routes = {
    "POST /v1/tickets" = {
      scopes = local.write_scopes
    }
    "GET /v1/tickets" = {
      scopes = local.read_scopes
    }
    "GET /v1/tickets/{ticket_id}" = {
      scopes = local.read_scopes
    }
    "PATCH /v1/tickets/{ticket_id}" = {
      scopes = local.write_scopes
    }
  }
}

# The health route is intentionally unauthenticated so external monitors can
# probe it. It returns a static payload and discloses no configuration --
# asserted by
# tests/security/test_api_behaviour.py::test_health_endpoint_does_not_disclose_configuration.
resource "aws_apigatewayv2_route" "health" {
  api_id = aws_apigatewayv2_api.main.id

  route_key = "GET /v1/health"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"

  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "protected" {
  for_each = local.protected_routes

  api_id = aws_apigatewayv2_api.main.id

  route_key = each.key
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"

  authorization_type   = "JWT"
  authorizer_id        = aws_apigatewayv2_authorizer.cognito.id
  authorization_scopes = each.value.scopes
}

# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

resource "aws_apigatewayv2_stage" "main" {
  api_id = aws_apigatewayv2_api.main.id

  # `$default` so the invoke URL has no stage prefix and paths match the
  # application's routes exactly. A named stage would make the deployed path
  # `/v1/v1/tickets` or require a base-path mapping.
  name        = "$default"
  auto_deploy = true

  # Throttling is the primary availability and cost control. API Gateway
  # enforces it before the authorizer runs, so an unauthenticated flood is
  # rejected without spending a Lambda invocation or a DynamoDB read.
  default_route_settings {
    throttling_rate_limit  = var.api_throttling_rate_limit
    throttling_burst_limit = var.api_throttling_burst_limit

    # Per-route metrics make the CloudWatch alarms in monitoring.tf able to
    # distinguish "the list endpoint is erroring" from "something is erroring".
    detailed_metrics_enabled = true
  }

  # Access logs record what the gateway decided, including the authorizer
  # outcome. Without these, a 401 is invisible: it never reaches Lambda, so
  # the application log has no record of it. This is the only source for
  # "someone is hammering us with invalid tokens", and it is what runbook A
  # reads first.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn

    # JSON so CloudWatch Logs Insights can query fields. Deliberately includes
    # the authorizer error and the principal id, and deliberately excludes
    # request and response bodies -- those would copy ticket content into a
    # second log store (finding F-007).
    format = jsonencode({
      requestId        = "$context.requestId"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      routeKey         = "$context.routeKey"
      path             = "$context.path"
      status           = "$context.status"
      protocol         = "$context.protocol"
      responseLength   = "$context.responseLength"
      responseLatency  = "$context.responseLatency"
      integrationError = "$context.integrationErrorMessage"
      sourceIp         = "$context.identity.sourceIp"
      userAgent        = "$context.identity.userAgent"
      # Authorizer outcome -- the authentication audit trail.
      authorizerError = "$context.authorizer.error"
      principalId     = "$context.authorizer.claims.sub"
      organizationId  = "$context.authorizer.claims.custom:organization_id"
    })
  }

  tags = {
    Name = "${local.name_prefix}-stage"
  }
}
