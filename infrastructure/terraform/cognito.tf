# ---------------------------------------------------------------------------
# Amazon Cognito: user directory and token issuer.
#
# Cognito issues the JWT; API Gateway's authorizer validates it. Neither the
# Lambda nor the application code ever handles a token, a signature or a JWKS
# document -- that whole category of bug is designed out rather than tested for.
#
# THE MOST IMPORTANT CONTROL IN THIS FILE is `write_attributes` on the app
# client. The custom attributes `organization_id` and `role` are deliberately
# absent from it, so a signed-in user cannot call UpdateUserAttributes to
# change their own tenancy or grant themselves the administrator role.
# ---------------------------------------------------------------------------

resource "aws_cognito_user_pool" "main" {
  name = local.name_prefix

  # Email as the sign-in identifier. `username_attributes` rather than
  # `alias_attributes` so an email can never be claimed as a bare username by
  # a different account.
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  username_configuration {
    # Case-insensitive, so Alice@ and alice@ cannot become two accounts that a
    # human reviewer would read as one.
    case_sensitive = false
  }

  password_policy {
    minimum_length = var.cognito_password_minimum_length

    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true

    # A compromised password must stop working promptly, not at next rotation.
    temporary_password_validity_days = 1
  }

  mfa_configuration = var.cognito_mfa_configuration

  # TOTP rather than SMS. SMS MFA is vulnerable to SIM-swap and port-out
  # attacks, and it costs money per message.
  software_token_mfa_configuration {
    enabled = var.cognito_mfa_configuration != "OFF"
  }

  # Threat protection: adaptive authentication and compromised-credential
  # checks. Billed per monthly active user, hence the variable.
  user_pool_add_ons {
    advanced_security_mode = var.cognito_advanced_security_mode
  }

  # Only an administrator may create users. Self-service sign-up would let
  # anyone create an account in the directory, and tenancy is assigned
  # out-of-band anyway.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # ---- Custom attributes -------------------------------------------------
  #
  # `mutable = true` because an administrator must be able to move a user
  # between organizations or change their role. The protection is that the app
  # client cannot write them (see `write_attributes` below) -- so only an
  # AWS-credentialed admin call can.
  #
  # These claims are a convenience for the gateway and for logging. They are
  # NOT the authorization source of truth: the application re-reads the
  # membership record from DynamoDB on every request (finding F-002), so a
  # stale or tampered claim cannot grant access.

  schema {
    name                     = "organization_id"
    attribute_data_type      = "String"
    mutable                  = true
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 3
      max_length = 64
    }
  }

  schema {
    name                     = "role"
    attribute_data_type      = "String"
    mutable                  = true
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 4
      max_length = 16
    }
  }

  # Prevents a destroy from silently deleting the directory along with every
  # user's credentials. Set to false here so the demo can be torn down; a real
  # deployment should flip this to true.
  deletion_protection = var.enable_deletion_protection ? "ACTIVE" : "INACTIVE"

  tags = {
    Name = "${local.name_prefix}-users"
  }
}

# ---------------------------------------------------------------------------
# Resource server: declares the OAuth scopes the API understands.
#
# Created unconditionally so the scopes exist and are documented; enforcement
# per route is controlled by `var.enable_scope_enforcement` (see api.tf for
# why it defaults to off).
# ---------------------------------------------------------------------------

resource "aws_cognito_resource_server" "support" {
  identifier = "support"
  name       = "${local.name_prefix}-support-api"

  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "tickets.read"
    scope_description = "Read tickets the caller is authorized to see"
  }

  scope {
    scope_name        = "tickets.write"
    scope_description = "Create and update tickets the caller is authorized to modify"
  }
}

resource "aws_cognito_user_pool_client" "api" {
  name = "${local.name_prefix}-api-client"

  user_pool_id = aws_cognito_user_pool.main.id

  # No client secret: this client is for a browser/mobile application, where a
  # secret cannot be kept. The authorization-code flow with PKCE is what
  # provides the security instead. A confidential server-side client would be a
  # separate client with `generate_secret = true`.
  generate_secret = false

  # Authorization code only. The implicit flow returns tokens in the URL
  # fragment, where they land in browser history, `Referer` headers and proxy
  # logs; it is deprecated for exactly that reason.
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true

  allowed_oauth_scopes = [
    "openid",
    "email",
    "profile",
    "${aws_cognito_resource_server.support.identifier}/tickets.read",
    "${aws_cognito_resource_server.support.identifier}/tickets.write",
  ]

  # SRP keeps the password off the wire. ALLOW_USER_PASSWORD_AUTH is
  # deliberately excluded: it sends the plaintext password to the Cognito API,
  # which removes the only reason to use SRP in the first place.
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  # Localhost only by default -- a real deployment supplies its own origins and
  # must not leave a localhost callback registered.
  callback_urls = length(var.cors_allowed_origins) > 0 ? var.cors_allowed_origins : ["http://localhost:3000/callback"]
  logout_urls   = length(var.cors_allowed_origins) > 0 ? var.cors_allowed_origins : ["http://localhost:3000/logout"]

  supported_identity_providers = ["COGNITO"]

  # Token lifetimes. The access token is the credential that reaches the API,
  # so it is the one that matters most.
  access_token_validity  = var.cognito_access_token_validity_minutes
  id_token_validity      = var.cognito_access_token_validity_minutes
  refresh_token_validity = var.cognito_refresh_token_validity_days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  # Rotate the refresh token on use, so a stolen refresh token has a short
  # useful life and reuse is detectable.
  enable_token_revocation = true

  # Returns a generic error for both "no such user" and "wrong password", so
  # the sign-in endpoint cannot be used to enumerate which email addresses
  # have accounts.
  prevent_user_existence_errors = "ENABLED"

  # ---- The control that stops self-granted privilege --------------------
  #
  # A user may read their own tenancy and role, and may update only their
  # profile fields. `custom:organization_id` and `custom:role` are absent from
  # `write_attributes`, so UpdateUserAttributes called with this client's
  # token cannot change them. Adding them here would make the DynamoDB
  # membership check the only thing standing between a user and admin rights.
  read_attributes = [
    "email",
    "email_verified",
    "name",
    "custom:organization_id",
    "custom:role",
  ]

  write_attributes = [
    "email",
    "name",
  ]
}

resource "aws_cognito_user_pool_domain" "main" {
  count = var.create_cognito_domain ? 1 : 0

  # Must be globally unique across all AWS accounts, hence the account-id
  # suffix. Not a secret: the domain is public by design.
  domain       = "${local.name_prefix}-${local.account_id}"
  user_pool_id = aws_cognito_user_pool.main.id
}
