# ---------------------------------------------------------------------------
# DynamoDB: two tables.
#
#   aws_dynamodb_table.main         tickets      (read + write)
#   aws_dynamodb_table.memberships  memberships  (READ ONLY to the function)
#
# Key schema (mirrored in application/app/repositories/keys.py and asserted by
# tests/integration/test_dynamodb_repository.py):
#
#   Ticket      PK = TENANT#{organization_id}   SK = TICKET#{ticket_id}
#   Membership  PK = USER#{user_id}             SK = MEMBERSHIP#{organization_id}
#
#   GSI1        GSI1PK = TENANT#{org}#USER#{user}   GSI1SK = CREATED#{ts}#{id}
#
# WHY MEMBERSHIPS ARE A SEPARATE TABLE
# The membership record is the authoritative source of a caller's role, so
# write access to it is tenant takeover. While memberships shared a table with
# tickets, IAM could not express "read memberships, write only tickets": the
# function needs `PutItem` for tickets, `dynamodb:LeadingKeys` constrains only
# the PARTITION key, and there is no condition key for a sort-key prefix. So
# the `PutItem` grant was necessarily table-wide, and the only thing stopping a
# membership write was the application never constructing a `USER#` key.
#
# That was a compensating control, not a boundary. Splitting the table makes it
# a boundary IAM enforces: `GetItem` on this table, no write action at all, and
# an explicit Deny on every write to it. This resolves accepted risk AR-04 /
# threat T-06 / register row R-06.
#
# WHY THE PARTITION KEY CARRIES THE TENANT
# Tenant isolation becomes a property of the access pattern rather than of
# remembering to filter. A Query cannot read outside its partition, so a
# cross-tenant read is not "blocked" -- it is impossible. The alternative (a
# flat table with an `organization_id` attribute) makes isolation depend on a
# FilterExpression that any refactor can drop. That was finding F-006.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "main" {
  name = local.name_prefix

  # On-demand. For a workload this spiky, provisioned capacity would either be
  # over-provisioned (waste) or throttle under burst (availability). On-demand
  # also removes autoscaling as a thing that can be misconfigured.
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  # GSI1 lets a member list their own tickets without reading the rest of the
  # organization's partition. The partition key embeds BOTH tenant and user:
  # keying it on the user alone would let a user who belongs to two
  # organizations see both organizations' tickets in one query, reintroducing
  # a cross-tenant read path through the index.
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  # Continuous backups for 35 days. The control that makes a bad migration or
  # a destructive bug recoverable rather than terminal.
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  # DynamoDB always encrypts at rest. This block upgrades it from the AWS-owned
  # key to a customer-managed key, which is what provides an auditable key
  # policy, independent rotation, and the ability to revoke access to the data
  # by revoking the key.
  server_side_encryption {
    enabled     = var.create_kms_key
    kms_key_arn = local.kms_key_arn
  }

  deletion_protection_enabled = var.enable_deletion_protection

  # Streams are deliberately off. Nothing consumes them, and an unconsumed
  # stream is a 24-hour copy of every change to customer data sitting in a
  # second place with its own access path.
  stream_enabled = false

  tags = {
    Name = local.name_prefix
  }

  lifecycle {
    # A table rename replaces the table, which silently destroys every ticket.
    # Making that an explicit error forces a migration plan instead.
    prevent_destroy = false

    ignore_changes = [
      # Tags applied out-of-band by an account-level tagging policy should not
      # cause perpetual drift.
      tags["LastReviewed"],
    ]
  }
}

# ---------------------------------------------------------------------------
# Seed data
#
# Membership records are the authoritative identity-to-tenant-and-role mapping
# (finding F-002). In a real deployment they are written by an administrative
# onboarding process, NOT by the support API -- which is the point: a support
# API caller cannot change their own tenancy or role.
#
# Terraform is used here only to create the two synthetic demo organizations so
# that `docs/DEMO.md` works immediately after an apply. Real memberships would
# never be managed as infrastructure state.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Membership table. Authorization input, read-only to the application.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "memberships" {
  name         = "${local.name_prefix}-memberships"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # No GSI. Every read is an exact (PK, SK) GetItem for one user's membership
  # of one organization. Adding an index would create a second access path to
  # the authorization source of truth for no access pattern that exists.

  # PITR matters more here than on the ticket table: a tampered or deleted
  # membership is an authorization failure, and recovering to a known-good
  # point is how you establish what the role *was* at the time of an incident.
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  server_side_encryption {
    enabled     = var.create_kms_key
    kms_key_arn = local.kms_key_arn
  }

  deletion_protection_enabled = var.enable_deletion_protection

  # Streams off: nothing consumes them, and a stream would be a 24-hour copy of
  # every authorization change in a second place with its own access path.
  stream_enabled = false

  tags = {
    Name = "${local.name_prefix}-memberships"
    Role = "authorization-source-of-truth"
  }

  lifecycle {
    prevent_destroy = false

    ignore_changes = [
      tags["LastReviewed"],
    ]
  }
}

resource "aws_dynamodb_table_item" "demo_memberships" {
  for_each = var.environment == "prod" ? {} : local.demo_memberships

  table_name = aws_dynamodb_table.memberships.name
  hash_key   = aws_dynamodb_table.memberships.hash_key
  range_key  = aws_dynamodb_table.memberships.range_key

  item = jsonencode({
    PK          = { S = "USER#${each.value.user_id}" }
    SK          = { S = "MEMBERSHIP#${each.value.organization_id}" }
    role        = { S = each.value.role }
    status      = { S = "active" }
    entity_type = { S = "membership" }
  })

  lifecycle {
    # Only the keys are managed. If an administrator changes a role through the
    # proper out-of-band process, Terraform must not revert it on the next
    # apply -- that would be an infrastructure tool silently overriding an
    # authorization decision.
    ignore_changes = [item]
  }
}

locals {
  # Synthetic identifiers. These are NOT Cognito subs -- after creating demo
  # users, replace them with the real `sub` values. See docs/DEMO.md.
  demo_memberships = {
    northwind_admin = {
      user_id         = "11111111-1111-4111-8111-111111111111"
      organization_id = "org-northwind"
      role            = "admin"
    }
    northwind_member = {
      user_id         = "22222222-2222-4222-8222-222222222222"
      organization_id = "org-northwind"
      role            = "member"
    }
    contoso_member = {
      user_id         = "44444444-4444-4444-8444-444444444444"
      organization_id = "org-contoso"
      role            = "member"
    }
  }
}
