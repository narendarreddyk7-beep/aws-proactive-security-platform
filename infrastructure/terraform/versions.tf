terraform {
  # 1.6 is the floor: `terraform test` and improved `moved`/`import` block
  # handling arrived there, and 1.5+ is required for `check` blocks.
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Deliberately a range rather than `~> 6.0`. The AWS provider ships a
      # major release roughly annually and this project must stay usable
      # across one boundary. Pin exactly in `.terraform.lock.hcl` (committed
      # for a real deployment) so that `terraform init` is reproducible even
      # though the constraint here is permissive.
      #
      # Before a first apply, confirm the resolved version in
      # `terraform version` output against the provider changelog.
      version = ">= 5.70.0, < 7.0.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0, < 3.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource created by this configuration is tagged, so that an
  # unexpected resource in the account is traceable back to this repository.
  default_tags {
    tags = local.common_tags
  }

  # Guard against pointing a `terraform apply` at the wrong account. Set
  # `allowed_account_ids` in the environment tfvars for anything beyond a
  # throwaway sandbox -- this is the cheapest possible blast-radius control.
  allowed_account_ids = var.allowed_account_ids
}
