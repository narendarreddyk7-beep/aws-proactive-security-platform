"""DynamoDB resource factory.

Centralised so that the endpoint override used for local testing cannot leak
into production code paths by accident.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import boto3

from app.config import get_settings


@lru_cache
def _resource() -> Any:
    """Return the shared DynamoDB service resource.

    Cached: constructing a boto3 resource performs credential resolution,
    which is expensive to repeat on every Lambda invocation.
    """
    settings = get_settings()
    return boto3.resource(
        "dynamodb",
        region_name=settings.aws_region,
        endpoint_url=settings.dynamodb_endpoint_url,
    )


@lru_cache
def get_table() -> Any:
    """Return the ``Table`` resource for the ticket table."""
    return _resource().Table(get_settings().table_name)


@lru_cache
def get_membership_table() -> Any:
    """Return the ``Table`` resource for the membership table.

    A separate table, not a separate partition prefix. The execution role is
    granted ``GetItem`` on this table and no write action at all, which is a
    boundary IAM can actually enforce -- see the comment on
    ``Settings.membership_table_name``.
    """
    return _resource().Table(get_settings().membership_table_name)
