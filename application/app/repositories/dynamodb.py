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
def get_table() -> Any:
    """Return the DynamoDB ``Table`` resource for the configured table.

    Cached: creating a boto3 resource performs credential resolution, which is
    expensive to repeat on every Lambda invocation.
    """
    settings = get_settings()
    resource = boto3.resource(
        "dynamodb",
        region_name=settings.aws_region,
        endpoint_url=settings.dynamodb_endpoint_url,
    )
    return resource.Table(settings.table_name)
