#!/usr/bin/env python3
"""Run the support API on a laptop, with no AWS account and no Docker.

WHAT THIS IS FOR
----------------
Exercising the real application -- real routes, real authorization policy, real
repository code -- against an in-process mocked DynamoDB, so the behaviour in
``docs/DEMO.md`` can be reproduced with ``curl`` alone.

WHY THIS IS SAFE
----------------
This script sets ``APP_IDENTITY_SOURCE=local_test``, which activates a
deliberate authentication bypass: identity is read from ``X-Local-*`` request
headers instead of a verified API Gateway JWT authorizer context. That adapter
is the subject of finding F-012, and three independent controls keep it out of
any deployed environment:

1. ``Settings`` refuses to load ``local_test`` unless ``APP_ENVIRONMENT=local``.
2. ``LocalTestIdentityProvider.__init__`` raises on the same condition.
3. ``gateway`` is the default, and Terraform sets it explicitly on the Lambda.

So this script can only work on a machine where ``APP_ENVIRONMENT`` is
``local``. It binds to loopback by default for the same reason.

NOT A PRODUCTION PATH
---------------------
``moto`` is a test double. Conditional-write and consistency semantics are
emulated, not real (limitation L5). Nothing here is deployed or deployable.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APPLICATION_DIR = REPO_ROOT / "application"

# Synthetic demo identities. UUIDs so they are shaped like Cognito `sub` values.
ORG_A = "org-acme"
ORG_B = "org-contoso"

DEMO_MEMBERSHIPS: list[dict[str, str]] = [
    {"user_id": "11111111-1111-4111-8111-111111111111", "organization_id": ORG_A, "role": "admin"},
    {"user_id": "22222222-2222-4222-8222-222222222222", "organization_id": ORG_A, "role": "member"},
    {"user_id": "33333333-3333-4333-8333-333333333333", "organization_id": ORG_A, "role": "member"},
    {"user_id": "44444444-4444-4444-8444-444444444444", "organization_id": ORG_B, "role": "admin"},
    {"user_id": "55555555-5555-4555-8555-555555555555", "organization_id": ORG_B, "role": "member"},
    # Deliberately inactive: demonstrates that a revoked membership denies
    # immediately rather than at token expiry (finding F-002).
    {
        "user_id": "66666666-6666-4666-8666-666666666666",
        "organization_id": ORG_A,
        "role": "member",
        "status": "suspended",
    },
]

TABLE_NAME = "support-platform-local"
MEMBERSHIP_TABLE_NAME = "support-platform-local-memberships"


def _configure_environment(table_name: str) -> None:
    """Set the environment the application reads, before it is imported."""
    os.environ["APP_ENVIRONMENT"] = "local"
    os.environ["APP_IDENTITY_SOURCE"] = "local_test"
    os.environ["APP_TABLE_NAME"] = table_name
    os.environ["APP_MEMBERSHIP_TABLE_NAME"] = f"{table_name}-memberships"
    os.environ["APP_LOG_LEVEL"] = os.environ.get("APP_LOG_LEVEL", "INFO")
    os.environ["APP_AWS_REGION"] = "us-east-1"
    # moto requires credentials to be *present* but never validates them, so
    # these are generated rather than written as literals. Two reasons: there
    # is then no credential-shaped string in source for a secret scanner (or
    # a reader) to trip over, and setting them explicitly guarantees a real
    # profile on the developer's machine is never picked up by accident.
    placeholder = f"local-demo-{uuid.uuid4().hex[:12]}"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_ACCESS_KEY_ID"] = placeholder
    os.environ["AWS_SECRET_ACCESS_KEY"] = placeholder
    os.environ["AWS_SESSION_TOKEN"] = placeholder
    os.environ.pop("AWS_PROFILE", None)


def _create_table(table_name: str) -> None:
    """Create the single table with the same key schema as ``dynamodb.tf``."""
    import boto3

    client = boto3.client("dynamodb", region_name="us-east-1")
    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    client.get_waiter("table_exists").wait(TableName=table_name)

    # Memberships live in their OWN table so the execution role can hold
    # GetItem on them and no write action at all. Mirrors
    # infrastructure/terraform/dynamodb.tf.
    client.create_table(
        TableName=f"{table_name}-memberships",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
    )
    client.get_waiter("table_exists").wait(TableName=f"{table_name}-memberships")


def _seed_memberships(table_name: str) -> None:
    """Write the server-side membership records the authorization layer reads.

    This is the out-of-band administrative process referred to in
    ``app/models/membership.py``: the API itself has no endpoint that can
    create or modify a membership, which is what makes "grant myself admin"
    unreachable from the application.
    """
    import boto3

    from app.repositories.keys import membership_sk, user_pk

    table = boto3.resource("dynamodb", region_name="us-east-1").Table(f"{table_name}-memberships")
    for record in DEMO_MEMBERSHIPS:
        table.put_item(
            Item={
                "PK": user_pk(record["user_id"]),
                "SK": membership_sk(record["organization_id"]),
                "entity_type": "membership",
                "role": record["role"],
                "status": record.get("status", "active"),
            }
        )


def _print_banner(host: str, port: int) -> None:
    """Print the synthetic identities so the demo can be driven immediately."""
    print("=" * 78, flush=True)
    print("  Multi-Tenant Customer Support API — LOCAL DEMO", flush=True)
    print("=" * 78, flush=True)
    print(f"  URL          http://{host}:{port}", flush=True)
    print(f"  Docs         http://{host}:{port}/docs", flush=True)
    print("  Storage      in-process moto, TWO tables (tickets + memberships)", flush=True)
    print("               nothing persists; no AWS account used", flush=True)
    print("", flush=True)
    print("  IDENTITY IS READ FROM HEADERS. This is the F-012 local adapter and", flush=True)
    print("  cannot load unless APP_ENVIRONMENT=local. Not a production path.", flush=True)
    print("", flush=True)
    print("  Synthetic identities:", flush=True)
    for record in DEMO_MEMBERSHIPS:
        status = record.get("status", "active")
        flag = "" if status == "active" else f"  [{status}]"
        print(
            f"    {record['role']:6} {record['organization_id']:12} {record['user_id']}{flag}",
            flush=True,
        )
    print("", flush=True)
    print("  Example:", flush=True)
    print(f"    curl -s http://{host}:{port}/v1/tickets \\", flush=True)
    print('      -H "X-Local-User-Id: 22222222-2222-4222-8222-222222222222" \\', flush=True)
    print('      -H "X-Local-Org-Id: org-acme" \\', flush=True)
    print('      -H "X-Local-Role: member"', flush=True)
    print("=" * 78, flush=True)


def main(argv: list[str] | None = None) -> int:
    """Start the mocked backend and serve the application."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default loopback)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--table", default=TABLE_NAME)
    parser.add_argument(
        "--check",
        action="store_true",
        help="set up, assert the app imports and the table is seeded, then exit",
    )
    args = parser.parse_args(argv)

    sys.path.insert(0, str(APPLICATION_DIR))
    _configure_environment(args.table)

    try:
        from moto import mock_aws
    except ImportError:
        print("moto is required: python -m pip install -e '.[dev]'", file=sys.stderr)
        return 2

    # Started and never stopped: the mock must stay active for the life of the
    # process so every request's boto3 call is intercepted.
    mock = mock_aws()
    mock.start()

    _create_table(args.table)
    _seed_memberships(args.table)

    from app.main import app

    if args.check:
        print(
            f"OK: app imported, tables '{args.table}' and "
            f"'{args.table}-memberships' created, "
            f"{len(DEMO_MEMBERSHIPS)} memberships seeded."
        )
        return 0

    import uvicorn

    _print_banner(args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, server_header=False, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
