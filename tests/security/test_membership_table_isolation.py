"""The membership table is read-only to the application.

WHY THIS MODULE EXISTS
----------------------
The membership record is the authoritative source of a caller's role, so write
access to it is tenant takeover (threat T-06).

Memberships originally shared the ticket table. That made the boundary
*inexpressible in IAM*: the function needs ``PutItem`` to create tickets,
``dynamodb:LeadingKeys`` constrains only the partition key, and IAM has no
condition key for a sort-key prefix. So the ``PutItem`` grant was necessarily
table-wide, and the only thing preventing a membership write was the
application never constructing a ``USER#`` key -- a compensating control, not a
boundary. It was carried as accepted risk AR-04.

Splitting the table makes it a real boundary. These tests pin both halves of
it: the application's behaviour, and the IAM document that is actually
deployed. The policy test is the one that matters most -- behaviour can be
re-reviewed, but a permission is what an attacker who already has code
execution is limited by.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.models.ticket import TicketStatus
from app.repositories.keys import membership_sk, user_pk
from app.repositories.membership_repository import DynamoDbMembershipRepository
from app.repositories.ticket_repository import DynamoDbTicketRepository
from tests.fixtures.synthetic_data import (
    ORG_A,
    TICKET_A1,
    USER_A_MEMBER,
    make_ticket,
)

pytestmark = [pytest.mark.security, pytest.mark.regression]

WRITE_OPERATIONS = frozenset(
    {"put_item", "update_item", "delete_item", "batch_write_item", "transact_write_items"}
)

POLICY_DIR = Path(__file__).resolve().parents[2] / "infrastructure" / "terraform" / "policies"
EXECUTION_POLICY = POLICY_DIR / "lambda-execution.json"
BOUNDARY_POLICY = POLICY_DIR / "lambda-permissions-boundary.json"

MEMBERSHIP_ARN = "${membership_table_arn}"
TABLE_ARN = "${table_arn}"


def _seed(table: Any, *, user_id: str, organization_id: str, role: str = "member") -> None:
    """Write a membership directly, as the out-of-band provisioner would."""
    table.put_item(
        Item={
            "PK": user_pk(user_id),
            "SK": membership_sk(organization_id),
            "entity_type": "membership",
            "role": role,
            "status": "active",
        }
    )


def _statements(path: Path) -> list[dict[str, Any]]:
    """Return the statements of a committed policy template."""
    return json.loads(path.read_text())["Statement"]


def _as_list(value: Any) -> list[Any]:
    """Normalise an IAM field that may be a string or a list."""
    if isinstance(value, list):
        return value
    return [value]


# ---------------------------------------------------------------------------
# Application behaviour
# ---------------------------------------------------------------------------


def test_the_two_tables_are_configured_separately() -> None:
    """The ticket and membership tables must not be the same table.

    A deployment that pointed both names at one table would silently restore
    the table-wide ``PutItem`` exposure while every other test still passed.
    """
    settings = Settings(environment="test")
    assert settings.table_name != settings.membership_table_name


def test_membership_lookup_reads_the_membership_table(recording_membership_table: Any) -> None:
    """The membership repository issues an exact GetItem on the right table."""
    _seed(recording_membership_table, user_id=USER_A_MEMBER, organization_id=ORG_A)
    recording_membership_table.calls.clear()

    repo = DynamoDbMembershipRepository(table=recording_membership_table)
    membership = repo.get_membership(USER_A_MEMBER, ORG_A)

    assert membership is not None
    assert membership.organization_id == ORG_A

    operations = [call.operation for call in recording_membership_table.calls]
    assert operations == ["get_item"], operations

    key = recording_membership_table.calls[0].kwargs["Key"]
    assert key == {"PK": user_pk(USER_A_MEMBER), "SK": membership_sk(ORG_A)}


def test_membership_lookup_uses_a_consistent_read(recording_membership_table: Any) -> None:
    """Revocation must take effect immediately, so the read cannot be stale.

    An eventually-consistent read is not acceptable for an authorization input:
    it would let a revoked membership keep working for an unbounded window.
    """
    _seed(recording_membership_table, user_id=USER_A_MEMBER, organization_id=ORG_A)
    recording_membership_table.calls.clear()

    DynamoDbMembershipRepository(table=recording_membership_table).get_membership(
        USER_A_MEMBER, ORG_A
    )

    assert recording_membership_table.calls[0].kwargs.get("ConsistentRead") is True


def test_membership_repository_never_issues_a_write(recording_membership_table: Any) -> None:
    """Exercising every membership code path must produce reads only."""
    _seed(recording_membership_table, user_id=USER_A_MEMBER, organization_id=ORG_A)
    recording_membership_table.calls.clear()

    repo = DynamoDbMembershipRepository(table=recording_membership_table)
    repo.get_membership(USER_A_MEMBER, ORG_A)
    repo.get_membership(USER_A_MEMBER, "org-does-not-exist")
    repo.get_membership("00000000-0000-4000-8000-000000000000", ORG_A)

    operations = {call.operation for call in recording_membership_table.calls}
    assert operations == {"get_item"}, operations
    assert not operations & WRITE_OPERATIONS


def test_membership_repository_exposes_no_write_method() -> None:
    """The class must offer no way to mutate a membership.

    Guards against a future convenience method ("just add an upsert") that
    would reintroduce the write path the IAM policy is designed to forbid.
    """
    public = {name for name in dir(DynamoDbMembershipRepository) if not name.startswith("_")}
    forbidden = {
        name
        for name in public
        if any(verb in name for verb in ("put", "save", "write", "update", "delete", "set"))
    }
    assert not forbidden, f"membership repository exposes write-shaped methods: {forbidden}"


def test_ticket_operations_never_touch_the_membership_table(
    recording_table: Any,
    recording_membership_table: Any,
) -> None:
    """A full ticket lifecycle must leave the membership table untouched."""
    recording_membership_table.calls.clear()

    repo = DynamoDbTicketRepository(table=recording_table)
    ticket = make_ticket(ticket_id=TICKET_A1, organization_id=ORG_A, created_by=USER_A_MEMBER)
    repo.put_ticket(ticket)
    repo.get_ticket(ORG_A, TICKET_A1)
    repo.list_tickets(ORG_A, limit=10)
    repo.list_tickets(ORG_A, limit=10, created_by=USER_A_MEMBER)
    repo.save_ticket(ticket.model_copy(update={"status": TicketStatus.IN_PROGRESS}))

    assert recording_membership_table.calls == [], (
        "ticket operations reached the membership table: "
        f"{[c.operation for c in recording_membership_table.calls]}"
    )


# ---------------------------------------------------------------------------
# The deployed IAM document
#
# These assert the policy that actually deploys. The policies are committed as
# JSON templates rather than rendered only by the provider at plan time
# (decision D11) precisely so this is testable with no AWS account.
# ---------------------------------------------------------------------------


def test_execution_policy_allows_only_getitem_on_the_membership_table() -> None:
    """Every Allow touching the membership table must be GetItem and nothing else."""
    allows = [
        s
        for s in _statements(EXECUTION_POLICY)
        if s["Effect"] == "Allow" and MEMBERSHIP_ARN in _as_list(s.get("Resource", []))
    ]
    assert allows, "no Allow statement grants access to the membership table"

    for statement in allows:
        actions = set(_as_list(statement["Action"]))
        assert actions == {"dynamodb:GetItem"}, (
            f"statement {statement.get('Sid')!r} grants {sorted(actions)} "
            "on the membership table; only dynamodb:GetItem is permitted"
        )


def test_execution_policy_denies_every_write_to_the_membership_table() -> None:
    """An explicit Deny must cover the write actions, so no later Allow can win."""
    denied: set[str] = set()
    for statement in _statements(EXECUTION_POLICY):
        if statement["Effect"] != "Deny":
            continue
        resources = _as_list(statement.get("Resource", []))
        if MEMBERSHIP_ARN in resources or "*" in resources:
            denied |= set(_as_list(statement["Action"]))

    required = {
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:TransactWriteItems",
    }
    missing = required - denied
    assert not missing, f"membership writes not explicitly denied: {sorted(missing)}"


def test_ticket_table_write_grant_does_not_extend_to_memberships() -> None:
    """The PutItem grant must name the ticket table only.

    NOTE ON WHAT THIS CAN AND CANNOT CATCH. Run against the pre-split policy,
    this assertion *passes* -- because back then the ARN in the PutItem grant
    genuinely was the ticket table's ARN; that table simply also held the
    memberships. No assertion over the policy document alone could have
    detected the exposure, which is the whole reason the split was necessary
    rather than a policy edit.

    So this is a guard against future *widening* (someone adding the membership
    ARN, or a broader ARN pattern, to a write grant), not a detector of the old
    arrangement. The three assertions that do fail against the pre-split policy
    are the two Deny checks and the Allow-scope check above; the behavioural
    detector of the old arrangement is
    ``test_the_two_tables_are_configured_separately``.
    """
    for statement in _statements(EXECUTION_POLICY):
        if statement["Effect"] != "Allow":
            continue
        actions = set(_as_list(statement["Action"]))
        if "dynamodb:PutItem" not in actions:
            continue
        resources = _as_list(statement["Resource"])
        assert MEMBERSHIP_ARN not in resources, (
            f"statement {statement.get('Sid')!r} grants PutItem on the membership table"
        )
        assert all(r.startswith(TABLE_ARN) for r in resources), (
            f"statement {statement.get('Sid')!r} grants PutItem beyond "
            f"the ticket table: {resources}"
        )


def test_permissions_boundary_also_forbids_membership_writes() -> None:
    """The boundary must cap the role even if the inline policy is replaced."""
    denied: set[str] = set()
    for statement in _statements(BOUNDARY_POLICY):
        if statement["Effect"] != "Deny":
            continue
        resources = _as_list(statement.get("Resource", []))
        if MEMBERSHIP_ARN in resources or "*" in resources:
            denied |= set(_as_list(statement["Action"]))

    assert {"dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"} <= denied
