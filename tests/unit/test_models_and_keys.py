"""Model validation, key construction and pagination unit tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.ticket import (
    MAX_DESCRIPTION_LENGTH,
    MAX_TITLE_LENGTH,
    Ticket,
    TicketCreateRequest,
    TicketPriority,
    TicketStatus,
    TicketUpdateRequest,
    is_transition_allowed,
)
from app.repositories.keys import (
    member_index_pk,
    member_index_sk,
    membership_sk,
    tenant_pk,
    ticket_sk,
    user_pk,
)
from app.repositories.pagination import (
    MAX_CURSOR_LENGTH,
    decode_cursor,
    encode_cursor,
    validate_cursor_key,
)
from app.security.errors import ValidationFailedError
from tests.fixtures.synthetic_data import ORG_A, ORG_B, TICKET_A1, USER_A_MEMBER, make_ticket

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Request models (finding F-004)
# ---------------------------------------------------------------------------


def test_create_request_strips_whitespace() -> None:
    """Leading/trailing whitespace is normalised, not stored."""
    payload = TicketCreateRequest(title="  Padded  ", description="  Body  ")
    assert payload.title == "Padded"
    assert payload.description == "Body"


def test_create_request_defaults_priority_to_medium() -> None:
    """Omitting priority must not leave the field unset."""
    assert TicketCreateRequest(title="t", description="d").priority is TicketPriority.MEDIUM


@pytest.mark.security
@pytest.mark.parametrize(
    "field",
    ["organization_id", "created_by", "ticket_id", "status", "created_at", "updated_at", "PK"],
)
def test_create_request_forbids_server_controlled_fields(field: str) -> None:
    """Guards finding F-004: mass assignment is rejected at the model."""
    with pytest.raises(ValidationError):
        TicketCreateRequest(title="t", description="d", **{field: "x"})  # type: ignore[arg-type]


@pytest.mark.security
@pytest.mark.parametrize(
    "field", ["organization_id", "created_by", "ticket_id", "created_at", "role"]
)
def test_update_request_forbids_server_controlled_fields(field: str) -> None:
    """Guards finding F-004."""
    with pytest.raises(ValidationError):
        TicketUpdateRequest(**{field: "x"})  # type: ignore[arg-type]


def test_update_request_requires_at_least_one_field() -> None:
    """An empty PATCH is a client bug, not a no-op success."""
    with pytest.raises(ValidationError):
        TicketUpdateRequest()
    with pytest.raises(ValidationError):
        TicketUpdateRequest(title=None, description=None)


def test_update_request_reports_only_explicitly_set_fields() -> None:
    """``changed_fields`` drives the audit log, so it must be exact."""
    payload = TicketUpdateRequest(title="New title", status=TicketStatus.RESOLVED)

    assert payload.changed_fields() == ["status", "title"]
    assert payload.changes() == {"title": "New title", "status": TicketStatus.RESOLVED}
    assert "description" not in payload.changes()
    assert "priority" not in payload.changes()


@pytest.mark.parametrize(
    ("field", "length"),
    [("title", MAX_TITLE_LENGTH), ("description", MAX_DESCRIPTION_LENGTH)],
)
def test_length_limits_are_inclusive(field: str, length: int) -> None:
    """The boundary value must be accepted, and one more rejected."""
    base = {"title": "t", "description": "d"}
    TicketCreateRequest(**{**base, field: "A" * length})  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        TicketCreateRequest(**{**base, field: "A" * (length + 1)})  # type: ignore[arg-type]


def test_ticket_model_rejects_unknown_stored_attributes() -> None:
    """A stray attribute on a stored item must fail loudly, not ride along."""
    item = make_ticket().model_dump(mode="json")
    item["internal_note"] = "should not exist"
    with pytest.raises(ValidationError):
        Ticket.model_validate(item)


def test_ticket_model_is_immutable() -> None:
    """Frozen models make accidental in-place mutation impossible."""
    ticket = make_ticket()
    with pytest.raises(ValidationError):
        ticket.organization_id = ORG_B  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Status machine (finding F-013)
# ---------------------------------------------------------------------------


def test_closed_is_terminal() -> None:
    """No transition out of ``closed`` is permitted."""
    for target in TicketStatus:
        if target is TicketStatus.CLOSED:
            continue
        assert is_transition_allowed(TicketStatus.CLOSED, target) is False


def test_every_non_terminal_status_can_reach_closed() -> None:
    """A ticket must always be closable, or the queue can never be drained."""
    for current in TicketStatus:
        if current is TicketStatus.CLOSED:
            continue
        assert is_transition_allowed(current, TicketStatus.CLOSED) is True


# ---------------------------------------------------------------------------
# Key construction (finding F-011)
# ---------------------------------------------------------------------------


def test_key_builders_produce_the_documented_shape() -> None:
    """The key format is a contract shared with Terraform and the runbooks."""
    assert tenant_pk(ORG_A) == f"TENANT#{ORG_A}"
    assert ticket_sk(TICKET_A1) == f"TICKET#{TICKET_A1}"
    assert user_pk(USER_A_MEMBER) == f"USER#{USER_A_MEMBER}"
    assert membership_sk(ORG_A) == f"MEMBERSHIP#{ORG_A}"
    assert member_index_pk(ORG_A, USER_A_MEMBER) == f"TENANT#{ORG_A}#USER#{USER_A_MEMBER}"
    assert member_index_sk("2026-03-01T12:00:00Z", TICKET_A1) == (
        f"CREATED#2026-03-01T12:00:00Z#{TICKET_A1}"
    )


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize("value", ["has#separator", "TICKET#forged", "", "   ", "a#b#c"])
def test_key_builders_reject_separator_injection(value: str) -> None:
    """Guards finding F-011.

    ``#`` delimits the key structure. An identifier containing it could
    address a key the application never meant to expose, so every builder
    refuses it -- the last line of defence behind the UUID check at the edge.
    """
    for builder in (tenant_pk, ticket_sk, user_pk, membership_sk):
        with pytest.raises(ValidationFailedError):
            builder(value)


@pytest.mark.security
def test_member_index_key_embeds_both_tenant_and_user() -> None:
    """A user-only index key would reintroduce a cross-tenant read path.

    If GSI1PK were just ``USER#{user}``, a user who belongs to two
    organizations would see both organizations' tickets in one query.
    """
    key_a = member_index_pk(ORG_A, USER_A_MEMBER)
    key_b = member_index_pk(ORG_B, USER_A_MEMBER)
    assert key_a != key_b
    assert ORG_A in key_a and ORG_B in key_b


# ---------------------------------------------------------------------------
# Pagination cursors (finding F-010)
# ---------------------------------------------------------------------------


def test_cursor_round_trip() -> None:
    """A cursor the API issued must decode back to the same key."""
    key = {"PK": tenant_pk(ORG_A), "SK": ticket_sk(TICKET_A1)}
    cursor = encode_cursor(key)
    assert cursor is not None
    assert decode_cursor(cursor, organization_id=ORG_A) == key


def test_encode_drops_non_key_attributes() -> None:
    """Only DynamoDB key attributes travel in a cursor.

    Projecting the key keeps item data out of a value the client can read and
    store, and keeps the decoder's allow-list small.
    """
    key = {
        "PK": tenant_pk(ORG_A),
        "SK": ticket_sk(TICKET_A1),
        "description": "customer content",
    }
    cursor = encode_cursor(key)
    decoded = decode_cursor(cursor, organization_id=ORG_A)
    assert decoded == {"PK": tenant_pk(ORG_A), "SK": ticket_sk(TICKET_A1)}


def test_encode_returns_none_for_the_last_page() -> None:
    """No ``LastEvaluatedKey`` means no cursor, which means no next page."""
    assert encode_cursor(None) is None
    assert encode_cursor({}) is None


def test_decode_returns_none_when_no_cursor_given() -> None:
    """An absent cursor is the first page, not an error."""
    assert decode_cursor(None, organization_id=ORG_A) is None
    assert decode_cursor("", organization_id=ORG_A) is None


@pytest.mark.security
@pytest.mark.regression
def test_cursor_bound_to_another_tenant_is_rejected() -> None:
    """Guards finding F-010 -- the control that matters most here."""
    cursor = encode_cursor({"PK": tenant_pk(ORG_B), "SK": ticket_sk(TICKET_A1)})
    with pytest.raises(ValidationFailedError):
        decode_cursor(cursor, organization_id=ORG_A)


@pytest.mark.security
def test_oversized_cursor_is_rejected_without_decoding() -> None:
    """Guards finding F-010: bound the input before doing work on it."""
    with pytest.raises(ValidationFailedError) as exc_info:
        decode_cursor("A" * (MAX_CURSOR_LENGTH + 1), organization_id=ORG_A)
    assert exc_info.value.detail == "cursor_too_long"


@pytest.mark.security
@pytest.mark.parametrize(
    "key",
    [
        pytest.param({"PK": f"TENANT#{ORG_A}"}, id="missing-sk"),
        pytest.param({"SK": "TICKET#x"}, id="missing-pk"),
        pytest.param({"PK": f"TENANT#{ORG_A}", "SK": 123}, id="non-string-value"),
        pytest.param({"PK": f"TENANT#{ORG_A}", "SK": "x", "evil": "y"}, id="extra-attribute"),
        pytest.param({}, id="empty"),
        pytest.param("not-a-dict", id="not-a-dict"),
        pytest.param(["list"], id="list"),
    ],
)
def test_malformed_cursor_keys_are_rejected(key: object) -> None:
    """Malformed keys are a 400-mapped error, never a pass-through."""
    with pytest.raises(ValidationFailedError):
        validate_cursor_key(key, organization_id=ORG_A)


@pytest.mark.security
def test_cursor_rejection_messages_are_identical() -> None:
    """A per-reason message would let a client probe the key structure."""
    messages = set()
    for candidate in ("!!!!", "e30=", "W10="):
        try:
            decode_cursor(candidate, organization_id=ORG_A)
        except ValidationFailedError as exc:
            messages.add(exc.message)
    assert len(messages) == 1, messages


def test_cursor_tolerates_stripped_base64_padding() -> None:
    """Some proxies strip ``=`` padding; a legitimate cursor must still work."""
    cursor = encode_cursor({"PK": tenant_pk(ORG_A), "SK": ticket_sk(TICKET_A1)})
    assert cursor is not None
    assert decode_cursor(cursor.rstrip("="), organization_id=ORG_A) is not None
