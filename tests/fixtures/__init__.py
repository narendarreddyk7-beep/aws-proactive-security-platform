"""Test fixtures.

Everything in this package is **synthetic**. No real customer data, no real
AWS account identifiers, and no real credentials appear anywhere.

`gateway.py` contains the only code in the repository that fabricates a
"verified" API Gateway authorizer context. It lives in the test tree
deliberately: the application itself has no code path that can be persuaded to
trust client input as identity.
"""

from tests.fixtures.fake_store import InMemoryMembershipStore, InMemoryTicketStore
from tests.fixtures.gateway import GatewayEventInjector, gateway_claims
from tests.fixtures.synthetic_data import (
    ORG_A,
    ORG_B,
    USER_A_ADMIN,
    USER_A_MEMBER,
    USER_A_MEMBER_2,
    USER_B_MEMBER,
    make_ticket,
)

__all__ = [
    "ORG_A",
    "ORG_B",
    "USER_A_ADMIN",
    "USER_A_MEMBER",
    "USER_A_MEMBER_2",
    "USER_B_MEMBER",
    "GatewayEventInjector",
    "InMemoryMembershipStore",
    "InMemoryTicketStore",
    "gateway_claims",
    "make_ticket",
]
