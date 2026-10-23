"""Architectural fitness functions for the security-critical invariants.

WHY THESE EXIST
---------------
Three properties of this codebase are currently guaranteed by *review* rather
than by a test:

1. No read path uses ``Scan`` (finding F-006).
2. Every service operation that takes a principal makes an authorization
   decision (finding F-003).
3. No request model declares a server-controlled field (finding F-004).

Review-maintained invariants decay. Each of these was a real finding, each fix
is currently held in place by a behavioural test of the *current* code paths,
and each would be silently reintroduced by a *new* code path that no existing
test covers -- a second repository method, a third service operation, a fourth
request model.

So these tests assert the property over the whole module tree rather than over
one call site. They are deliberately structural (AST-based, not grep-based):
``# noqa`` cannot silence them, a renamed variable does not fool them, and they
read the same source the reviewer would.

Recorded as safeguards S-8, S-9 and S-10 in
``assessments/remediation-tracker.md``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.security, pytest.mark.regression]

APP_ROOT = Path(__file__).resolve().parents[2] / "application" / "app"


def _python_files(root: Path) -> list[Path]:
    """Every application module, excluding caches."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parsed(path: Path) -> ast.Module:
    """Parse a module, reporting the path on a syntax error."""
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:  # pragma: no cover - a syntax error fails elsewhere too
        pytest.fail(f"{path}: {exc}")


# ---------------------------------------------------------------------------
# S-8 -- no Scan anywhere in the application
# ---------------------------------------------------------------------------


def test_no_application_module_calls_scan() -> None:
    """Guards finding F-006.

    ``Scan`` reads every tenant's items and makes isolation depend on a
    post-query filter that any refactor can drop. IAM denies it as well, so a
    ``Scan`` would fail at runtime -- but it would fail as an opaque
    ``AccessDenied`` in production rather than as a clear failure here.
    """
    offenders: list[str] = []

    for path in _python_files(APP_ROOT):
        tree = _parsed(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # table.scan(...) / self._table.scan(...)
            if isinstance(func, ast.Attribute) and func.attr in {"scan", "Scan"}:
                offenders.append(f"{path.relative_to(APP_ROOT.parent.parent)}:{node.lineno}")
            # getattr(table, "scan")(...) -- the dynamic back door
            if (
                isinstance(func, ast.Call)
                and isinstance(func.func, ast.Name)
                and func.func.id == "getattr"
                and len(func.args) >= 2
                and isinstance(func.args[1], ast.Constant)
                and func.args[1].value in {"scan", "Scan"}
            ):
                offenders.append(f"{path.relative_to(APP_ROOT.parent.parent)}:{node.lineno}")

    assert not offenders, (
        f"Scan is not permitted in a tenant-facing read path (finding F-006). Found at: {offenders}"
    )


def test_scan_is_not_reachable_as_a_string_operation() -> None:
    """Backstop for a client built from a string operation name.

    ``client.get_paginator("scan")`` and ``meta.client.scan`` do not look like
    an attribute call named ``scan``, so the AST check above would miss them.
    """
    offenders: list[str] = []
    for path in _python_files(APP_ROOT):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if '"scan"' in stripped or "'scan'" in stripped:
                offenders.append(f"{path.relative_to(APP_ROOT.parent.parent)}:{lineno}")
    assert not offenders, f"'scan' appears as a string operation name at: {offenders}"


# ---------------------------------------------------------------------------
# S-9 -- every principal-taking service operation enforces a decision
# ---------------------------------------------------------------------------

#: Service methods that take a principal but legitimately make no authorization
#: decision. Every entry needs a documented reason, because adding one is how
#: this guard would be defeated.
ENFORCEMENT_EXEMPT: dict[str, str] = {
    "create_ticket": (
        "Creating a ticket in your own organization is permitted for every active "
        "member, and membership was already established by resolve_principal. "
        "There is no object to authorize against: organization_id and created_by "
        "are taken from the principal, so the operation cannot target another "
        "tenant or another user (finding F-004)."
    ),
    "list_tickets": (
        "Scope is applied to the QUERY rather than enforced against a loaded "
        "object: list_scope(principal) selects GSI1 for a member, so a "
        "coworker's tickets are never read (findings F-003, F-006). There is no "
        "loaded object to deny, and a decision here would be a no-op that made "
        "the real control harder to see."
    ),
}

SERVICES_DIR = APP_ROOT / "services"


def _service_methods() -> list[tuple[str, str, ast.FunctionDef]]:
    """Return (module, class, function) for every public service method."""
    found: list[tuple[str, str, ast.FunctionDef]] = []
    for path in _python_files(SERVICES_DIR):
        tree = _parsed(path)
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            for fn in cls.body:
                if isinstance(fn, ast.FunctionDef) and not fn.name.startswith("_"):
                    found.append((path.name, cls.name, fn))
    return found


def test_service_layer_has_methods_to_check() -> None:
    """Sanity check: the guard below is only meaningful if it found something."""
    methods = _service_methods()
    assert methods, "no service methods discovered -- the S-9 guard would vacuously pass"
    assert any(arg.arg == "principal" for _, _, fn in methods for arg in fn.args.args), (
        "no principal-taking service method found"
    )


def test_every_principal_taking_service_method_enforces_a_decision() -> None:
    """Guards finding F-003.

    The original defect was a policy helper that was defined and never called.
    A behavioural test catches that for the paths it exercises; this catches it
    for a path nobody has written a test for yet.

    A method is satisfied by calling ``enforce`` directly, or by delegating to a
    private helper in the same class that does (``_load_or_404`` raises before
    any decision is needed).
    """
    unguarded: list[str] = []

    for module, cls_name, fn in _service_methods():
        takes_principal = any(arg.arg == "principal" for arg in fn.args.args)
        if not takes_principal:
            continue
        if fn.name in ENFORCEMENT_EXEMPT:
            continue

        calls = {
            node.func.id
            for node in ast.walk(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        } | {
            node.func.attr
            for node in ast.walk(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }

        if "enforce" not in calls:
            unguarded.append(f"{module}::{cls_name}.{fn.name} (line {fn.lineno})")

    assert not unguarded, (
        "these service methods take a principal but never call enforce() "
        "(finding F-003). Either enforce a Decision, or add an entry to "
        f"ENFORCEMENT_EXEMPT with a written reason: {unguarded}"
    )


def test_enforcement_exemptions_are_documented() -> None:
    """Every exemption must carry a real reason, not a placeholder."""
    for name, reason in ENFORCEMENT_EXEMPT.items():
        assert len(reason) > 80, f"exemption for {name!r} is not adequately justified"
        assert "finding" in reason.lower() or "principal" in reason.lower(), (
            f"exemption for {name!r} does not explain the security reasoning"
        )


def test_exemptions_refer_to_methods_that_exist() -> None:
    """A stale exemption silently widens the guard, so fail on one."""
    actual = {fn.name for _, _, fn in _service_methods()}
    stale = set(ENFORCEMENT_EXEMPT) - actual
    assert not stale, f"ENFORCEMENT_EXEMPT names methods that no longer exist: {stale}"


# ---------------------------------------------------------------------------
# S-10 -- no request model declares a server-controlled field
# ---------------------------------------------------------------------------

#: Fields the server owns. A client that can set any of these can choose its
#: own tenant, owner, identifier or audit timestamps (finding F-004).
SERVER_CONTROLLED_FIELDS: frozenset[str] = frozenset(
    {
        "organization_id",
        "created_by",
        "ticket_id",
        "created_at",
        "updated_at",
        "user_id",
        "role",
        "status_changed_by",
    }
)

MODELS_DIR = APP_ROOT / "models"


def _request_models() -> list[tuple[Path, ast.ClassDef]]:
    """Return every model class whose name marks it as client input."""
    found: list[tuple[Path, ast.ClassDef]] = []
    for path in _python_files(MODELS_DIR):
        tree = _parsed(path)
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            if cls.name.endswith(("Request", "Payload", "Input", "Create", "Update")):
                found.append((path, cls))
    return found


def test_request_models_were_discovered() -> None:
    """Sanity check so the guard below cannot pass vacuously."""
    models = _request_models()
    assert models, "no request models discovered -- the S-10 guard would vacuously pass"


def test_no_request_model_declares_a_server_controlled_field() -> None:
    """Guards finding F-004.

    The original ``TicketCreateRequest`` declared ``organization_id``, and the
    service used ``payload.organization_id or principal.organization_id`` -- a
    cross-tenant write reachable by adding one JSON field.

    ``extra="forbid"`` stops a client *sending* an undeclared field. This stops
    a developer *declaring* one.
    """
    offenders: list[str] = []

    for path, cls in _request_models():
        for stmt in cls.body:
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                continue
            field = stmt.target.id
            if field in SERVER_CONTROLLED_FIELDS:
                offenders.append(f"{path.name}::{cls.name}.{field} (line {stmt.lineno})")

    assert not offenders, (
        f"request models must not declare server-controlled fields (finding F-004): {offenders}"
    )


def test_every_request_model_forbids_unknown_fields() -> None:
    """Guards finding F-004.

    ``extra="allow"`` on the original ``TicketUpdateRequest`` let any attribute
    the client sent be written through to storage. A silent *drop* would be
    almost as bad: it is invisible, so an attacker can map the schema at
    leisure. Rejection is logged and alertable.
    """
    missing: list[str] = []

    for path, cls in _request_models():
        forbids = False
        for stmt in cls.body:
            if not isinstance(stmt, ast.Assign):
                continue
            targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            if "model_config" not in targets:
                continue
            # ConfigDict(extra="forbid", ...)
            if isinstance(stmt.value, ast.Call):
                for kw in stmt.value.keywords:
                    if (
                        kw.arg == "extra"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value == "forbid"
                    ):
                        forbids = True
        if not forbids:
            missing.append(f"{path.name}::{cls.name} (line {cls.lineno})")

    assert not missing, (
        'every request model must set model_config = ConfigDict(extra="forbid") '
        f"(finding F-004). Missing on: {missing}"
    )
