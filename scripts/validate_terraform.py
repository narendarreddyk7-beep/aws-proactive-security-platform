#!/usr/bin/env python3
"""Terraform configuration linter — a stand-in for `terraform validate`.

WHY THIS EXISTS
---------------
`terraform validate` needs the Terraform binary and a provider download. In a
restricted build environment neither is available (HashiCorp's release
endpoint is outside the network allow-list in this project's sandbox), so the
configuration would otherwise go completely unverified until someone with AWS
access ran it.

This script recovers the part of `terraform validate` that does not need a
provider: parse every `.tf` file, build the symbol table, and check that every
reference resolves. It catches the overwhelming majority of real mistakes --
a typo'd variable, a renamed resource, an output referring to something that
no longer exists, a module input that does not exist.

WHAT IT DOES NOT DO
-------------------
It is NOT `terraform validate` and must not be reported as such:

* no provider schema validation -- a misspelled *argument* on a resource
  (`retention_days` instead of `retention_in_days`) is not caught;
* no type checking of expressions;
* no `count`/`for_each` evaluation, so `resource[0]` indexing is not verified;
* no backend or provider-plugin resolution.

`terraform validate`, `terraform fmt -check` and `terraform plan` remain
required before any deployment. See docs/AWS_DEPLOYMENT.md §"Verification
status" for exactly what has and has not been run.

CHECKS PERFORMED
----------------
  TF001  HCL parse failure
  TF002  Reference to an undeclared variable (`var.x`)
  TF003  Reference to an undeclared local (`local.x`)
  TF004  Reference to an undeclared resource or data source
  TF005  Reference to an undeclared module
  TF006  Module input that the module does not declare
  TF007  Required module input not supplied
  TF008  Variable declared but never used
  TF009  Variable with no description
  TF010  Output with no description
  TF011  Hardcoded AWS account id outside a documented placeholder
  TF012  Possible hardcoded secret

USAGE
    python scripts/validate_terraform.py infrastructure/terraform
    python scripts/validate_terraform.py infrastructure/terraform --strict

EXIT CODES
    0  no errors (warnings may be present)
    1  one or more errors, or warnings with --strict
    2  could not run (missing directory, python-hcl2 not installed)
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

# Values that look like an AWS account id but are documented placeholders.
PLACEHOLDER_ACCOUNT_IDS = {"000000000000", "111111111111", "123456789012"}

SECRET_PATTERNS = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key id"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (
        re.compile(r"(?i)\b(secret|password|passwd|token|api[_-]?key)\s*=\s*\"[^\"${}\s]{12,}\""),
        "possible hardcoded credential",
    ),
)

# A 12-digit run is only an account id when it is NOT part of a larger token.
# The hyphen exclusions matter: a UUID segment such as the tail of
# "22222222-2222-4222-8222-222222222222" is exactly twelve digits, and
# reporting every synthetic user id as a leaked account number would make the
# check useless. In an ARN an account id is delimited by colons, never hyphens.
ACCOUNT_ID_PATTERN = re.compile(r"(?<![\d.\-])(\d{12})(?![\d.\-])")

#: `var.x`, `local.x`, `module.x`, `each.value`, `count.index`, `path.module`,
#: and `<type>.<name>` resource references.
REF_VAR = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)")
REF_LOCAL = re.compile(r"\blocal\.([A-Za-z_][A-Za-z0-9_-]*)")
REF_MODULE = re.compile(r"\bmodule\.([A-Za-z_][A-Za-z0-9_-]*)")
REF_DATA = re.compile(r"\bdata\.([A-Za-z_][A-Za-z0-9_-]*)\.([A-Za-z_][A-Za-z0-9_-]*)")
REF_RESOURCE = re.compile(
    r"\b(aws_[A-Za-z0-9_]+|archive_file|local_file)\.([A-Za-z_][A-Za-z0-9_-]*)"
)

#: Scope-local names that are always valid inside the right block.
BUILTIN_SCOPES = {"each", "count", "path", "terraform", "self"}


@dataclass
class Issue:
    """One linter finding."""

    code: str
    severity: str
    file: str
    message: str

    def render(self) -> str:
        """Human-readable single line."""
        marker = "ERROR  " if self.severity == SEVERITY_ERROR else "warning"
        return f"[{marker}] {self.code} {self.file}: {self.message}"


@dataclass
class Symbols:
    """Everything a configuration declares."""

    variables: dict[str, dict[str, Any]]
    locals_: set[str]
    resources: set[str]
    data_sources: set[str]
    modules: dict[str, dict[str, Any]]
    outputs: dict[str, dict[str, Any]]
    used_variables: set[str]


#: Metadata keys python-hcl2 injects into the parsed tree.
_HCL2_METADATA = {"__is_block__", "__comments__", "__start_line__", "__end_line__"}


def _as_list(value: Any) -> list[Any]:
    """hcl2 returns repeated blocks as lists; normalise everything to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _unquote(label: Any) -> str:
    """Strip the quotes python-hcl2 keeps around block labels.

    The library returns a resource block as ``{'"aws_dynamodb_table"':
    {'"main"': {...}}}`` -- the quotes are part of the key. Normalising here
    keeps every downstream check working on plain identifiers.
    """
    text = str(label).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def _block_entries(block: Any) -> list[tuple[str, dict[str, Any]]]:
    """Yield ``(unquoted_label, body)`` pairs from one parsed block."""
    if not isinstance(block, dict):
        return []
    return [
        (_unquote(label), body if isinstance(body, dict) else {})
        for label, body in block.items()
        if _unquote(label) not in _HCL2_METADATA
    ]


def _walk_strings(node: Any) -> list[str]:
    """Collect every string anywhere in a parsed HCL tree."""
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            if str(key) in _HCL2_METADATA:
                continue
            found.append(str(key))
            found.extend(_walk_strings(value))
    elif isinstance(node, (list, tuple)):
        for item in node:
            found.extend(_walk_strings(item))
    return found


def parse_directory(directory: Path) -> tuple[dict[str, dict[str, Any]], list[Issue]]:
    """Parse every ``.tf`` file in a directory (non-recursive, like Terraform)."""
    try:
        import hcl2
    except ImportError:
        print(
            "error: python-hcl2 is not installed. Install it with:\n    pip install python-hcl2",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    parsed: dict[str, dict[str, Any]] = {}
    issues: list[Issue] = []

    files = sorted(directory.glob("*.tf"))
    if not files:
        issues.append(
            Issue("TF001", SEVERITY_ERROR, str(directory), "no .tf files found in directory")
        )
        return parsed, issues

    for path in files:
        try:
            with path.open(encoding="utf-8") as handle:
                parsed[path.name] = hcl2.load(handle)
        except Exception as exc:  # noqa: BLE001 - any parse failure is one finding
            issues.append(
                Issue(
                    "TF001",
                    SEVERITY_ERROR,
                    path.name,
                    f"HCL parse failure: {type(exc).__name__}: {exc}",
                )
            )

    return parsed, issues


def build_symbols(parsed: dict[str, dict[str, Any]]) -> Symbols:
    """Build the symbol table from parsed configurations."""
    variables: dict[str, dict[str, Any]] = {}
    locals_: set[str] = set()
    resources: set[str] = set()
    data_sources: set[str] = set()
    modules: dict[str, dict[str, Any]] = {}
    outputs: dict[str, dict[str, Any]] = {}

    for body in parsed.values():
        for block in _as_list(body.get("variable")):
            for name, definition in _block_entries(block):
                variables[name] = definition

        for block in _as_list(body.get("locals")):
            if isinstance(block, dict):
                locals_.update(
                    _unquote(key) for key in block if _unquote(key) not in _HCL2_METADATA
                )

        for block in _as_list(body.get("resource")):
            for resource_type, instances in _block_entries(block):
                for name, _ in _block_entries(instances):
                    resources.add(f"{resource_type}.{name}")

        for block in _as_list(body.get("data")):
            for data_type, instances in _block_entries(block):
                for name, _ in _block_entries(instances):
                    data_sources.add(f"{data_type}.{name}")

        for block in _as_list(body.get("module")):
            for name, definition in _block_entries(block):
                modules[name] = definition

        for block in _as_list(body.get("output")):
            for name, definition in _block_entries(block):
                outputs[name] = definition

    return Symbols(
        variables=variables,
        locals_=locals_,
        resources=resources,
        data_sources=data_sources,
        modules=modules,
        outputs=outputs,
        used_variables=set(),
    )


def check_references(parsed: dict[str, dict[str, Any]], symbols: Symbols) -> list[Issue]:
    """Check that every reference resolves to a declared symbol."""
    issues: list[Issue] = []

    for filename, body in parsed.items():
        for text in _walk_strings(body):
            for name in REF_VAR.findall(text):
                symbols.used_variables.add(name)
                if name not in symbols.variables:
                    issues.append(
                        Issue(
                            "TF002",
                            SEVERITY_ERROR,
                            filename,
                            f"reference to undeclared variable 'var.{name}'",
                        )
                    )

            for name in REF_LOCAL.findall(text):
                if name not in symbols.locals_:
                    issues.append(
                        Issue(
                            "TF003",
                            SEVERITY_ERROR,
                            filename,
                            f"reference to undeclared local 'local.{name}'",
                        )
                    )

            for data_type, name in REF_DATA.findall(text):
                if f"{data_type}.{name}" not in symbols.data_sources:
                    issues.append(
                        Issue(
                            "TF004",
                            SEVERITY_ERROR,
                            filename,
                            f"reference to undeclared data source 'data.{data_type}.{name}'",
                        )
                    )

            # Strip `data.` prefixes first so a data reference is not also
            # read as a resource reference.
            resource_text = REF_DATA.sub("", text)
            for resource_type, name in REF_RESOURCE.findall(resource_text):
                reference = f"{resource_type}.{name}"
                if reference in symbols.resources:
                    continue
                if f"{resource_type}.{name}" in symbols.data_sources:
                    continue
                issues.append(
                    Issue(
                        "TF004",
                        SEVERITY_ERROR,
                        filename,
                        f"reference to undeclared resource '{reference}'",
                    )
                )

            for name in REF_MODULE.findall(text):
                if name not in symbols.modules:
                    issues.append(
                        Issue(
                            "TF005",
                            SEVERITY_ERROR,
                            filename,
                            f"reference to undeclared module 'module.{name}'",
                        )
                    )

    return issues


def check_module_calls(
    _parsed: dict[str, dict[str, Any]], symbols: Symbols, root: Path
) -> list[Issue]:
    """Check module inputs against the called module's own variables.

    ``_parsed`` is unused but kept so every check shares one signature and
    ``validate`` can dispatch them uniformly.
    """
    issues: list[Issue] = []

    for name, definition in symbols.modules.items():
        source = definition.get("source")
        if isinstance(source, list):
            source = source[0] if source else None
        source = _unquote(source) if source is not None else None
        if not isinstance(source, str) or source.startswith(("http", "git", "registry")):
            continue

        module_dir = (root / source).resolve()
        if not module_dir.is_dir():
            issues.append(
                Issue(
                    "TF005",
                    SEVERITY_ERROR,
                    "module." + name,
                    f"module source directory not found: {source}",
                )
            )
            continue

        module_parsed, parse_issues = parse_directory(module_dir)
        issues.extend(parse_issues)
        module_symbols = build_symbols(module_parsed)

        reserved = {"source", "count", "for_each", "providers", "depends_on"}
        supplied = {
            _unquote(key) for key in definition if _unquote(key) not in reserved | _HCL2_METADATA
        }
        declared = set(module_symbols.variables)

        for unknown in sorted(supplied - declared):
            issues.append(
                Issue(
                    "TF006",
                    SEVERITY_ERROR,
                    "module." + name,
                    f"input '{unknown}' is not declared by the module at {source}",
                )
            )

        required = {
            variable for variable, spec in module_symbols.variables.items() if "default" not in spec
        }
        for missing in sorted(required - supplied):
            issues.append(
                Issue(
                    "TF007",
                    SEVERITY_ERROR,
                    "module." + name,
                    f"required input '{missing}' not supplied to the module at {source}",
                )
            )

    return issues


def check_hygiene(_parsed: dict[str, dict[str, Any]], symbols: Symbols) -> list[Issue]:
    """Documentation and unused-declaration checks.

    ``_parsed`` is unused but kept for signature parity with the other checks.
    """
    issues: list[Issue] = []

    for name in sorted(set(symbols.variables) - symbols.used_variables):
        issues.append(
            Issue("TF008", SEVERITY_WARNING, "variables.tf", f"variable '{name}' is never used")
        )

    for name, spec in sorted(symbols.variables.items()):
        if not spec.get("description"):
            issues.append(
                Issue(
                    "TF009",
                    SEVERITY_WARNING,
                    "variables.tf",
                    f"variable '{name}' has no description",
                )
            )

    for name, spec in sorted(symbols.outputs.items()):
        if not spec.get("description"):
            issues.append(
                Issue(
                    "TF010", SEVERITY_WARNING, "outputs.tf", f"output '{name}' has no description"
                )
            )

    return issues


def check_hardcoded_values(directory: Path) -> list[Issue]:
    """Scan raw file text for account ids and credential-shaped strings.

    Raw text rather than the parsed tree, because a secret in a comment is
    still a committed secret.
    """
    issues: list[Issue] = []

    for path in sorted(directory.glob("*.tf")) + sorted(directory.glob("*.tfvars")):
        text = path.read_text(encoding="utf-8")

        for line_number, line in enumerate(text.splitlines(), start=1):
            for account_id in ACCOUNT_ID_PATTERN.findall(line):
                if account_id in PLACEHOLDER_ACCOUNT_IDS:
                    continue
                issues.append(
                    Issue(
                        "TF011",
                        SEVERITY_ERROR,
                        f"{path.name}:{line_number}",
                        f"hardcoded 12-digit value that looks like an AWS "
                        f"account id: {account_id}. Use "
                        "data.aws_caller_identity.current.account_id or a variable.",
                    )
                )

            for pattern, label in SECRET_PATTERNS:
                if pattern.search(line):
                    issues.append(
                        Issue(
                            "TF012",
                            SEVERITY_ERROR,
                            f"{path.name}:{line_number}",
                            f"{label} appears to be hardcoded. Use a secret store reference.",
                        )
                    )

    return issues


def validate(directory: Path, *, check_hygiene_rules: bool = True) -> list[Issue]:
    """Run every check against one Terraform directory."""
    parsed, issues = parse_directory(directory)
    if not parsed:
        return issues

    symbols = build_symbols(parsed)
    issues.extend(check_references(parsed, symbols))
    issues.extend(check_module_calls(parsed, symbols, directory))
    issues.extend(check_hardcoded_values(directory))
    if check_hygiene_rules:
        issues.extend(check_hygiene(parsed, symbols))

    return issues


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        prog="validate_terraform.py",
        description=(
            "Parse and reference-check a Terraform configuration without the Terraform "
            "binary. NOT a replacement for `terraform validate` -- see the module docstring."
        ),
    )
    parser.add_argument("directory", help="Terraform directory to check.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors (exit 1).")
    parser.add_argument(
        "--no-hygiene",
        action="store_true",
        help="Skip the documentation and unused-declaration warnings.",
    )
    args = parser.parse_args(argv)

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"error: {directory} is not a directory", file=sys.stderr)
        return 2

    issues = validate(directory, check_hygiene_rules=not args.no_hygiene)

    errors = [i for i in issues if i.severity == SEVERITY_ERROR]
    warnings = [i for i in issues if i.severity == SEVERITY_WARNING]

    print("=" * 78)
    print(f"Terraform configuration linter — {directory}")
    print("=" * 78)

    for issue in errors + warnings:
        print(issue.render())

    tf_files = len(sorted(directory.glob("*.tf")))
    print()
    print(f"Files parsed : {tf_files}")
    print(f"Errors       : {len(errors)}")
    print(f"Warnings     : {len(warnings)}")
    print()
    print("NOTE: this checks HCL syntax and reference resolution only. It does NOT")
    print("      validate provider schemas or argument names. `terraform validate`,")
    print("      `terraform fmt -check` and `terraform plan` are still required")
    print("      before deployment — see docs/AWS_DEPLOYMENT.md.")

    if errors:
        return 1
    if warnings and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
