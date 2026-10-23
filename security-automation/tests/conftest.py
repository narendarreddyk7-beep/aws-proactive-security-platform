"""Path setup and shared fixtures for the security-automation tests.

``security-automation/`` contains a hyphen, so it cannot be a Python package
name. The directory is put on ``sys.path`` here instead, which keeps the tools
runnable as plain scripts (``python security-automation/iam_policy_checker.py``)
rather than requiring an installed package just to lint a policy.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS_DIR.parent
TRIAGE_LAMBDA_SRC = REPO_ROOT / "infrastructure" / "modules" / "security_hub_triage" / "src"

for candidate in (TOOLS_DIR, TRIAGE_LAMBDA_SRC):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def sample_data_dir() -> Path:
    """Directory holding the synthetic sample inputs."""
    return REPO_ROOT / "sample-data"


@pytest.fixture
def tmp_json(tmp_path: Path) -> Any:
    """Return a helper that writes an object to a temporary JSON file."""
    import json

    def _write(name: str, payload: Any) -> Path:
        destination = tmp_path / name
        destination.write_text(json.dumps(payload), encoding="utf-8")
        return destination

    return _write


@pytest.fixture(autouse=True)
def _no_ambient_aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make sure no test can accidentally reach a real AWS account."""
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")  # noqa: S105
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    yield
