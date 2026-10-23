"""Security tests.

Each module asserts a security *invariant*. Tests tagged ``@pytest.mark.regression``
guard a specific confirmed finding recorded in ``assessments/security-findings.md``;
the finding ID appears in the test docstring so the two can never drift apart.
"""
