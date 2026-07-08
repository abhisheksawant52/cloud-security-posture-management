"""Smoke tests that the package imports and registers checks."""

from __future__ import annotations

import cspm
from cspm.registry import registry


def test_version() -> None:
    assert cspm.__version__ == "0.1.0"


def test_checks_registered() -> None:
    # Importing the checks package registers the built-in checks.
    import cspm.checks  # noqa: F401

    services = registry.services()
    assert {"s3", "iam", "ec2"}.issubset(set(services))
    assert len(registry.all()) >= 5
