"""Pluggable check framework for the CSPM scanner.

Importing this package registers all built-in checks with the shared
:data:`cspm.registry.registry` so that :class:`cspm.scanner.Scanner` can
discover them. Each check module registers one or more :class:`Check`
callables keyed by service.
"""

from __future__ import annotations

from . import ec2, iam, s3  # noqa: F401  (imported for registration side effects)

__all__ = ["s3", "iam", "ec2"]
