"""A lightweight registry for pluggable CSPM checks.

A *check* is any callable that accepts a resource inventory (a plain mapping of
service name to a list of resource dictionaries) and returns an iterable of
:class:`~cspm.models.Finding`. Checks register themselves with the module-level
:data:`registry` via the :func:`register` decorator, which keeps the scanner
decoupled from the concrete checks it runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .models import Control, Finding

Inventory = dict[str, list[dict]]
CheckFn = Callable[[Inventory], Iterable[Finding]]


@dataclass(frozen=True)
class Check:
    """A registered check bound to the control it evaluates."""

    control: Control
    func: CheckFn

    def run(self, inventory: Inventory) -> list[Finding]:
        """Execute the check against ``inventory`` and return findings."""
        return list(self.func(inventory))


class CheckRegistry:
    """Holds all registered checks and offers simple lookup helpers."""

    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, control: Control) -> Callable[[CheckFn], CheckFn]:
        """Return a decorator that registers ``func`` for ``control``."""

        def decorator(func: CheckFn) -> CheckFn:
            if control.control_id in self._checks:
                raise ValueError(f"duplicate control id: {control.control_id}")
            self._checks[control.control_id] = Check(control=control, func=func)
            return func

        return decorator

    def all(self) -> list[Check]:
        """Return all registered checks sorted by control id."""
        return [self._checks[key] for key in sorted(self._checks)]

    def for_service(self, service: str) -> list[Check]:
        """Return registered checks scoped to a single ``service``."""
        return [c for c in self.all() if c.control.service == service]

    def services(self) -> list[str]:
        """Return the sorted set of services with registered checks."""
        return sorted({c.control.service for c in self.all()})


registry = CheckRegistry()
"""The process-wide check registry used by the scanner and CLI."""
