"""Core domain models for the CSPM scanner.

These dataclasses describe CIS benchmark controls, the individual findings a
check produces, and the aggregate result of a scan. They contain no cloud SDK
logic so they can be constructed and asserted against in offline unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    """Severity of a finding, ordered from most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Return a numeric rank where higher means more severe."""
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return order[self.value]


class Status(str, Enum):
    """Outcome of evaluating a control against a resource."""

    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True)
class Control:
    """A single CIS benchmark control that a check evaluates.

    Attributes:
        control_id: Stable internal identifier, e.g. ``s3-public-access``.
        cis_ref: The CIS Benchmark reference, e.g. ``2.1.5``.
        title: Human-readable control title.
        severity: Default severity applied to findings for this control.
        service: Cloud service the control applies to, e.g. ``s3``.
    """

    control_id: str
    cis_ref: str
    title: str
    severity: Severity
    service: str


@dataclass
class Finding:
    """The result of evaluating a control against a specific resource.

    Attributes:
        control_id: Identifier of the :class:`Control` that produced this.
        cis_ref: CIS Benchmark reference copied from the control.
        title: Human-readable control title.
        severity: Severity of the finding.
        resource: Identifier of the resource evaluated (ARN, name, or id).
        status: Whether the resource passed or failed the control.
        remediation: Guidance describing how to fix a failing resource.
        details: Optional free-form context about the evaluation.
    """

    control_id: str
    cis_ref: str
    title: str
    severity: Severity
    resource: str
    status: Status
    remediation: str
    details: str = ""

    @classmethod
    def from_control(
        cls,
        control: Control,
        resource: str,
        status: Status,
        remediation: str,
        details: str = "",
    ) -> "Finding":
        """Build a finding, inheriting reference metadata from ``control``."""
        return cls(
            control_id=control.control_id,
            cis_ref=control.cis_ref,
            title=control.title,
            severity=control.severity,
            resource=resource,
            status=status,
            remediation=remediation,
            details=details,
        )

    @property
    def failed(self) -> bool:
        """Return ``True`` when the finding represents a failing control."""
        return self.status is Status.FAIL

    def to_dict(self) -> dict[str, str]:
        """Serialize the finding to a JSON-friendly dictionary."""
        return {
            "control_id": self.control_id,
            "cis_ref": self.cis_ref,
            "title": self.title,
            "severity": self.severity.value,
            "resource": self.resource,
            "status": self.status.value,
            "remediation": self.remediation,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Aggregate result of running a set of checks over an inventory."""

    account_id: str
    benchmark_version: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add(self, findings: Iterable[Finding]) -> None:
        """Append one or more findings to the result."""
        self.findings.extend(findings)

    @property
    def failures(self) -> list[Finding]:
        """Return only the failing findings."""
        return [f for f in self.findings if f.failed]

    def counts_by_severity(self) -> dict[str, int]:
        """Return a count of failing findings grouped by severity value."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.failures:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        """Serialize the scan result to a JSON-friendly dictionary."""
        return {
            "account_id": self.account_id,
            "benchmark_version": self.benchmark_version,
            "started_at": self.started_at.isoformat(),
            "summary": {
                "total": len(self.findings),
                "failures": len(self.failures),
                "by_severity": self.counts_by_severity(),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
