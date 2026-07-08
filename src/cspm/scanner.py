"""The Scanner orchestrates registered checks over a resource inventory.

The scanner is deliberately decoupled from AWS. It accepts an inventory — a
mapping of service name to a list of resource dictionaries — which in
production is collected from a boto3 session, but in tests is injected directly.
This keeps all control logic verifiable offline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .logging_config import get_logger
from .models import ScanResult, Severity
from .registry import CheckRegistry, Inventory
from .registry import registry as default_registry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from boto3.session import Session

logger = get_logger("scanner")


class Scanner:
    """Run registered CIS checks over an injected resource inventory."""

    def __init__(
        self,
        benchmark_version: str = "CIS AWS Foundations 3.0.0",
        registry: Optional[CheckRegistry] = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            benchmark_version: Benchmark version recorded on the result.
            registry: Check registry to use; defaults to the shared registry.
        """
        # Importing the checks package registers the built-in checks.
        from . import checks  # noqa: F401

        self.benchmark_version = benchmark_version
        self.registry = registry or default_registry

    def scan(
        self,
        inventory: Inventory,
        account_id: str = "000000000000",
        services: Optional[list[str]] = None,
    ) -> ScanResult:
        """Evaluate the inventory and return an aggregate :class:`ScanResult`.

        Args:
            inventory: Mapping of service name to resource dictionaries.
            account_id: AWS account id recorded on the result.
            services: Optional subset of services to scan; ``None`` scans all.
        """
        result = ScanResult(
            account_id=account_id,
            benchmark_version=self.benchmark_version,
        )
        checks = self.registry.all()
        if services is not None:
            wanted = set(services)
            checks = [c for c in checks if c.control.service in wanted]

        for check in checks:
            logger.debug("running check %s", check.control.control_id)
            result.add(check.run(inventory))

        logger.info(
            "scan complete: %d findings, %d failures",
            len(result.findings),
            len(result.failures),
        )
        return result

    @staticmethod
    def inventory_from_session(
        session: "Session",
        region: Optional[str] = None,
    ) -> Inventory:
        """Collect a resource inventory from a live boto3 session.

        This is a thin, best-effort collector kept intentionally minimal; the
        scanning logic operates on the returned mapping regardless of source.

        Args:
            session: An authenticated ``boto3.session.Session``.
            region: Optional region override for the service clients.
        """
        inventory: Inventory = {"s3": [], "iam": [], "ec2": []}

        s3 = session.client("s3", region_name=region)
        for bucket in s3.list_buckets().get("Buckets", []):
            inventory["s3"].append({"name": bucket.get("Name")})

        ec2 = session.client("ec2", region_name=region)
        for group in ec2.describe_security_groups().get("SecurityGroups", []):
            ingress = [
                {
                    "port": perm.get("FromPort"),
                    "protocol": perm.get("IpProtocol"),
                    "cidr": rng.get("CidrIp"),
                }
                for perm in group.get("IpPermissions", [])
                for rng in perm.get("IpRanges", [])
            ]
            inventory["ec2"].append(
                {"group_id": group.get("GroupId"), "ingress": ingress}
            )

        return inventory


def meets_threshold(result: ScanResult, threshold: Severity) -> bool:
    """Return ``True`` if any failure meets or exceeds ``threshold``."""
    return any(f.severity.rank >= threshold.rank for f in result.failures)
