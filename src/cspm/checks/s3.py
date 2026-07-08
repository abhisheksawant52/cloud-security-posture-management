"""CIS benchmark checks for Amazon S3 buckets.

Each check consumes the ``s3`` slice of the resource inventory. Every bucket is
expected to be a mapping such as::

    {
        "name": "my-bucket",
        "public": False,
        "encryption": "AES256",
        "versioning": "Enabled",
    }
"""

from __future__ import annotations

from ..models import Control, Finding, Severity, Status
from ..registry import Inventory, registry

PUBLIC_ACCESS = Control(
    control_id="s3-public-access",
    cis_ref="2.1.5",
    title="S3 buckets should block public access",
    severity=Severity.CRITICAL,
    service="s3",
)

ENCRYPTION = Control(
    control_id="s3-encryption",
    cis_ref="2.1.1",
    title="S3 buckets should enable server-side encryption",
    severity=Severity.HIGH,
    service="s3",
)

VERSIONING = Control(
    control_id="s3-versioning",
    cis_ref="2.1.3",
    title="S3 buckets should enable versioning",
    severity=Severity.MEDIUM,
    service="s3",
)


@registry.register(PUBLIC_ACCESS)
def check_public_access(inventory: Inventory) -> list[Finding]:
    """Fail buckets that allow public access."""
    findings: list[Finding] = []
    for bucket in inventory.get("s3", []):
        is_public = bool(bucket.get("public", False))
        findings.append(
            Finding.from_control(
                PUBLIC_ACCESS,
                resource=bucket.get("name", "<unknown>"),
                status=Status.FAIL if is_public else Status.PASS,
                remediation=(
                    "Enable S3 Block Public Access at the bucket and account "
                    "level and remove public bucket policies/ACLs."
                ),
                details="Bucket is publicly accessible." if is_public else "",
            )
        )
    return findings


@registry.register(ENCRYPTION)
def check_encryption(inventory: Inventory) -> list[Finding]:
    """Fail buckets without server-side encryption configured."""
    findings: list[Finding] = []
    for bucket in inventory.get("s3", []):
        algorithm = bucket.get("encryption")
        encrypted = bool(algorithm) and algorithm != "none"
        findings.append(
            Finding.from_control(
                ENCRYPTION,
                resource=bucket.get("name", "<unknown>"),
                status=Status.PASS if encrypted else Status.FAIL,
                remediation=(
                    "Apply a default encryption configuration using SSE-S3 "
                    "(AES256) or SSE-KMS."
                ),
                details="" if encrypted else "No default encryption configured.",
            )
        )
    return findings


@registry.register(VERSIONING)
def check_versioning(inventory: Inventory) -> list[Finding]:
    """Fail buckets that do not have versioning enabled."""
    findings: list[Finding] = []
    for bucket in inventory.get("s3", []):
        enabled = str(bucket.get("versioning", "")).lower() == "enabled"
        findings.append(
            Finding.from_control(
                VERSIONING,
                resource=bucket.get("name", "<unknown>"),
                status=Status.PASS if enabled else Status.FAIL,
                remediation="Enable versioning to protect against accidental deletion.",
                details="" if enabled else "Versioning is suspended or disabled.",
            )
        )
    return findings
