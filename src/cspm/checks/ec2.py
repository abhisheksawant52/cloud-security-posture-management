"""CIS benchmark checks for EC2 networking (security groups).

The ``ec2`` slice of the inventory is expected to contain security-group
mappings, for example::

    {
        "group_id": "sg-0123",
        "ingress": [
            {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
        ],
    }
"""

from __future__ import annotations

from ..models import Control, Finding, Severity, Status
from ..registry import Inventory, registry

OPEN_INGRESS = Control(
    control_id="ec2-open-security-group",
    cis_ref="5.2",
    title="Security groups should not allow ingress from 0.0.0.0/0 to admin ports",
    severity=Severity.HIGH,
    service="ec2",
)

# Sensitive administrative ports that must never be open to the world.
ADMIN_PORTS = frozenset({22, 3389})
OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


@registry.register(OPEN_INGRESS)
def check_open_security_groups(inventory: Inventory) -> list[Finding]:
    """Fail security groups that expose admin ports to the internet."""
    findings: list[Finding] = []
    for group in inventory.get("ec2", []):
        group_id = group.get("group_id", "<unknown>")
        open_rules = [
            rule
            for rule in group.get("ingress", [])
            if rule.get("cidr") in OPEN_CIDRS and int(rule.get("port", -1)) in ADMIN_PORTS
        ]
        exposed = bool(open_rules)
        ports = ", ".join(str(r.get("port")) for r in open_rules)
        findings.append(
            Finding.from_control(
                OPEN_INGRESS,
                resource=group_id,
                status=Status.FAIL if exposed else Status.PASS,
                remediation=(
                    "Restrict ingress on ports 22/3389 to known CIDR ranges or a "
                    "bastion/SSM session instead of 0.0.0.0/0."
                ),
                details=f"Ports open to the world: {ports}." if exposed else "",
            )
        )
    return findings
