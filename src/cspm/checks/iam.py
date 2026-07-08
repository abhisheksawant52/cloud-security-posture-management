"""CIS benchmark checks for AWS IAM.

The ``iam`` slice of the inventory is expected to contain a single account-level
mapping plus zero or more user mappings, for example::

    {
        "account": {"root_mfa_enabled": True},
        "password_policy": {"minimum_length": 14},
        "users": [{"name": "alice", "access_key_age_days": 30, "key_active": True}],
    }
"""

from __future__ import annotations

from ..models import Control, Finding, Severity, Status
from ..registry import Inventory, registry

ROOT_MFA = Control(
    control_id="iam-root-mfa",
    cis_ref="1.5",
    title="MFA should be enabled for the root account",
    severity=Severity.CRITICAL,
    service="iam",
)

PASSWORD_POLICY = Control(
    control_id="iam-password-policy",
    cis_ref="1.8",
    title="IAM password policy should require a minimum length of 14",
    severity=Severity.MEDIUM,
    service="iam",
)

UNUSED_KEYS = Control(
    control_id="iam-unused-access-keys",
    cis_ref="1.12",
    title="Access keys unused for 90 days should be disabled",
    severity=Severity.HIGH,
    service="iam",
)

MAX_KEY_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14


def _iam_config(inventory: Inventory) -> dict:
    """Return the first ``iam`` inventory entry, or an empty mapping."""
    entries = inventory.get("iam", [])
    return entries[0] if entries else {}


@registry.register(ROOT_MFA)
def check_root_mfa(inventory: Inventory) -> list[Finding]:
    """Fail when the root account does not have MFA enabled."""
    config = _iam_config(inventory)
    account = config.get("account", {})
    enabled = bool(account.get("root_mfa_enabled", False))
    return [
        Finding.from_control(
            ROOT_MFA,
            resource="root-account",
            status=Status.PASS if enabled else Status.FAIL,
            remediation="Enable a hardware or virtual MFA device on the root user.",
            details="" if enabled else "Root account is missing MFA.",
        )
    ]


@registry.register(PASSWORD_POLICY)
def check_password_policy(inventory: Inventory) -> list[Finding]:
    """Fail when the account password policy is weaker than CIS guidance."""
    config = _iam_config(inventory)
    policy = config.get("password_policy", {})
    length = int(policy.get("minimum_length", 0))
    compliant = length >= MIN_PASSWORD_LENGTH
    return [
        Finding.from_control(
            PASSWORD_POLICY,
            resource="account-password-policy",
            status=Status.PASS if compliant else Status.FAIL,
            remediation=f"Require a minimum password length of {MIN_PASSWORD_LENGTH}.",
            details="" if compliant else f"Minimum length is {length}.",
        )
    ]


@registry.register(UNUSED_KEYS)
def check_unused_keys(inventory: Inventory) -> list[Finding]:
    """Fail active access keys older than the maximum permitted age."""
    config = _iam_config(inventory)
    findings: list[Finding] = []
    for user in config.get("users", []):
        active = bool(user.get("key_active", False))
        age = int(user.get("access_key_age_days", 0))
        stale = active and age > MAX_KEY_AGE_DAYS
        findings.append(
            Finding.from_control(
                UNUSED_KEYS,
                resource=user.get("name", "<unknown>"),
                status=Status.FAIL if stale else Status.PASS,
                remediation="Rotate or deactivate access keys older than 90 days.",
                details=f"Active key age is {age} days." if stale else "",
            )
        )
    return findings
