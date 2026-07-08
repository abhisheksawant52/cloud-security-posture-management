"""Unit tests exercising real check logic on injected sample resources."""

from __future__ import annotations

from cspm.checks import ec2, iam, s3
from cspm.models import Status


def _by_resource(findings, resource):
    return next(f for f in findings if f.resource == resource)


def test_public_bucket_fails_public_access_check() -> None:
    inventory = {
        "s3": [
            {"name": "public-bucket", "public": True},
            {"name": "private-bucket", "public": False},
        ]
    }
    findings = s3.check_public_access(inventory)
    assert _by_resource(findings, "public-bucket").status is Status.FAIL
    assert _by_resource(findings, "private-bucket").status is Status.PASS


def test_unencrypted_bucket_fails_encryption_check() -> None:
    inventory = {"s3": [{"name": "b", "encryption": "none"}]}
    assert s3.check_encryption(inventory)[0].status is Status.FAIL


def test_root_mfa_disabled_fails() -> None:
    inventory = {"iam": [{"account": {"root_mfa_enabled": False}}]}
    assert iam.check_root_mfa(inventory)[0].status is Status.FAIL


def test_weak_password_policy_fails() -> None:
    inventory = {"iam": [{"password_policy": {"minimum_length": 8}}]}
    assert iam.check_password_policy(inventory)[0].status is Status.FAIL


def test_stale_access_key_fails() -> None:
    inventory = {
        "iam": [
            {
                "users": [
                    {"name": "alice", "access_key_age_days": 200, "key_active": True},
                    {"name": "bob", "access_key_age_days": 10, "key_active": True},
                ]
            }
        ]
    }
    findings = iam.check_unused_keys(inventory)
    assert _by_resource(findings, "alice").status is Status.FAIL
    assert _by_resource(findings, "bob").status is Status.PASS


def test_open_security_group_fails() -> None:
    inventory = {
        "ec2": [
            {"group_id": "sg-open", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]},
            {"group_id": "sg-safe", "ingress": [{"port": 22, "cidr": "10.0.0.0/8"}]},
        ]
    }
    findings = ec2.check_open_security_groups(inventory)
    assert _by_resource(findings, "sg-open").status is Status.FAIL
    assert _by_resource(findings, "sg-safe").status is Status.PASS
