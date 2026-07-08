"""Tests for the Scanner orchestration and reporting."""

from __future__ import annotations

import json

from cspm.models import Severity
from cspm.report import render_sarif
from cspm.scanner import Scanner, meets_threshold

SAMPLE_INVENTORY = {
    "s3": [{"name": "public-bucket", "public": True, "encryption": "none", "versioning": "Enabled"}],
    "iam": [{"account": {"root_mfa_enabled": False}, "password_policy": {"minimum_length": 14}}],
    "ec2": [{"group_id": "sg-open", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]}],
}


def test_scan_produces_failures() -> None:
    result = Scanner().scan(SAMPLE_INVENTORY, account_id="123456789012")
    assert result.account_id == "123456789012"
    assert result.failures
    counts = result.counts_by_severity()
    assert counts["critical"] >= 1


def test_service_filter_limits_checks() -> None:
    result = Scanner().scan(SAMPLE_INVENTORY, services=["s3"])
    assert {f.control_id.split("-")[0] for f in result.findings} == {"s3"}


def test_meets_threshold() -> None:
    result = Scanner().scan(SAMPLE_INVENTORY)
    assert meets_threshold(result, Severity.HIGH) is True


def test_sarif_is_valid_json() -> None:
    result = Scanner().scan(SAMPLE_INVENTORY)
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "cspm"
