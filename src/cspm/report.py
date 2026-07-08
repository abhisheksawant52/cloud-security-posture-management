"""Render scan results to text, JSON, or SARIF 2.1.0.

SARIF output lets findings be uploaded to GitHub code scanning or any SARIF
viewer, mirroring the reporting style of mature security tooling.
"""

from __future__ import annotations

import json

from .models import ScanResult, Status

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_text(result: ScanResult) -> str:
    """Render a human-readable text report."""
    lines = [
        f"CSPM scan — account {result.account_id}",
        f"Benchmark: {result.benchmark_version}",
        "",
    ]
    for finding in result.findings:
        marker = "PASS" if finding.status is Status.PASS else "FAIL"
        lines.append(
            f"[{marker}] {finding.severity.value.upper():8} "
            f"{finding.cis_ref:6} {finding.control_id}: {finding.resource}"
        )
        if finding.failed and finding.details:
            lines.append(f"         {finding.details}")
    counts = result.counts_by_severity()
    lines.extend(
        [
            "",
            f"{len(result.failures)} failing / {len(result.findings)} checks "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']})",
        ]
    )
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    """Render the full scan result as indented JSON."""
    return json.dumps(result.to_dict(), indent=2)


def render_sarif(result: ScanResult) -> str:
    """Render failing findings as a SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    sarif_results = []
    for finding in result.failures:
        rules.setdefault(
            finding.control_id,
            {
                "id": finding.control_id,
                "name": finding.control_id,
                "shortDescription": {"text": finding.title},
                "helpUri": "https://www.cisecurity.org/benchmark/amazon_web_services",
                "properties": {"cis": finding.cis_ref, "severity": finding.severity.value},
            },
        )
        sarif_results.append(
            {
                "ruleId": finding.control_id,
                "level": _SARIF_LEVELS[finding.severity.value],
                "message": {"text": f"{finding.title}: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.resource}
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cspm",
                        "informationUri": "https://github.com/abhisheksawant52/cloud-security-posture-management",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


_RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}


def render(result: ScanResult, output_format: str = "text") -> str:
    """Render ``result`` in the requested ``output_format``."""
    try:
        return _RENDERERS[output_format](result)
    except KeyError as exc:  # pragma: no cover - guarded by CLI Choice
        raise ValueError(f"unknown format: {output_format}") from exc
