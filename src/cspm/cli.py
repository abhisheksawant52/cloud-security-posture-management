"""Command-line entrypoint for the ``cspm`` tool."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .config import get_settings
from .logging_config import configure_logging, get_logger
from .models import Severity
from .registry import registry
from .report import render
from .scanner import Scanner, meets_threshold

logger = get_logger("cli")


def _load_inventory(path: Optional[Path]) -> dict[str, list[dict]]:
    """Load an inventory JSON file, or return an empty inventory."""
    if path is None:
        return {"s3": [], "iam": [], "ec2": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise click.BadParameter("inventory file must contain a JSON object")
    return data


@click.group()
@click.version_option(__version__, prog_name="cspm")
def main() -> None:
    """Scan cloud accounts for CIS benchmark misconfigurations."""


@main.command(name="list-checks")
def list_checks() -> None:
    """List all registered CIS checks."""
    # Trigger registration of the built-in checks.
    from . import checks  # noqa: F401

    for check in registry.all():
        control = check.control
        click.echo(
            f"{control.control_id:28} {control.cis_ref:6} "
            f"{control.severity.value:8} {control.title}"
        )


@main.command()
@click.option(
    "--inventory",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a JSON resource inventory (offline scan).",
)
@click.option("--account-id", default="000000000000", help="AWS account id to record.")
@click.option(
    "--service",
    "services",
    multiple=True,
    help="Restrict the scan to one or more services (repeatable).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
)
def scan(
    inventory: Optional[Path],
    account_id: str,
    services: tuple[str, ...],
    output_format: str,
) -> None:
    """Run checks over an inventory and print a report.

    Exits non-zero when a failing finding meets the configured severity
    threshold, making the command suitable for CI gating.
    """
    settings = get_settings()
    configure_logging(settings.log_level)

    data = _load_inventory(inventory)
    scanner = Scanner(benchmark_version=settings.benchmark_version)
    result = scanner.scan(
        data,
        account_id=account_id,
        services=list(services) or None,
    )
    click.echo(render(result, output_format))

    if meets_threshold(result, settings.severity_threshold):
        sys.exit(1)


@main.command()
@click.option(
    "--inventory",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a JSON resource inventory.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="json",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to a file instead of stdout.",
)
def report(inventory: Path, output_format: str, output: Optional[Path]) -> None:
    """Generate a report from an inventory without gating on severity."""
    settings = get_settings()
    configure_logging(settings.log_level)

    data = _load_inventory(inventory)
    scanner = Scanner(benchmark_version=settings.benchmark_version)
    result = scanner.scan(data)
    rendered = render(result, output_format)

    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {output_format} report to {output}")
    else:
        click.echo(rendered)


def _severity_choices() -> list[str]:  # pragma: no cover - trivial helper
    return [s.value for s in Severity]


if __name__ == "__main__":  # pragma: no cover
    main()
