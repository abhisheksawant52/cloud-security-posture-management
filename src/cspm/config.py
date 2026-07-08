"""Runtime configuration for the CSPM scanner.

Settings are loaded from environment variables (optionally via a ``.env`` file)
using ``pydantic-settings``. Every variable is prefixed with ``CSPM_``.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import Severity


class Settings(BaseSettings):
    """Application settings sourced from the environment.

    Attributes:
        aws_profile: Named AWS profile used to create a boto3 session.
        aws_region: Default AWS region to scan.
        benchmark_version: CIS AWS Foundations Benchmark version to report.
        severity_threshold: Minimum severity that causes a non-zero exit.
        log_level: Root log level, e.g. ``INFO`` or ``DEBUG``.
    """

    model_config = SettingsConfigDict(
        env_prefix="CSPM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    aws_profile: str = Field(default="default", description="AWS named profile")
    aws_region: str = Field(default="us-east-1", description="AWS region to scan")
    benchmark_version: str = Field(default="CIS AWS Foundations 3.0.0")
    severity_threshold: Severity = Field(default=Severity.HIGH)
    log_level: str = Field(default="INFO")


def get_settings() -> Settings:
    """Return a freshly loaded :class:`Settings` instance."""
    return Settings()
