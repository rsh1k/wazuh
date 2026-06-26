# SPDX-License-Identifier: GPL-2.0-only
"""Command-line interface.

Usage examples
--------------
Run once against a config file::

    wazuh-causal-triage run --config config/config.yaml

Run with all defaults (reads /var/ossec/logs/alerts/alerts.json)::

    wazuh-causal-triage run

Override the alert file ad hoc::

    wazuh-causal-triage run --alerts ./alerts.json
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from . import __version__
from .config import AppConfig, ConfigError
from .ingest import IngestError
from .pipeline import TriagePipeline


def _configure_logging(level_name: str) -> None:
    """Initialize root logging once, with a concise operational format."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _load_config(args: argparse.Namespace) -> AppConfig:
    """Build the effective configuration from file plus CLI overrides."""
    if args.config:
        config = AppConfig.from_yaml(args.config)
    else:
        config = AppConfig.from_dict({})

    # Targeted CLI overrides take precedence over the file.
    if args.alerts:
        config.ingest.source = "file"
        config.ingest.file.path = args.alerts
    if args.log_level:
        config.log_level = args.log_level
    if args.no_stdout:
        config.output.stdout = False
    config.validate()
    return config


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser (exposed for testing)."""
    parser = argparse.ArgumentParser(
        prog="wazuh-causal-triage",
        description="Causal alert-triage companion module for Wazuh SIEM.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run one triage cycle.")
    run_parser.add_argument("--config", help="Path to a YAML configuration file.")
    run_parser.add_argument("--alerts", help="Override: path to a Wazuh alerts.json file.")
    run_parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Override the configured log level.",
    )
    run_parser.add_argument(
        "--no-stdout", action="store_true", help="Suppress the stdout report."
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Logging is configured from the (possibly overridden) level as early as
    # possible so even config errors are well-formatted.
    preliminary_level = getattr(args, "log_level", None) or "INFO"
    _configure_logging(preliminary_level)
    log = logging.getLogger("wazuh_causal_triage.cli")

    if args.command == "run":
        try:
            config = _load_config(args)
        except ConfigError as exc:
            log.error("Configuration error: %s", exc)
            return 2

        _configure_logging(config.log_level)  # Re-apply final level.

        try:
            pipeline = TriagePipeline(config)
            result = pipeline.run()
        except IngestError as exc:
            log.error("Ingestion failed: %s", exc)
            return 3
        except Exception:  # pragma: no cover - last-resort guard
            log.exception("Unexpected error during triage run")
            return 1

        log.info(
            "Done. %d alerts, %d incidents, %d prioritized.",
            result.alerts_ingested,
            result.incidents_total,
            result.incidents_prioritized,
        )
        return 0

    parser.error(f"Unknown command: {args.command}")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
