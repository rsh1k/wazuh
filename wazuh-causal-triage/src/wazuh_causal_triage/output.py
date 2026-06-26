# SPDX-License-Identifier: GPL-2.0-only
"""Output sinks for triage verdicts.

Verdicts can be emitted three ways, all additive and non-destructive:

* a JSON array of *all* scored incidents (a complete audit trail);
* a newline-delimited JSON file of *prioritized* incidents, formatted so a
  Wazuh logcollector can re-ingest them as enriched alerts (a feedback loop
  that never touches the original alert data); and
* stdout, for ad-hoc and containerized runs.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Optional

from .config import OutputConfig
from .models import Incident

logger = logging.getLogger(__name__)


class OutputWriter:
    """Persist and/or print scored incidents."""

    def __init__(self, config: OutputConfig) -> None:
        self._config = config

    def write(self, incidents: list[Incident]) -> None:
        """Emit ``incidents`` to every configured sink."""
        if self._config.json_path:
            self._write_json_array(self._config.json_path, incidents)
        if self._config.wazuh_feedback_path:
            self._write_wazuh_feedback(self._config.wazuh_feedback_path, incidents)
        if self._config.stdout:
            self._write_stdout(incidents)

    # ------------------------------------------------------------------
    # Sinks
    # ------------------------------------------------------------------
    def _write_json_array(self, path: str, incidents: list[Incident]) -> None:
        payload = [incident.to_dict() for incident in incidents]
        self._atomic_write(path, json.dumps(payload, indent=2))
        logger.info("Wrote %d incident(s) to %s", len(incidents), path)

    def _write_wazuh_feedback(self, path: str, incidents: list[Incident]) -> None:
        """Append prioritized incidents as NDJSON for Wazuh re-ingestion.

        We *append* rather than overwrite because a logcollector tails the file;
        each line is a compact, self-describing event under a dedicated
        ``integration`` key so a custom Wazuh decoder/rule can recognize it.
        """
        prioritized = [i for i in incidents if i.is_prioritized]
        if not prioritized:
            return
        lines = []
        for incident in prioritized:
            event = {
                "integration": "causal-triage",
                "incident_id": incident.incident_id,
                "host": incident.host,
                "score": round(incident.score, 2),
                "priority": incident.priority.value,
                "tactics": list(incident.tactics),
                "techniques": list(incident.technique_ids),
                "alert_count": incident.alert_count,
                "first_seen": incident.first_seen.isoformat(),
                "last_seen": incident.last_seen.isoformat(),
                "narrative": incident.narrative,
            }
            lines.append(json.dumps(event))
        try:
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError as exc:  # pragma: no cover - filesystem-dependent
            logger.error("Failed to write Wazuh feedback to %s: %s", path, exc)
            return
        logger.info("Appended %d prioritized incident(s) to %s", len(prioritized), path)

    def _write_stdout(self, incidents: list[Incident]) -> None:
        prioritized = [i for i in incidents if i.is_prioritized]
        print(
            f"\n=== Causal Triage: {len(incidents)} incident(s), "
            f"{len(prioritized)} prioritized ===\n"
        )
        # Show prioritized incidents first, each highest-score first.
        for incident in sorted(
            incidents, key=lambda i: (not i.is_prioritized, -i.score)
        ):
            flag = "[*]" if incident.is_prioritized else "[ ]"
            print(
                f"{flag} {incident.priority.value.upper():8s} "
                f"score={incident.score:6.2f}  {incident.incident_id}"
            )
            if incident.narrative:
                indented = "\n".join("      " + ln for ln in incident.narrative.splitlines())
                print(indented + "\n")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _atomic_write(path: str, content: str) -> None:
        """Write ``content`` to ``path`` atomically (temp file + rename)."""
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
