# SPDX-License-Identifier: GPL-2.0-only
"""Narrative generation for incidents.

Two narrators are provided:

* :class:`TemplateNarrator` builds a deterministic, dependency-free summary
  from the incident's structured fields. It always works and is the safe
  default.
* :class:`OllamaNarrator` asks a *locally hosted* LLM to write a richer analyst
  narrative, passing only the structured incident summary (never raw logs) to
  keep data local and the prompt small. On any failure it transparently falls
  back to the template narrator, so narrative generation can never crash the
  pipeline or block on an unreachable model.

All narratives are advisory. LLM output may be imperfect and must be reviewed
by an analyst; the template narrator's deterministic facts are always included
as ground truth alongside any LLM prose.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from .config import NarrativeConfig
from .models import Incident

logger = logging.getLogger(__name__)


class Narrator(ABC):
    """Abstract narrator interface."""

    @abstractmethod
    def narrate(self, incident: Incident) -> str:
        """Return a human-readable narrative for ``incident``."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Template narrator
# ---------------------------------------------------------------------------
class TemplateNarrator(Narrator):
    """Deterministic narrative assembled from structured incident fields."""

    def narrate(self, incident: Incident) -> str:
        lines: list[str] = []
        lines.append(
            f"Incident {incident.incident_id} on host '{incident.host}' "
            f"[priority={incident.priority.value}, score={incident.score:.1f}]."
        )
        duration = (incident.last_seen - incident.first_seen).total_seconds()
        lines.append(
            f"{incident.alert_count} causally linked alert(s) spanning "
            f"{duration:.0f}s (from {incident.first_seen.isoformat()} "
            f"to {incident.last_seen.isoformat()})."
        )
        if incident.tactics:
            lines.append("ATT&CK tactics observed: " + ", ".join(incident.tactics) + ".")
        if incident.technique_ids:
            lines.append("Techniques: " + ", ".join(incident.technique_ids) + ".")
        if len(incident.hosts_involved) > 1:
            lines.append(
                "Multiple hosts/destinations involved (possible lateral movement/egress): "
                + ", ".join(incident.hosts_involved)
                + "."
            )

        lines.append("Event sequence:")
        for index, alert in enumerate(incident.alerts, start=1):
            actor = alert.image or alert.user or "—"
            lines.append(
                f"  {index}. [{alert.timestamp.isoformat()}] "
                f"(level {alert.rule_level}, rule {alert.rule_id}) "
                f"{alert.description} | actor={actor}"
            )

        lines.append("Scoring rationale:")
        for factor in incident.factors:
            lines.append(f"  - {factor.name}: +{factor.contribution} ({factor.detail})")

        lines.append(
            "NOTE: This is an automated triage hypothesis. Verify before acting; "
            "no alerts have been suppressed or modified."
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ollama narrator
# ---------------------------------------------------------------------------
class OllamaNarrator(Narrator):
    """Generate a narrative via a locally hosted Ollama model.

    The structured incident summary (not raw logs) is sent to the local Ollama
    HTTP API. Any error — unreachable model, timeout, malformed response —
    results in a transparent fallback to :class:`TemplateNarrator`.
    """

    def __init__(self, config: NarrativeConfig) -> None:
        self._config = config
        self._fallback = TemplateNarrator()

    def _build_prompt(self, incident: Incident) -> str:
        summary = {
            "host": incident.host,
            "score": round(incident.score, 1),
            "priority": incident.priority.value,
            "tactics": list(incident.tactics),
            "techniques": list(incident.technique_ids),
            "hosts_involved": list(incident.hosts_involved),
            "events": [
                {
                    "time": a.timestamp.isoformat(),
                    "level": a.rule_level,
                    "rule": a.rule_id,
                    "description": a.description,
                    "image": a.image,
                    "user": a.user,
                    "dest_ip": a.dest_ip,
                }
                for a in incident.alerts
            ],
        }
        return (
            "You are a senior SOC analyst. Given the following structured "
            "security incident (already correlated and scored by an automated "
            "system), write a concise, factual investigation summary for a Tier-1 "
            "analyst. State the likely attacker objective, the kill-chain stage, "
            "and the top three recommended verification steps. Do NOT invent "
            "details beyond the data. Do NOT recommend deleting data.\n\n"
            f"INCIDENT DATA:\n{json.dumps(summary, indent=2)}\n"
        )

    def narrate(self, incident: Incident) -> str:
        prompt = self._build_prompt(incident)
        body = json.dumps(
            {"model": self._config.ollama_model, "prompt": prompt, "stream": False}
        ).encode("utf-8")
        url = f"{self._config.ollama_url.rstrip('/')}/api/generate"
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            llm_text = str(payload.get("response", "")).strip()
            if not llm_text:
                raise ValueError("empty LLM response")
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "Ollama narration failed (%s); falling back to template narrator", exc
            )
            return self._fallback.narrate(incident)

        # Always anchor LLM prose to the deterministic ground-truth facts.
        facts = self._fallback.narrate(incident)
        return f"{llm_text}\n\n--- Verified facts ---\n{facts}"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def build_narrator(config: NarrativeConfig) -> Narrator:
    """Instantiate the configured narrator."""
    if config.backend == "ollama":
        return OllamaNarrator(config)
    return TemplateNarrator()
