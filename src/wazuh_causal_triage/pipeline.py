# SPDX-License-Identifier: GPL-2.0-only
"""Pipeline orchestration.

:class:`TriagePipeline` wires the stages together: ingest -> build incidents ->
score -> narrate (prioritized only, by default) -> output. It is the single
public entry point and is intentionally small and dependency-injectable so it
can be driven from the CLI, a scheduler, or a test.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .config import AppConfig
from .graph import ProvenanceGraphBuilder
from .ingest import AlertSource, build_source
from .models import Incident
from .narrative import Narrator, build_narrator
from .output import OutputWriter
from .scoring import CausalScorer

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Summary of a single pipeline run."""

    alerts_ingested: int
    incidents_total: int
    incidents_prioritized: int
    incidents: list[Incident]


class TriagePipeline:
    """End-to-end causal-triage pipeline."""

    def __init__(
        self,
        config: AppConfig,
        *,
        source: Optional[AlertSource] = None,
        builder: Optional[ProvenanceGraphBuilder] = None,
        scorer: Optional[CausalScorer] = None,
        narrator: Optional[Narrator] = None,
        writer: Optional[OutputWriter] = None,
        reference_time: Optional[datetime] = None,
    ) -> None:
        """Construct a pipeline.

        Every collaborator is injectable; when omitted, a default is built from
        ``config``. This makes the pipeline trivially unit-testable with fakes
        while keeping production construction a one-liner.
        """
        self._config = config
        self._source = source or build_source(config.ingest, reference_time)
        self._builder = builder or ProvenanceGraphBuilder(config.graph)
        self._scorer = scorer or CausalScorer(config.scoring)
        self._narrator = narrator or build_narrator(config.narrative)
        self._writer = writer or OutputWriter(config.output)

    def run(self) -> TriageResult:
        """Execute one full triage cycle and return a summary."""
        alerts = self._source.fetch()
        incidents = self._builder.build_incidents(alerts)
        incidents = self._scorer.score_incidents(incidents)

        only_prioritized = self._config.narrative.only_prioritized
        for incident in incidents:
            if only_prioritized and not incident.is_prioritized:
                continue
            incident.narrative = self._narrator.narrate(incident)

        self._writer.write(incidents)

        prioritized = sum(1 for i in incidents if i.is_prioritized)
        result = TriageResult(
            alerts_ingested=len(alerts),
            incidents_total=len(incidents),
            incidents_prioritized=prioritized,
            incidents=incidents,
        )
        logger.info(
            "Triage run complete: %d alerts -> %d incidents (%d prioritized)",
            result.alerts_ingested,
            result.incidents_total,
            result.incidents_prioritized,
        )
        return result
