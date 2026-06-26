# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.narrative`."""

from __future__ import annotations

from wazuh_causal_triage.config import GraphConfig, NarrativeConfig, ScoringConfig
from wazuh_causal_triage.graph import ProvenanceGraphBuilder
from wazuh_causal_triage.models import Alert
from wazuh_causal_triage.narrative import (
    OllamaNarrator,
    TemplateNarrator,
    build_narrator,
)
from wazuh_causal_triage.scoring import CausalScorer
from conftest import wazuh_alert


def _scored_incident(attack_chain):
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=1800))
    inc = builder.build_incidents([Alert.from_wazuh(d) for d in attack_chain])[0]
    CausalScorer(ScoringConfig()).score_incidents([inc])
    return inc


def test_template_narrative_contains_key_facts(attack_chain) -> None:
    inc = _scored_incident(attack_chain)
    text = TemplateNarrator().narrate(inc)
    assert inc.incident_id in text
    assert "Event sequence:" in text
    assert "Scoring rationale:" in text
    # Tactics surfaced
    assert "Credential Access" in text
    # Advisory / non-destructive note present
    assert "no alerts have been suppressed" in text


def test_template_narrative_lists_all_events(attack_chain) -> None:
    inc = _scored_incident(attack_chain)
    text = TemplateNarrator().narrate(inc)
    for alert in inc.alerts:
        assert alert.rule_id in text


def test_build_narrator_defaults_to_template() -> None:
    assert isinstance(build_narrator(NarrativeConfig(backend="template")), TemplateNarrator)


def test_build_narrator_ollama_selected() -> None:
    assert isinstance(build_narrator(NarrativeConfig(backend="ollama")), OllamaNarrator)


def test_ollama_falls_back_when_unreachable(attack_chain) -> None:
    inc = _scored_incident(attack_chain)
    # Point at a closed port so the connection fails fast and we exercise the
    # graceful fallback path (no network dependency, deterministic).
    cfg = NarrativeConfig(
        backend="ollama",
        ollama_url="http://127.0.0.1:1",  # unlikely to be listening
        timeout_seconds=1.0,
    )
    narrator = OllamaNarrator(cfg)
    text = narrator.narrate(inc)
    # Fallback returns the template narrative, which always includes this line.
    assert "no alerts have been suppressed" in text
    assert inc.incident_id in text
