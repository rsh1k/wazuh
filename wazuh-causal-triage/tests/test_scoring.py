# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.scoring`."""

from __future__ import annotations

import json

from wazuh_causal_triage.config import GraphConfig, ScoringConfig
from wazuh_causal_triage.graph import ProvenanceGraphBuilder
from wazuh_causal_triage.models import Alert
from wazuh_causal_triage.scoring import CausalScorer, _Baseline
from conftest import wazuh_alert


def _incident_from(docs, window=1800):
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=window))
    incidents = builder.build_incidents([Alert.from_wazuh(d) for d in docs])
    assert len(incidents) == 1
    return incidents[0]


def test_benign_probability_monotonic_in_level() -> None:
    scorer = CausalScorer(ScoringConfig())
    low = scorer._benign_probability(2)
    high = scorer._benign_probability(12)
    # Higher rule level => lower benign probability.
    assert low > high
    # Clamped within configured bounds.
    assert scorer._benign_probability(15) >= ScoringConfig().benign_prob_floor
    assert scorer._benign_probability(0) <= ScoringConfig().benign_prob_ceil


def test_longer_chain_scores_higher_than_single_alert() -> None:
    single = _incident_from([wazuh_alert(alert_id="s", level=6, user="u")])
    chain = _incident_from(
        [
            wazuh_alert(alert_id="c1", offset_seconds=0, level=6, user="u"),
            wazuh_alert(alert_id="c2", offset_seconds=10, level=6, user="u"),
            wazuh_alert(alert_id="c3", offset_seconds=20, level=6, user="u"),
        ]
    )
    scorer = CausalScorer(ScoringConfig())
    scorer.score_incidents([single])
    scorer2 = CausalScorer(ScoringConfig())
    scorer2.score_incidents([chain])
    # Multiplicative decay: a chain of equal-severity alerts scores higher.
    assert chain.score > single.score


def test_tactic_diversity_increases_score() -> None:
    no_progression = _incident_from(
        [
            wazuh_alert(alert_id="a", offset_seconds=0, level=8, user="u",
                        mitre_tactics=["Execution"], process_guid="{P}"),
            wazuh_alert(alert_id="b", offset_seconds=5, level=8, user="u",
                        mitre_tactics=["Execution"], process_guid="{P}"),
        ]
    )
    progression = _incident_from(
        [
            wazuh_alert(alert_id="a", offset_seconds=0, level=8, user="u",
                        mitre_tactics=["Execution"], process_guid="{P}"),
            wazuh_alert(alert_id="b", offset_seconds=5, level=8, user="u",
                        mitre_tactics=["Lateral Movement"], process_guid="{P}"),
        ]
    )
    s1 = CausalScorer(ScoringConfig())
    s1.score_incidents([no_progression])
    s2 = CausalScorer(ScoringConfig())
    s2.score_incidents([progression])
    assert progression.score > no_progression.score


def test_score_is_clamped_to_100(attack_chain) -> None:
    inc = _incident_from(attack_chain)
    scorer = CausalScorer(ScoringConfig())
    scorer.score_incidents([inc])
    assert 0.0 <= inc.score <= 100.0


def test_factors_present_and_explainable(attack_chain) -> None:
    inc = _incident_from(attack_chain)
    scorer = CausalScorer(ScoringConfig())
    scorer.score_incidents([inc])
    names = {f.name for f in inc.factors}
    assert "causal_chain" in names
    # The attack chain traverses multiple tactics and a remote host.
    assert "killchain_progression" in names
    assert "lateral_movement" in names


def test_absolute_floor_on_cold_start() -> None:
    # With no baseline history, only the absolute floor applies.
    weak = _incident_from([wazuh_alert(alert_id="w", level=4, user="u")])
    scorer = CausalScorer(ScoringConfig(absolute_floor=45.0))
    scorer.score_incidents([weak])
    # A single low-level alert should not be prioritized under the floor.
    assert weak.is_prioritized is False


def test_strong_incident_is_prioritized(attack_chain) -> None:
    inc = _incident_from(attack_chain)
    scorer = CausalScorer(ScoringConfig())
    scorer.score_incidents([inc])
    assert inc.is_prioritized is True


def test_baseline_persistence_round_trip(tmp_path, attack_chain) -> None:
    state = tmp_path / "baseline.json"
    cfg = ScoringConfig(baseline_state_path=str(state))
    scorer = CausalScorer(cfg)
    inc = _incident_from(attack_chain)
    scorer.score_incidents([inc])
    assert state.exists()
    # A fresh scorer loads the persisted baseline.
    saved = json.loads(state.read_text())
    assert saved["count"] >= 1
    scorer2 = CausalScorer(cfg)
    assert scorer2.baseline_mean == saved["mean"]


def test_corrupt_baseline_does_not_crash(tmp_path, attack_chain) -> None:
    state = tmp_path / "baseline.json"
    state.write_text("{ not valid json", encoding="utf-8")
    cfg = ScoringConfig(baseline_state_path=str(state))
    scorer = CausalScorer(cfg)  # must not raise
    assert scorer.baseline_mean == 0.0


def test_baseline_ewma_math() -> None:
    baseline = _Baseline()
    baseline.update(50.0, alpha=0.5)
    assert baseline.mean == 50.0  # first sample seeds mean
    assert baseline.variance == 0.0
    baseline.update(70.0, alpha=0.5)
    # mean moves halfway toward 70 -> 60
    assert abs(baseline.mean - 60.0) < 1e-9
    assert baseline.stddev > 0.0
