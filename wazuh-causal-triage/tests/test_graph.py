# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.graph`."""

from __future__ import annotations

from wazuh_causal_triage.config import GraphConfig
from wazuh_causal_triage.graph import ProvenanceGraphBuilder
from wazuh_causal_triage.models import Alert
from conftest import wazuh_alert


def _alerts(docs) -> list[Alert]:
    return [Alert.from_wazuh(d) for d in docs]


def test_empty_input_returns_no_incidents() -> None:
    builder = ProvenanceGraphBuilder(GraphConfig())
    assert builder.build_incidents([]) == []


def test_process_lineage_links_into_one_incident() -> None:
    # Parent powershell spawns child cmd; same incident via parent_child edge.
    docs = [
        wazuh_alert(alert_id="p", offset_seconds=0, level=10, process_guid="{P}",
                    image="powershell.exe"),
        wazuh_alert(alert_id="c", offset_seconds=5, level=10, process_guid="{C}",
                    parent_process_guid="{P}", image="cmd.exe"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=1))
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 1
    assert incidents[0].alert_count == 2


def test_temporal_proximity_links_same_user() -> None:
    docs = [
        wazuh_alert(alert_id="a", offset_seconds=0, level=8, user="alice"),
        wazuh_alert(alert_id="b", offset_seconds=60, level=8, user="alice"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=300))
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 1
    assert incidents[0].alert_count == 2


def test_temporal_window_splits_distant_alerts() -> None:
    docs = [
        wazuh_alert(alert_id="a", offset_seconds=0, level=8, user="alice"),
        wazuh_alert(alert_id="b", offset_seconds=10_000, level=8, user="alice"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=60))
    incidents = builder.build_incidents(_alerts(docs))
    # Two separate incidents because they exceed the correlation window.
    assert len(incidents) == 2


def test_different_users_not_temporally_linked() -> None:
    docs = [
        wazuh_alert(alert_id="a", offset_seconds=0, level=8, user="alice"),
        wazuh_alert(alert_id="b", offset_seconds=10, level=8, user="bob"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=300))
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 2


def test_noise_without_seed_is_not_an_incident() -> None:
    # All alerts at or below min_seed_level -> no incident.
    docs = [
        wazuh_alert(alert_id="n1", offset_seconds=0, level=2, user="alice"),
        wazuh_alert(alert_id="n2", offset_seconds=5, level=3, user="alice"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(min_seed_level=3))
    incidents = builder.build_incidents(_alerts(docs))
    assert incidents == []


def test_seed_pulls_in_adjacent_noise() -> None:
    docs = [
        wazuh_alert(alert_id="noise", offset_seconds=0, level=2, user="alice"),
        wazuh_alert(alert_id="seed", offset_seconds=10, level=10, user="alice"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(min_seed_level=3,
                                                 correlation_window_seconds=300))
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 1
    assert incidents[0].alert_count == 2


def test_incident_collects_tactics_and_lateral_hosts() -> None:
    docs = [
        wazuh_alert(alert_id="a", offset_seconds=0, level=10, user="alice",
                    mitre_tactics=["Execution"], process_guid="{P}"),
        wazuh_alert(alert_id="b", offset_seconds=5, level=10, user="alice",
                    mitre_tactics=["Lateral Movement"], process_guid="{P}",
                    dest_ip="10.0.0.99"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=60))
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 1
    inc = incidents[0]
    assert set(inc.tactics) == {"Execution", "Lateral Movement"}
    assert "10.0.0.99" in inc.hosts_involved
    assert len(inc.hosts_involved) == 2  # origin host + destination


def test_alerts_on_different_hosts_are_separate_incidents() -> None:
    docs = [
        wazuh_alert(alert_id="a", offset_seconds=0, level=10, agent_name="HOST-A"),
        wazuh_alert(alert_id="b", offset_seconds=5, level=10, agent_name="HOST-B"),
    ]
    builder = ProvenanceGraphBuilder(GraphConfig())
    incidents = builder.build_incidents(_alerts(docs))
    assert len(incidents) == 2
    assert {i.host for i in incidents} == {"HOST-A", "HOST-B"}


def test_full_attack_chain_is_one_incident(attack_chain) -> None:
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=1800))
    incidents = builder.build_incidents(_alerts(attack_chain))
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.alert_count == 5
    assert "Credential Access" in inc.tactics
    assert "Lateral Movement" in inc.tactics
    assert "192.168.1.77" in inc.hosts_involved


def test_incident_id_is_deterministic(attack_chain) -> None:
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=1800))
    first = builder.build_incidents(_alerts(attack_chain))[0].incident_id
    second = builder.build_incidents(_alerts(attack_chain))[0].incident_id
    assert first == second
