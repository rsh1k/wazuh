# SPDX-License-Identifier: GPL-2.0-only
"""Provenance-graph construction and incident extraction.

The builder turns a flat list of alerts into per-host *incidents*: clusters of
alerts linked either by shared process provenance (Sysmon process GUIDs) or by
temporal proximity on the same host/user. Each incident is a weakly-connected
component of the graph that contains at least one "seed" alert (an alert above
a configurable noise floor).

Why a graph
-----------
Treating every alert independently is exactly what produces alert fatigue. By
reconstructing the causal chain — process A spawned process B which opened a
connection to host C — we can later score the *chain*, whose joint probability
of being benign decays multiplicatively with its length. A graph is the natural
representation for that reasoning.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

import networkx as nx

from .config import GraphConfig
from .models import Alert, Incident, alerts_time_bounds

logger = logging.getLogger(__name__)


class ProvenanceGraphBuilder:
    """Build provenance graphs and extract incidents from alert batches."""

    def __init__(self, config: GraphConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def build_incidents(self, alerts: list[Alert]) -> list[Incident]:
        """Group ``alerts`` into scored-ready incidents.

        Alerts are partitioned by host first (an incident never spans hosts in
        construction; cross-host *movement* is detected later via destination
        IPs). Within a host, alerts are linked by process lineage and temporal
        proximity, then split into connected components.
        """
        if not alerts:
            return []

        by_host: dict[str, list[Alert]] = {}
        for alert in alerts:
            host = alert.agent_name or alert.agent_id or alert.agent_ip or "unknown"
            by_host.setdefault(host, []).append(alert)

        incidents: list[Incident] = []
        for host, host_alerts in by_host.items():
            incidents.extend(self._build_host_incidents(host, host_alerts))

        # Stable, deterministic ordering aids reproducible output and testing.
        incidents.sort(key=lambda inc: (inc.first_seen, inc.incident_id))
        logger.info("Extracted %d incident(s) from %d alert(s)", len(incidents), len(alerts))
        return incidents

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_host_incidents(self, host: str, alerts: list[Alert]) -> list[Incident]:
        """Construct incidents for a single host."""
        graph: nx.Graph = nx.Graph()
        # Each alert is a node, keyed by a unique synthetic id so that two
        # alerts sharing an alert_id (rare, but possible across reloads) do not
        # collide.
        node_ids: list[str] = []
        for index, alert in enumerate(alerts):
            node_id = f"{alert.alert_id or 'noid'}::{index}"
            graph.add_node(node_id, alert=alert)
            node_ids.append(node_id)

        self._link_by_process_lineage(graph, node_ids, alerts)
        self._link_by_temporal_proximity(graph, node_ids, alerts)

        incidents: list[Incident] = []
        for component in nx.connected_components(graph):
            component_alerts = [graph.nodes[n]["alert"] for n in component]
            if not self._component_has_seed(component_alerts):
                # Pure low-level noise with no seed alert is not an incident.
                continue
            incidents.append(self._materialize_incident(host, component_alerts))
        return incidents

    def _link_by_process_lineage(
        self, graph: nx.Graph, node_ids: list[str], alerts: list[Alert]
    ) -> None:
        """Connect alerts that belong to the same process tree.

        Two relationships are used: alerts sharing a ``processGuid`` describe the
        same process; an alert whose ``parentProcessGuid`` matches another
        alert's ``processGuid`` is its child. Both are strong causal links.
        """
        guid_to_nodes: dict[str, list[str]] = {}
        for node_id, alert in zip(node_ids, alerts):
            if alert.process_guid:
                guid_to_nodes.setdefault(alert.process_guid, []).append(node_id)

        # Same-process links.
        for nodes in guid_to_nodes.values():
            for first, second in zip(nodes, nodes[1:]):
                graph.add_edge(first, second, relation="same_process")

        # Parent-child links.
        for node_id, alert in zip(node_ids, alerts):
            parent = alert.parent_process_guid
            if parent and parent in guid_to_nodes:
                for parent_node in guid_to_nodes[parent]:
                    if parent_node != node_id:
                        graph.add_edge(parent_node, node_id, relation="parent_child")

    def _link_by_temporal_proximity(
        self, graph: nx.Graph, node_ids: list[str], alerts: list[Alert]
    ) -> None:
        """Connect alerts close in time on the same host/user.

        This captures causal stories that lack process-GUID linkage (e.g. an
        authentication failure followed by a successful logon). Alerts are
        linked when they share a user (or either lacks one) and fall within the
        configured correlation window. The list is processed in time order so
        only adjacent-in-time pairs need checking.
        """
        window = timedelta(seconds=self._config.correlation_window_seconds)
        indexed = sorted(zip(node_ids, alerts), key=lambda pair: pair[1].timestamp)
        for i, (node_i, alert_i) in enumerate(indexed):
            for node_j, alert_j in indexed[i + 1:]:
                if alert_j.timestamp - alert_i.timestamp > window:
                    break  # Sorted by time: no further alert can be in-window.
                if self._users_compatible(alert_i.user, alert_j.user):
                    graph.add_edge(node_i, node_j, relation="temporal")

    @staticmethod
    def _users_compatible(user_a: Optional[str], user_b: Optional[str]) -> bool:
        """Two alerts may be linked if they share a user or either is unknown."""
        if not user_a or not user_b:
            return True
        return user_a == user_b

    def _component_has_seed(self, alerts: list[Alert]) -> bool:
        """A component is a real incident only if it has at least one seed."""
        return any(a.rule_level > self._config.min_seed_level for a in alerts)

    def _materialize_incident(self, host: str, alerts: list[Alert]) -> Incident:
        """Build an :class:`Incident` from a connected component's alerts."""
        ordered = sorted(alerts, key=lambda a: a.timestamp)
        first_seen, last_seen = alerts_time_bounds(ordered)

        tactics: list[str] = []
        techniques: list[str] = []
        hosts: set[str] = {host}
        for alert in ordered:
            for tactic in alert.mitre_tactics:
                if tactic not in tactics:
                    tactics.append(tactic)
            for tech in alert.mitre_ids:
                if tech not in techniques:
                    techniques.append(tech)
            # A destination IP that differs from the source host is evidence of
            # potential lateral movement / egress.
            if alert.dest_ip:
                hosts.add(alert.dest_ip)

        incident_id = self._make_incident_id(host, ordered)
        return Incident(
            incident_id=incident_id,
            host=host,
            alerts=ordered,
            first_seen=first_seen,
            last_seen=last_seen,
            tactics=tuple(tactics),
            technique_ids=tuple(techniques),
            hosts_involved=tuple(sorted(hosts)),
        )

    @staticmethod
    def _make_incident_id(host: str, alerts: list[Alert]) -> str:
        """Deterministic, human-traceable incident id.

        Built from host plus the earliest alert's timestamp and id so the same
        batch always produces the same identifier (important for idempotent
        re-ingestion and for stable test assertions).
        """
        seed = alerts[0]
        stamp = seed.timestamp.strftime("%Y%m%dT%H%M%S")
        return f"inc-{host}-{stamp}-{seed.alert_id or 'noid'}"
