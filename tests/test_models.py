# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.models`."""

from __future__ import annotations

from datetime import datetime, timezone

from wazuh_causal_triage.models import (
    Alert,
    Incident,
    Priority,
    ScoreFactor,
    alerts_time_bounds,
)
from conftest import wazuh_alert


def test_alert_from_wazuh_parses_core_fields() -> None:
    doc = wazuh_alert(
        alert_id="abc",
        rule_id="60122",
        level=7,
        description="Logon failure",
        mitre_ids=["T1110"],
        mitre_tactics=["Credential Access"],
        user="Administrator",
    )
    alert = Alert.from_wazuh(doc)
    assert alert.alert_id == "abc"
    assert alert.rule_id == "60122"
    assert alert.rule_level == 7
    assert alert.mitre_ids == ("T1110",)
    assert alert.mitre_tactics == ("Credential Access",)
    assert alert.user == "Administrator"
    assert alert.agent_name == "WIN-HOST"
    assert alert.timestamp.tzinfo is not None


def test_alert_from_wazuh_tolerates_missing_fields() -> None:
    # An almost-empty document must not raise.
    alert = Alert.from_wazuh({})
    assert alert.rule_level == 0
    assert alert.alert_id == ""
    assert alert.mitre_ids == ()
    assert alert.timestamp.tzinfo is not None


def test_alert_from_wazuh_coerces_string_level() -> None:
    doc = {"rule": {"id": "1", "level": "9"}}
    assert Alert.from_wazuh(doc).rule_level == 9
    # A non-numeric level degrades to 0 instead of raising.
    doc_bad = {"rule": {"id": "1", "level": "high"}}
    assert Alert.from_wazuh(doc_bad).rule_level == 0


def test_alert_process_and_network_fields() -> None:
    doc = wazuh_alert(
        alert_id="p1",
        process_guid="{guid-1}",
        parent_process_guid="{guid-0}",
        image="powershell.exe",
        dest_ip="10.0.0.9",
        dest_port="445",
    )
    alert = Alert.from_wazuh(doc)
    assert alert.process_guid == "{guid-1}"
    assert alert.parent_process_guid == "{guid-0}"
    assert alert.image == "powershell.exe"
    assert alert.dest_ip == "10.0.0.9"
    assert alert.dest_port == "445"


def test_alert_from_ecs_findings_shape() -> None:
    # A flatter, ECS/indexer-aligned document (provisional 5.0 "findings"
    # shape). The parser must map it via fallback field paths.
    doc = {
        "_id": "finding-1",
        "@timestamp": "2026-06-26T09:00:00Z",
        "rule": {"id": "92052", "level": 12, "description": "Suspicious PowerShell",
                 "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]}},
        "host": {"name": "WIN-HOST", "ip": "192.168.1.50"},
        "process": {
            "entity_id": "{guid-1}",
            "executable": "C:/Windows/System32/powershell.exe",
            "parent": {"entity_id": "{guid-0}"},
        },
        "user": {"name": "Administrator"},
        "destination": {"ip": "192.168.1.77", "port": 445},
    }
    alert = Alert.from_wazuh(doc)
    assert alert.alert_id == "finding-1"
    assert alert.rule_level == 12
    assert alert.agent_name == "WIN-HOST"          # from host.name
    assert alert.agent_ip == "192.168.1.50"        # from host.ip
    assert alert.process_guid == "{guid-1}"        # from process.entity_id
    assert alert.parent_process_guid == "{guid-0}"  # from process.parent.entity_id
    assert alert.image.endswith("powershell.exe")  # from process.executable
    assert alert.user == "Administrator"           # from user.name
    assert alert.dest_ip == "192.168.1.77"         # from destination.ip
    assert alert.dest_port == "445"                # coerced from int
    assert alert.mitre_tactics == ("Execution",)
    assert alert.timestamp.utcoffset().total_seconds() == 0


def test_alert_4x_shape_still_parses_after_fallbacks() -> None:
    # Regression guard: the classic 4.x nested shape must keep working.
    doc = wazuh_alert(
        alert_id="evt-1", level=10, agent_name="WIN-HOST",
        process_guid="{P}", image="powershell.exe", user="Administrator",
        dest_ip="10.0.0.9", dest_port="445",
    )
    alert = Alert.from_wazuh(doc)
    assert alert.agent_name == "WIN-HOST"
    assert alert.process_guid == "{P}"
    assert alert.dest_ip == "10.0.0.9"
    assert alert.dest_port == "445"
    alert = Alert.from_wazuh(wazuh_alert(alert_id="x"))
    payload = alert.to_dict()
    assert "raw" not in payload
    # timestamp serialized as ISO string
    datetime.fromisoformat(payload["timestamp"])


def test_priority_from_score_boundaries() -> None:
    assert Priority.from_score(95) is Priority.CRITICAL
    assert Priority.from_score(90) is Priority.CRITICAL
    assert Priority.from_score(89.99) is Priority.HIGH
    assert Priority.from_score(70) is Priority.HIGH
    assert Priority.from_score(45) is Priority.MEDIUM
    assert Priority.from_score(20) is Priority.LOW
    assert Priority.from_score(0) is Priority.INFO


def test_incident_serialization_round_trips_fields() -> None:
    alert = Alert.from_wazuh(wazuh_alert(alert_id="x", level=10))
    incident = Incident(
        incident_id="inc-1",
        host="WIN-HOST",
        alerts=[alert],
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
        score=72.5,
        priority=Priority.HIGH,
        tactics=("Execution",),
        technique_ids=("T1059",),
        hosts_involved=("WIN-HOST",),
        factors=[ScoreFactor("causal_chain", "1 alert", 72.5)],
        is_prioritized=True,
        narrative="hello",
    )
    payload = incident.to_dict()
    assert payload["incident_id"] == "inc-1"
    assert payload["score"] == 72.5
    assert payload["priority"] == "high"
    assert payload["alert_count"] == 1
    assert payload["factors"][0]["name"] == "causal_chain"
    assert payload["narrative"] == "hello"
    # to_json must be valid JSON
    import json

    json.loads(incident.to_json())


def test_alerts_time_bounds_empty_is_safe() -> None:
    first, last = alerts_time_bounds([])
    assert isinstance(first, datetime) and isinstance(last, datetime)


def test_timestamp_parsing_variants() -> None:
    # Z suffix
    a = Alert.from_wazuh({"timestamp": "2026-06-26T09:00:00Z", "rule": {"level": 1}})
    assert a.timestamp == datetime(2026, 6, 26, 9, 0, 0, tzinfo=timezone.utc)
    # Offset without colon
    b = Alert.from_wazuh({"timestamp": "2026-06-26T09:00:00+0000", "rule": {"level": 1}})
    assert b.timestamp.utcoffset().total_seconds() == 0
    # Garbage timestamp falls back to a tz-aware now (does not raise)
    c = Alert.from_wazuh({"timestamp": "not-a-time", "rule": {"level": 1}})
    assert c.timestamp.tzinfo is not None
