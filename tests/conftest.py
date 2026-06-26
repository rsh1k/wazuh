# SPDX-License-Identifier: GPL-2.0-only
"""Shared fixtures and helpers for the test suite.

The :func:`wazuh_alert` factory mints realistic Wazuh alert documents with
sensible defaults so individual tests only specify the fields they care about.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

BASE_TIME = datetime(2026, 6, 26, 9, 0, 0, tzinfo=timezone.utc)


def wazuh_alert(
    *,
    alert_id: str,
    offset_seconds: int = 0,
    rule_id: str = "1000",
    level: int = 5,
    description: str = "Test alert",
    agent_name: str = "WIN-HOST",
    agent_id: str = "001",
    agent_ip: str = "192.168.1.50",
    groups: Optional[list[str]] = None,
    mitre_ids: Optional[list[str]] = None,
    mitre_tactics: Optional[list[str]] = None,
    process_guid: Optional[str] = None,
    parent_process_guid: Optional[str] = None,
    image: Optional[str] = None,
    parent_image: Optional[str] = None,
    user: Optional[str] = None,
    dest_ip: Optional[str] = None,
    dest_port: Optional[str] = None,
    base_time: datetime = BASE_TIME,
) -> dict[str, Any]:
    """Return a Wazuh-shaped alert document for use in tests."""
    timestamp = (base_time + timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f%z"
    )
    # Wazuh writes offsets like +0000 (no colon); emulate that exactly.
    timestamp = timestamp[:-2] + timestamp[-2:]
    eventdata: dict[str, Any] = {}
    if process_guid:
        eventdata["processGuid"] = process_guid
    if parent_process_guid:
        eventdata["parentProcessGuid"] = parent_process_guid
    if image:
        eventdata["image"] = image
    if parent_image:
        eventdata["parentImage"] = parent_image
    if user:
        eventdata["user"] = user
    if dest_ip:
        eventdata["destinationIp"] = dest_ip
    if dest_port:
        eventdata["destinationPort"] = dest_port

    rule: dict[str, Any] = {
        "id": rule_id,
        "level": level,
        "description": description,
        "groups": groups or ["windows"],
    }
    if mitre_ids or mitre_tactics:
        rule["mitre"] = {
            "id": mitre_ids or [],
            "tactic": mitre_tactics or [],
            "technique": [],
        }

    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": rule,
        "agent": {"id": agent_id, "name": agent_name, "ip": agent_ip},
        "manager": {"name": "wazuh-server"},
        "data": {"win": {"system": {}, "eventdata": eventdata}},
        "location": "EventChannel",
    }


@pytest.fixture
def base_time() -> datetime:
    return BASE_TIME


@pytest.fixture
def reference_time() -> datetime:
    """A reference 'now' a few minutes after the fixture alerts."""
    return BASE_TIME + timedelta(minutes=10)


@pytest.fixture
def attack_chain() -> list[dict[str, Any]]:
    """A realistic multi-stage attack chain mirroring the fr3akk lab.

    Failed logins (credential access) -> suspicious PowerShell spawn
    (execution/discovery) -> outbound connection to another host (lateral
    movement / exfil). These are causally linked by process GUIDs and time.
    """
    powershell_guid = "{aaaa-1111}"
    cmd_guid = "{bbbb-2222}"
    return [
        wazuh_alert(
            alert_id="evt-1",
            offset_seconds=0,
            rule_id="60122",
            level=5,
            description="Logon failure - Unknown user or bad password",
            groups=["windows", "authentication_failed"],
            mitre_ids=["T1110"],
            mitre_tactics=["Credential Access"],
            user="Administrator",
        ),
        wazuh_alert(
            alert_id="evt-2",
            offset_seconds=30,
            rule_id="60122",
            level=5,
            description="Logon failure - Unknown user or bad password",
            groups=["windows", "authentication_failed"],
            mitre_ids=["T1110"],
            mitre_tactics=["Credential Access"],
            user="Administrator",
        ),
        wazuh_alert(
            alert_id="evt-3",
            offset_seconds=90,
            rule_id="92052",
            level=12,
            description="Suspicious PowerShell encoded command execution",
            groups=["windows", "sysmon"],
            mitre_ids=["T1059.001"],
            mitre_tactics=["Execution"],
            process_guid=powershell_guid,
            image="C:\\\\Windows\\\\System32\\\\powershell.exe",
            user="Administrator",
        ),
        wazuh_alert(
            alert_id="evt-4",
            offset_seconds=120,
            rule_id="92100",
            level=10,
            description="Process spawned for network discovery",
            groups=["windows", "sysmon"],
            mitre_ids=["T1046"],
            mitre_tactics=["Discovery"],
            process_guid=cmd_guid,
            parent_process_guid=powershell_guid,
            image="C:\\\\Windows\\\\System32\\\\cmd.exe",
            user="Administrator",
        ),
        wazuh_alert(
            alert_id="evt-5",
            offset_seconds=150,
            rule_id="92200",
            level=11,
            description="Outbound network connection to internal host",
            groups=["windows", "sysmon"],
            mitre_ids=["T1021"],
            mitre_tactics=["Lateral Movement"],
            process_guid=cmd_guid,
            image="C:\\\\Windows\\\\System32\\\\cmd.exe",
            user="Administrator",
            dest_ip="192.168.1.77",
            dest_port="445",
        ),
    ]
