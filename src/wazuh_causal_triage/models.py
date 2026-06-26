# SPDX-License-Identifier: GPL-2.0-only
"""Typed, immutable-friendly data models used across the module.

These models form the stable contract between the ingestion, graph, scoring,
narrative, and output layers. Keeping them dependency-free (standard library
``dataclasses`` only) makes them trivial to construct in tests and serialize
to JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Priority(str, Enum):
    """Incident priority tiers, ordered from least to most urgent.

    Inheriting from ``str`` makes the enum JSON-serializable out of the box and
    comparable against plain strings, which is convenient in configuration.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Priority":
        """Map a 0-100 incident score onto a coarse priority tier.

        The thresholds are deliberately conservative; the *adaptive* threshold
        in the scorer decides what actually gets surfaced. This mapping is only
        a human-friendly label.
        """
        if score >= 90.0:
            return cls.CRITICAL
        if score >= 70.0:
            return cls.HIGH
        if score >= 45.0:
            return cls.MEDIUM
        if score >= 20.0:
            return cls.LOW
        return cls.INFO


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_timestamp(raw: str) -> datetime:
    """Parse a Wazuh timestamp into a timezone-aware ``datetime``.

    Wazuh emits ISO-8601 timestamps such as ``2026-06-26T09:28:09.123+0000``.
    Python's ``fromisoformat`` accepts ``+00:00`` but historically not
    ``+0000``; we normalize the few known variants and fall back to "now (UTC)"
    rather than raising, because a single malformed timestamp must never crash
    a triage pipeline processing thousands of alerts.
    """
    if not raw:
        return datetime.now(timezone.utc)

    candidate = raw.strip()
    # Normalize a trailing "Z" and offsets written without a colon.
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    elif len(candidate) >= 5 and candidate[-5] in "+-" and candidate[-3] != ":":
        candidate = candidate[:-2] + ":" + candidate[-2:]

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Alert:
    """A normalized view over a single Wazuh alert.

    Only the fields the triage engine actually reasons about are promoted to
    first-class attributes; the untouched original document is retained in
    :attr:`raw` so nothing is lost for downstream consumers or audit.
    """

    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    description: str
    agent_id: str
    agent_name: str
    agent_ip: str
    groups: tuple[str, ...] = ()
    mitre_ids: tuple[str, ...] = ()
    mitre_tactics: tuple[str, ...] = ()
    # Process-provenance fields (populated for Sysmon-style events).
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    image: Optional[str] = None
    parent_image: Optional[str] = None
    user: Optional[str] = None
    # Network fields (populated for network-connection events).
    dest_ip: Optional[str] = None
    dest_port: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @staticmethod
    def from_wazuh(doc: dict[str, Any]) -> "Alert":
        """Build an :class:`Alert` from a raw Wazuh alert document.

        The method is defensive by construction: every lookup tolerates missing
        keys, because real-world alert streams are heterogeneous and partial
        documents must not abort ingestion.
        """
        rule = doc.get("rule") or {}
        agent = doc.get("agent") or {}
        data = doc.get("data") or {}
        win = data.get("win") or {}
        eventdata = win.get("eventdata") or {}

        mitre = rule.get("mitre") or {}

        def _as_tuple(value: Any) -> tuple[str, ...]:
            if value is None:
                return ()
            if isinstance(value, (list, tuple)):
                return tuple(str(v) for v in value)
            return (str(value),)

        # Rule level is occasionally delivered as a string; coerce safely.
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0

        return Alert(
            alert_id=str(doc.get("id") or doc.get("_id") or ""),
            timestamp=_parse_timestamp(str(doc.get("timestamp", ""))),
            rule_id=str(rule.get("id", "")),
            rule_level=level,
            description=str(rule.get("description", "")),
            agent_id=str(agent.get("id", "")),
            agent_name=str(agent.get("name", "")),
            agent_ip=str(agent.get("ip", "")),
            groups=_as_tuple(rule.get("groups")),
            mitre_ids=_as_tuple(mitre.get("id")),
            mitre_tactics=_as_tuple(mitre.get("tactic")),
            process_guid=(eventdata.get("processGuid") or None),
            parent_process_guid=(eventdata.get("parentProcessGuid") or None),
            image=(eventdata.get("image") or None),
            parent_image=(eventdata.get("parentImage") or None),
            user=(eventdata.get("user") or eventdata.get("targetUserName") or None),
            dest_ip=(eventdata.get("destinationIp") or None),
            dest_port=(eventdata.get("destinationPort") or None),
            raw=doc,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict (drops the bulky raw document)."""
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        payload.pop("raw", None)
        return payload


# ---------------------------------------------------------------------------
# Scoring breakdown
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScoreFactor:
    """A single, named contribution to an incident score, for explainability."""

    name: str
    detail: str
    contribution: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
@dataclass
class Incident:
    """A causally connected cluster of alerts on one host within a time window.

    An incident is the unit of triage. Its :attr:`score` reflects how unlikely
    the *whole chain* is to be benign noise, which is far more informative than
    any single alert's severity.
    """

    incident_id: str
    host: str
    alerts: list[Alert]
    first_seen: datetime
    last_seen: datetime
    score: float = 0.0
    priority: Priority = Priority.INFO
    tactics: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    hosts_involved: tuple[str, ...] = ()
    factors: list[ScoreFactor] = field(default_factory=list)
    is_prioritized: bool = False
    narrative: str = ""

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def max_rule_level(self) -> int:
        return max((a.rule_level for a in self.alerts), default=0)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the incident, including its full score breakdown."""
        return {
            "incident_id": self.incident_id,
            "host": self.host,
            "score": round(self.score, 2),
            "priority": self.priority.value,
            "is_prioritized": self.is_prioritized,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "alert_count": self.alert_count,
            "max_rule_level": self.max_rule_level,
            "tactics": list(self.tactics),
            "technique_ids": list(self.technique_ids),
            "hosts_involved": list(self.hosts_involved),
            "factors": [f.to_dict() for f in self.factors],
            "narrative": self.narrative,
            "alerts": [a.to_dict() for a in self.alerts],
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def alerts_time_bounds(alerts: Iterable[Alert]) -> tuple[datetime, datetime]:
    """Return the (earliest, latest) timestamps across ``alerts``.

    Falls back to "now" for both bounds when the iterable is empty, which keeps
    callers free of edge-case handling.
    """
    times = [a.timestamp for a in alerts]
    if not times:
        now = datetime.now(timezone.utc)
        return now, now
    return min(times), max(times)
