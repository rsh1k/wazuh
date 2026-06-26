# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.ingest`."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from wazuh_causal_triage.config import IngestConfig
from wazuh_causal_triage.ingest import (
    FileAlertSource,
    IngestError,
    OpenSearchAlertSource,
    build_source,
)
from conftest import BASE_TIME, wazuh_alert


def _write_alerts(path, docs) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for doc in docs:
            handle.write(json.dumps(doc) + "\n")


def test_file_source_reads_in_window(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(alerts_file, [wazuh_alert(alert_id="a", offset_seconds=0),
                                wazuh_alert(alert_id="b", offset_seconds=60)])
    config = IngestConfig(source="file", lookback_minutes=60)
    config.file.path = str(alerts_file)
    source = FileAlertSource(config, reference_time=BASE_TIME + timedelta(minutes=5))
    alerts = source.fetch()
    assert [a.alert_id for a in alerts] == ["a", "b"]


def test_file_source_filters_outside_lookback(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    # One alert two hours old, one recent.
    _write_alerts(
        alerts_file,
        [
            wazuh_alert(alert_id="old", offset_seconds=-7200),
            wazuh_alert(alert_id="new", offset_seconds=0),
        ],
    )
    config = IngestConfig(source="file", lookback_minutes=60)
    config.file.path = str(alerts_file)
    source = FileAlertSource(config, reference_time=BASE_TIME + timedelta(minutes=1))
    alerts = source.fetch()
    assert [a.alert_id for a in alerts] == ["new"]


def test_file_source_skips_malformed_lines(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    with open(alerts_file, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(wazuh_alert(alert_id="ok", offset_seconds=0)) + "\n")
        handle.write("{ this is not valid json\n")
        handle.write("\n")  # blank line
        handle.write("\"a string, not an object\"\n")
        handle.write(json.dumps(wazuh_alert(alert_id="ok2", offset_seconds=1)) + "\n")
    config = IngestConfig(source="file", lookback_minutes=60)
    config.file.path = str(alerts_file)
    source = FileAlertSource(config, reference_time=BASE_TIME + timedelta(minutes=1))
    alerts = source.fetch()
    assert sorted(a.alert_id for a in alerts) == ["ok", "ok2"]


def test_file_source_respects_max_alerts(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(
        alerts_file,
        [wazuh_alert(alert_id=f"a{i}", offset_seconds=i) for i in range(10)],
    )
    config = IngestConfig(source="file", lookback_minutes=600, max_alerts=3)
    config.file.path = str(alerts_file)
    source = FileAlertSource(config, reference_time=BASE_TIME + timedelta(minutes=30))
    alerts = source.fetch()
    assert len(alerts) == 3


def test_file_source_missing_file_raises_ingesterror(tmp_path) -> None:
    config = IngestConfig(source="file")
    config.file.path = str(tmp_path / "does-not-exist.json")
    source = FileAlertSource(config, reference_time=BASE_TIME)
    with pytest.raises(IngestError, match="not found"):
        source.fetch()


def test_file_source_returns_sorted_by_time(tmp_path) -> None:
    alerts_file = tmp_path / "alerts.json"
    # Write out of order; expect sorted ascending by timestamp.
    _write_alerts(
        alerts_file,
        [
            wazuh_alert(alert_id="late", offset_seconds=120),
            wazuh_alert(alert_id="early", offset_seconds=0),
        ],
    )
    config = IngestConfig(source="file", lookback_minutes=60)
    config.file.path = str(alerts_file)
    source = FileAlertSource(config, reference_time=BASE_TIME + timedelta(minutes=5))
    alerts = source.fetch()
    assert [a.alert_id for a in alerts] == ["early", "late"]


def test_opensearch_request_is_well_formed() -> None:
    config = IngestConfig(source="opensearch", lookback_minutes=30)
    config.opensearch.url = "https://indexer:9200"
    config.opensearch.username = "admin"
    config.opensearch.password = "secret"
    source = OpenSearchAlertSource(config, reference_time=BASE_TIME)
    request = source._build_request()  # internal, but valuable to verify
    assert request.full_url == "https://indexer:9200/wazuh-alerts-*/_search"
    assert request.get_header("Authorization").startswith("Basic ")
    body = json.loads(request.data.decode("utf-8"))
    assert "range" in body["query"]
    assert body["sort"][0]["timestamp"]["order"] == "asc"


def test_build_source_factory_selects_backend() -> None:
    file_cfg = IngestConfig(source="file")
    assert isinstance(build_source(file_cfg), FileAlertSource)
    os_cfg = IngestConfig(source="opensearch")
    assert isinstance(build_source(os_cfg), OpenSearchAlertSource)
