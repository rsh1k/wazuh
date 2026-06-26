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
    body = source._build_query_body()
    request = source._build_request(body)  # internal, but valuable to verify
    assert request.full_url == "https://indexer:9200/wazuh-alerts-*/_search"
    assert request.get_header("Authorization").startswith("Basic ")
    assert "range" in body["query"]
    assert body["sort"][0]["timestamp"]["order"] == "asc"


def test_build_source_factory_selects_backend() -> None:
    file_cfg = IngestConfig(source="file")
    assert isinstance(build_source(file_cfg), FileAlertSource)
    os_cfg = IngestConfig(source="opensearch")
    assert isinstance(build_source(os_cfg), OpenSearchAlertSource)


# ---------------------------------------------------------------------------
# OpenSearch fetch: pagination and retry (offline, via a fake urlopen)
# ---------------------------------------------------------------------------
import json as _json
import urllib.error
import urllib.request
from contextlib import contextmanager


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._body = _json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _hit(doc_id: str, offset: int):
    return {
        "_id": doc_id,
        "_source": wazuh_alert(alert_id=doc_id, offset_seconds=offset, level=10),
        "sort": [offset, doc_id],
    }


def test_opensearch_pagination_via_search_after(monkeypatch) -> None:
    # page_size=2: first page returns 2 hits, second returns 1, then stop.
    pages = [
        {"hits": {"hits": [_hit("a", 0), _hit("b", 1)]}},
        {"hits": {"hits": [_hit("c", 2)]}},
    ]
    calls = {"n": 0}

    def fake_urlopen(request, timeout=None, context=None):
        body = _json.loads(request.data.decode("utf-8"))
        # First call has no search_after; subsequent calls do.
        idx = 0 if "search_after" not in body else 1
        calls["n"] += 1
        return _FakeResponse(pages[idx])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    cfg = IngestConfig(source="opensearch")
    cfg.opensearch.page_size = 2
    source = OpenSearchAlertSource(cfg, reference_time=BASE_TIME + timedelta(minutes=10))
    alerts = source.fetch()
    assert [a.alert_id for a in alerts] == ["a", "b", "c"]
    assert calls["n"] == 2  # exactly two pages fetched


def test_opensearch_retries_then_succeeds(monkeypatch) -> None:
    attempts = {"n": 0}

    def flaky_urlopen(request, timeout=None, context=None):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise urllib.error.URLError("connection refused")
        return _FakeResponse({"hits": {"hits": [_hit("a", 0)]}})

    monkeypatch.setattr(urllib.request, "urlopen", flaky_urlopen)
    cfg = IngestConfig(source="opensearch")
    cfg.opensearch.max_retries = 2
    cfg.opensearch.retry_backoff_seconds = 0.0  # no real delay in tests
    cfg.opensearch.page_size = 10
    source = OpenSearchAlertSource(cfg, reference_time=BASE_TIME + timedelta(minutes=10))
    alerts = source.fetch()
    assert [a.alert_id for a in alerts] == ["a"]
    assert attempts["n"] == 2  # failed once, succeeded on retry


def test_opensearch_4xx_is_not_retried(monkeypatch) -> None:
    attempts = {"n": 0}

    def auth_fail(request, timeout=None, context=None):
        attempts["n"] += 1
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", auth_fail)
    cfg = IngestConfig(source="opensearch")
    cfg.opensearch.max_retries = 3
    source = OpenSearchAlertSource(cfg, reference_time=BASE_TIME)
    with pytest.raises(IngestError, match="HTTP 401"):
        source.fetch()
    assert attempts["n"] == 1  # 4xx fails fast, no retries


def test_opensearch_unreachable_raises_after_retries(monkeypatch) -> None:
    def always_fail(request, timeout=None, context=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", always_fail)
    cfg = IngestConfig(source="opensearch")
    cfg.opensearch.max_retries = 1
    cfg.opensearch.retry_backoff_seconds = 0.0
    source = OpenSearchAlertSource(cfg, reference_time=BASE_TIME)
    with pytest.raises(IngestError, match="Cannot reach indexer"):
        source.fetch()


def test_opensearch_query_uses_configured_timestamp_field() -> None:
    cfg = IngestConfig(source="opensearch")
    cfg.opensearch.timestamp_field = "@timestamp"
    source = OpenSearchAlertSource(cfg, reference_time=BASE_TIME)
    body = source._build_query_body()
    assert "@timestamp" in body["query"]["range"]
    assert body["sort"][0] == {"@timestamp": {"order": "asc"}}
