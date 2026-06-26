# SPDX-License-Identifier: GPL-2.0-only
"""Tests for output, pipeline orchestration, and the CLI."""

from __future__ import annotations

import json
from datetime import timedelta

from wazuh_causal_triage.cli import build_parser, main
from wazuh_causal_triage.config import AppConfig, OutputConfig
from wazuh_causal_triage.graph import ProvenanceGraphBuilder
from wazuh_causal_triage.models import Alert
from wazuh_causal_triage.output import OutputWriter
from wazuh_causal_triage.pipeline import TriagePipeline
from wazuh_causal_triage.scoring import CausalScorer
from wazuh_causal_triage.config import GraphConfig, ScoringConfig
from conftest import BASE_TIME, wazuh_alert


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------
def _scored(attack_chain):
    builder = ProvenanceGraphBuilder(GraphConfig(correlation_window_seconds=1800))
    incidents = builder.build_incidents([Alert.from_wazuh(d) for d in attack_chain])
    CausalScorer(ScoringConfig()).score_incidents(incidents)
    return incidents


def test_output_writes_json_array(tmp_path, attack_chain) -> None:
    incidents = _scored(attack_chain)
    json_path = tmp_path / "out.json"
    writer = OutputWriter(OutputConfig(json_path=str(json_path), stdout=False,
                                       wazuh_feedback_path=None))
    writer.write(incidents)
    data = json.loads(json_path.read_text())
    assert isinstance(data, list) and len(data) == 1
    assert data[0]["alert_count"] == 5


def test_output_wazuh_feedback_only_prioritized(tmp_path, attack_chain) -> None:
    incidents = _scored(attack_chain)
    feedback = tmp_path / "feedback.json"
    writer = OutputWriter(OutputConfig(json_path=None, stdout=False,
                                       wazuh_feedback_path=str(feedback)))
    writer.write(incidents)
    # The attack chain is prioritized, so one NDJSON line is written.
    lines = [ln for ln in feedback.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["integration"] == "causal-triage"
    assert event["priority"] in {"high", "critical"}


def test_output_stdout_runs_without_error(capsys, attack_chain) -> None:
    incidents = _scored(attack_chain)
    writer = OutputWriter(OutputConfig(json_path=None, stdout=True,
                                       wazuh_feedback_path=None))
    writer.write(incidents)
    captured = capsys.readouterr().out
    assert "Causal Triage" in captured


# ---------------------------------------------------------------------------
# Pipeline end-to-end
# ---------------------------------------------------------------------------
def _write_alerts(path, docs) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for doc in docs:
            handle.write(json.dumps(doc) + "\n")


def test_pipeline_end_to_end(tmp_path, attack_chain) -> None:
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(alerts_file, attack_chain)
    json_out = tmp_path / "incidents.json"

    config = AppConfig.from_dict(
        {
            "ingest": {"source": "file", "lookback_minutes": 600,
                       "file": {"path": str(alerts_file)}},
            "graph": {"correlation_window_seconds": 1800},
            "narrative": {"backend": "template"},
            "output": {"json_path": str(json_out), "stdout": False,
                       "wazuh_feedback_path": None},
        }
    )
    pipeline = TriagePipeline(config, reference_time=BASE_TIME + timedelta(minutes=10))
    result = pipeline.run()

    assert result.alerts_ingested == 5
    assert result.incidents_total == 1
    assert result.incidents_prioritized == 1
    inc = result.incidents[0]
    assert inc.narrative  # prioritized incidents get a narrative
    assert json_out.exists()


def test_pipeline_no_alerts_is_clean(tmp_path) -> None:
    alerts_file = tmp_path / "empty.json"
    alerts_file.write_text("", encoding="utf-8")
    config = AppConfig.from_dict(
        {
            "ingest": {"source": "file", "file": {"path": str(alerts_file)}},
            "output": {"json_path": None, "stdout": False, "wazuh_feedback_path": None},
        }
    )
    pipeline = TriagePipeline(config, reference_time=BASE_TIME)
    result = pipeline.run()
    assert result.alerts_ingested == 0
    assert result.incidents_total == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def test_cli_parser_requires_command() -> None:
    parser = build_parser()
    # argparse exits (SystemExit) when no subcommand is supplied.
    try:
        parser.parse_args([])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit")


def test_cli_run_on_file(tmp_path, attack_chain, monkeypatch) -> None:
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(alerts_file, attack_chain)
    json_out = tmp_path / "out.json"
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        "\n".join(
            [
                "ingest:",
                "  source: file",
                "  lookback_minutes: 99999999",
                f"  file: {{path: {alerts_file}}}",
                "output:",
                f"  json_path: {json_out}",
                "  stdout: false",
                "  wazuh_feedback_path: null",
            ]
        ),
        encoding="utf-8",
    )
    exit_code = main(["run", "--config", str(cfg_file), "--no-stdout"])
    assert exit_code == 0
    assert json_out.exists()


def test_cli_missing_alert_file_returns_error_code(tmp_path) -> None:
    missing = tmp_path / "nope.json"
    exit_code = main(["run", "--alerts", str(missing), "--no-stdout"])
    # IngestError is mapped to exit code 3.
    assert exit_code == 3


def test_cli_bad_config_returns_error_code(tmp_path) -> None:
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text("log_level: NONSENSE\n", encoding="utf-8")
    exit_code = main(["run", "--config", str(cfg_file)])
    assert exit_code == 2
