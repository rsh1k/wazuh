# SPDX-License-Identifier: GPL-2.0-only
"""Tests for :mod:`wazuh_causal_triage.config`."""

from __future__ import annotations

import textwrap

import pytest

from wazuh_causal_triage.config import AppConfig, ConfigError


def test_defaults_are_valid() -> None:
    config = AppConfig.from_dict({})
    assert config.ingest.source == "file"
    assert config.scoring.absolute_floor == 45.0
    assert config.narrative.backend == "template"
    config.validate()  # must not raise


def test_partial_override_merges_with_defaults() -> None:
    config = AppConfig.from_dict({"ingest": {"lookback_minutes": 120}})
    assert config.ingest.lookback_minutes == 120
    # untouched nested default remains
    assert config.ingest.file.path.endswith("alerts.json")


def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown configuration key"):
        AppConfig.from_dict({"bogus": 1})


def test_unknown_nested_key_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown configuration key"):
        AppConfig.from_dict({"scoring": {"not_a_field": 1}})


def test_invalid_source_rejected() -> None:
    with pytest.raises(ConfigError, match="ingest.source"):
        AppConfig.from_dict({"ingest": {"source": "carrier-pigeon"}})


def test_invalid_benign_prob_bounds_rejected() -> None:
    with pytest.raises(ConfigError, match="benign_prob"):
        AppConfig.from_dict({"scoring": {"benign_prob_floor": 0.9, "benign_prob_ceil": 0.5}})


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ConfigError, match="log_level"):
        AppConfig.from_dict({"log_level": "VERBOSE"})


def test_invalid_baseline_alpha_rejected() -> None:
    with pytest.raises(ConfigError, match="baseline_alpha"):
        AppConfig.from_dict({"scoring": {"baseline_alpha": 0.0}})


def test_nested_non_mapping_rejected() -> None:
    with pytest.raises(ConfigError, match="Expected a mapping"):
        AppConfig.from_dict({"ingest": "file"})


def test_from_yaml_loads_file(tmp_path) -> None:
    yaml_text = textwrap.dedent(
        """
        log_level: DEBUG
        ingest:
          source: file
          lookback_minutes: 15
        scoring:
          adaptive_k: 1.5
        """
    )
    path = tmp_path / "c.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    config = AppConfig.from_yaml(str(path))
    assert config.log_level == "DEBUG"
    assert config.ingest.lookback_minutes == 15
    assert config.scoring.adaptive_k == 1.5


def test_from_yaml_missing_file_raises_configerror() -> None:
    with pytest.raises(ConfigError, match="not found"):
        AppConfig.from_yaml("/no/such/file.yaml")


def test_from_yaml_non_mapping_top_level_rejected(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="must be a mapping"):
        AppConfig.from_yaml(str(path))
