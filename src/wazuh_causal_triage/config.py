# SPDX-License-Identifier: GPL-2.0-only
"""Configuration loading and validation.

Configuration is expressed as nested dataclasses with defaults that make the
module runnable with an empty config. A YAML file (or a plain dict) overrides
any subset of those defaults. Validation raises :class:`ConfigError` with a
precise, actionable message rather than letting a bad value surface as an
obscure failure deep in the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Optional, get_type_hints

try:  # PyYAML is a hard dependency, but we degrade to a clear error if absent.
    import yaml
except ImportError as exc:  # pragma: no cover - exercised only without PyYAML
    yaml = None  # type: ignore[assignment]
    _YAML_IMPORT_ERROR: Optional[ImportError] = exc
else:
    _YAML_IMPORT_ERROR = None


class ConfigError(ValueError):
    """Raised when configuration is structurally or semantically invalid."""


# ---------------------------------------------------------------------------
# Sub-configurations
# ---------------------------------------------------------------------------
@dataclass
class FileSourceConfig:
    """Settings for reading alerts from a Wazuh ``alerts.json`` file."""

    path: str = "/var/ossec/logs/alerts/alerts.json"


@dataclass
class OpenSearchSourceConfig:
    """Settings for reading alerts/findings from the Wazuh indexer (OpenSearch).

    This is the forward-looking source: in Wazuh 5.0, alerts (renamed
    "findings") live exclusively on the indexer side, so indexer retrieval is
    the path that survives the upgrade.
    """

    url: str = "https://localhost:9200"
    # 4.x alerts use ``wazuh-alerts-*``. For 5.0 findings, set this to the
    # findings index pattern once it is published (e.g. ``wazuh-findings-*``).
    index_pattern: str = "wazuh-alerts-*"
    username: str = "admin"
    password: str = ""
    # The timestamp field used for range filtering and sort. 4.x uses
    # ``timestamp``; ECS/5.0 documents may use ``@timestamp``.
    timestamp_field: str = "timestamp"
    verify_certs: bool = False
    # Path to a CA bundle for TLS verification in production. When set and
    # ``verify_certs`` is true, the indexer's certificate is validated against
    # it; strongly recommended over disabling verification.
    ca_cert_path: Optional[str] = None
    timeout_seconds: float = 30.0
    # Pagination: results are pulled in pages via ``search_after`` so runs are
    # not limited to a single 10k OpenSearch page.
    page_size: int = 1000
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0


@dataclass
class IngestConfig:
    """Which alert source to use and its parameters.

    ``source`` selects the backend: ``"opensearch"`` (default; reads the Wazuh
    indexer and is the path forward for 5.0 findings) or ``"file"`` (reads a
    local ``alerts.json``; dependency-free and fully offline-testable, suited to
    4.x and to development).

    ``schema`` selects how documents are interpreted: ``"auto"`` (default; the
    parser probes both 4.x and ECS/findings field locations), ``"alerts"``
    (4.x), or ``"findings"`` (5.0). In practice ``"auto"`` handles both because
    field lookups are additive fallbacks.
    """

    source: str = "opensearch"
    schema: str = "auto"
    lookback_minutes: int = 60
    max_alerts: int = 50_000
    file: FileSourceConfig = field(default_factory=FileSourceConfig)
    opensearch: OpenSearchSourceConfig = field(default_factory=OpenSearchSourceConfig)


@dataclass
class GraphConfig:
    """Provenance-graph construction parameters."""

    # Two alerts on the same host are eligible to join the same incident only
    # if they fall within this temporal window of an existing member.
    correlation_window_seconds: int = 1800
    # Alerts at or below this Wazuh rule level are treated as pure context and
    # never *seed* an incident on their own (they can still join one).
    min_seed_level: int = 3


@dataclass
class ScoringConfig:
    """Causal scoring-model parameters.

    The model is built on the documented principle that the probability of
    independent benign events jointly forming a malicious-looking causal chain
    decays multiplicatively with chain length. See :mod:`scoring` for detail.
    """

    # Clamp for per-alert benign probability, keeping any single alert from
    # dominating (floor) or being dismissed entirely (ceil).
    benign_prob_floor: float = 0.05
    benign_prob_ceil: float = 0.98
    # Bonus (points, pre-normalization) per distinct ATT&CK tactic observed —
    # kill-chain progression is a strong, well-established signal.
    tactic_diversity_weight: float = 6.0
    # Bonus per additional host touched (lateral movement indicator).
    lateral_movement_weight: float = 8.0
    # Adaptive threshold: an incident is prioritized when its score exceeds
    # ``mean + k * stddev`` of the recent score baseline, subject to a floor.
    adaptive_k: float = 2.0
    absolute_floor: float = 45.0
    # Exponential weighting for the running baseline (0 < alpha <= 1); larger
    # adapts faster to recent conditions.
    baseline_alpha: float = 0.05
    baseline_state_path: Optional[str] = None


@dataclass
class NarrativeConfig:
    """Narrative-generation settings (advisory, local-first)."""

    backend: str = "template"  # "template" | "ollama"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    timeout_seconds: float = 60.0
    # Only spend LLM time on incidents that cleared the adaptive threshold.
    only_prioritized: bool = True


@dataclass
class OutputConfig:
    """Where triage verdicts are written."""

    # JSON array of all scored incidents (audit trail).
    json_path: Optional[str] = "triage_incidents.json"
    # Newline-delimited JSON of *prioritized* incidents, suitable for a Wazuh
    # logcollector to re-ingest as enriched alerts. Never overwrites source
    # data; this is an additive feedback channel.
    wazuh_feedback_path: Optional[str] = None
    stdout: bool = True


@dataclass
class AppConfig:
    """Top-level application configuration."""

    ingest: IngestConfig = field(default_factory=IngestConfig)
    graph: GraphConfig = field(default_factory=GraphConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    narrative: NarrativeConfig = field(default_factory=NarrativeConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> "AppConfig":
        """Build a config from a (possibly partial, possibly None) dict."""
        config = _build_dataclass(cls, data or {})
        config.validate()
        return config

    @classmethod
    def from_yaml(cls, path: str) -> "AppConfig":
        """Load and validate configuration from a YAML file."""
        if yaml is None:  # pragma: no cover
            raise ConfigError(
                "PyYAML is required to load YAML configuration files "
                f"but could not be imported: {_YAML_IMPORT_ERROR}"
            )
        try:
            with open(path, "r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
        except FileNotFoundError as exc:
            raise ConfigError(f"Configuration file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigError(
                f"Top-level YAML in {path} must be a mapping, got {type(loaded).__name__}"
            )
        return cls.from_dict(loaded)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate(self) -> None:
        """Raise :class:`ConfigError` on any semantically invalid value."""
        if self.ingest.source not in ("file", "opensearch"):
            raise ConfigError(
                f"ingest.source must be 'file' or 'opensearch', got {self.ingest.source!r}"
            )
        if self.ingest.schema not in ("auto", "alerts", "findings"):
            raise ConfigError(
                f"ingest.schema must be 'auto', 'alerts', or 'findings', got {self.ingest.schema!r}"
            )
        if self.ingest.opensearch.page_size <= 0:
            raise ConfigError("ingest.opensearch.page_size must be a positive integer")
        if self.ingest.opensearch.max_retries < 0:
            raise ConfigError("ingest.opensearch.max_retries must be non-negative")
        if self.ingest.lookback_minutes <= 0:
            raise ConfigError("ingest.lookback_minutes must be a positive integer")
        if self.ingest.max_alerts <= 0:
            raise ConfigError("ingest.max_alerts must be a positive integer")
        if self.graph.correlation_window_seconds <= 0:
            raise ConfigError("graph.correlation_window_seconds must be positive")
        if not (0.0 <= self.scoring.benign_prob_floor < self.scoring.benign_prob_ceil <= 1.0):
            raise ConfigError(
                "scoring requires 0 <= benign_prob_floor < benign_prob_ceil <= 1"
            )
        if not (0.0 < self.scoring.baseline_alpha <= 1.0):
            raise ConfigError("scoring.baseline_alpha must be in (0, 1]")
        if self.scoring.adaptive_k < 0:
            raise ConfigError("scoring.adaptive_k must be non-negative")
        if self.narrative.backend not in ("template", "ollama"):
            raise ConfigError(
                f"narrative.backend must be 'template' or 'ollama', got {self.narrative.backend!r}"
            )
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            raise ConfigError(
                f"log_level must be one of {sorted(valid_levels)}, got {self.log_level!r}"
            )


# ---------------------------------------------------------------------------
# Generic recursive dataclass builder
# ---------------------------------------------------------------------------
def _build_dataclass(cls: type, data: dict[str, Any]) -> Any:
    """Recursively instantiate dataclass ``cls`` from ``data``.

    Unknown keys are rejected with a clear error (typo protection); nested
    dataclasses are built recursively. Only mappings are accepted where a
    nested dataclass is expected.
    """
    if not isinstance(data, dict):
        raise ConfigError(
            f"Expected a mapping for {cls.__name__}, got {type(data).__name__}"
        )

    field_map = {f.name: f for f in fields(cls)}
    # With ``from __future__ import annotations`` in effect, ``field.type`` is a
    # string. Resolve the real types once so nested dataclasses are recognized.
    resolved_types = get_type_hints(cls)
    unknown = set(data) - set(field_map)
    if unknown:
        raise ConfigError(
            f"Unknown configuration key(s) for {cls.__name__}: {sorted(unknown)}"
        )

    kwargs: dict[str, Any] = {}
    for name in field_map:
        if name not in data:
            continue
        value = data[name]
        field_type = resolved_types.get(name)
        if isinstance(field_type, type) and is_dataclass(field_type):
            kwargs[name] = _build_dataclass(field_type, value)
        else:
            kwargs[name] = value
    return cls(**kwargs)
