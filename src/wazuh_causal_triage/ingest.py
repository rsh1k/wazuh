# SPDX-License-Identifier: GPL-2.0-only
"""Alert ingestion backends.

Two sources are provided:

* :class:`FileAlertSource` tails a Wazuh ``alerts.json`` file. It is the
  default because it has zero external dependencies and is fully testable
  offline.
* :class:`OpenSearchAlertSource` queries the Wazuh indexer over HTTP using only
  the Python standard library (``urllib``), so the module pulls in no heavy
  HTTP client.

Both implement :class:`AlertSource` and return already-normalized
:class:`~wazuh_causal_triage.models.Alert` objects, filtered to the configured
look-back window.
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

from .config import IngestConfig
from .models import Alert

logger = logging.getLogger(__name__)


class IngestError(RuntimeError):
    """Raised for unrecoverable ingestion failures (e.g. unreachable indexer)."""


class AlertSource(ABC):
    """Abstract base for anything that yields normalized alerts."""

    @abstractmethod
    def fetch(self) -> list[Alert]:
        """Return the in-window alerts, oldest first."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# File source
# ---------------------------------------------------------------------------
class FileAlertSource(AlertSource):
    """Read alerts from a Wazuh ``alerts.json`` (newline-delimited JSON) file.

    Parameters
    ----------
    config:
        The ingest configuration block.
    reference_time:
        The "now" used for look-back filtering. Injectable purely so tests can
        pin a deterministic window; defaults to the current UTC time.
    """

    def __init__(self, config: IngestConfig, reference_time: Optional[datetime] = None) -> None:
        self._config = config
        self._reference_time = reference_time or datetime.now(timezone.utc)

    def fetch(self) -> list[Alert]:
        path = self._config.file.path
        cutoff = self._reference_time - timedelta(minutes=self._config.lookback_minutes)
        alerts: list[Alert] = []
        skipped = 0

        try:
            handle = open(path, "r", encoding="utf-8")
        except FileNotFoundError as exc:
            raise IngestError(f"Alert file not found: {path}") from exc
        except OSError as exc:  # permission errors, etc.
            raise IngestError(f"Cannot open alert file {path}: {exc}") from exc

        with handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    # A single corrupt line must never abort the whole batch;
                    # Wazuh occasionally writes partial lines during rotation.
                    skipped += 1
                    logger.debug("Skipping malformed alert at %s:%d", path, line_no)
                    continue
                if not isinstance(doc, dict):
                    skipped += 1
                    continue
                alert = Alert.from_wazuh(doc)
                if alert.timestamp >= cutoff:
                    alerts.append(alert)
                if len(alerts) >= self._config.max_alerts:
                    logger.warning(
                        "Reached max_alerts=%d; truncating ingestion", self._config.max_alerts
                    )
                    break

        if skipped:
            logger.info("Skipped %d malformed/non-object lines in %s", skipped, path)

        alerts.sort(key=lambda a: a.timestamp)
        logger.info("Ingested %d alerts from %s", len(alerts), path)
        return alerts


# ---------------------------------------------------------------------------
# OpenSearch source
# ---------------------------------------------------------------------------
class OpenSearchAlertSource(AlertSource):
    """Query the Wazuh indexer (OpenSearch) for recent alerts.

    Uses HTTP Basic auth and a bounded time-range query. TLS verification is
    configurable; it defaults to off only because Wazuh ships self-signed certs
    in default deployments, but operators should enable it in production with a
    trusted CA bundle.
    """

    def __init__(self, config: IngestConfig, reference_time: Optional[datetime] = None) -> None:
        self._config = config
        self._reference_time = reference_time or datetime.now(timezone.utc)

    def _build_request(self) -> urllib.request.Request:
        os_cfg = self._config.opensearch
        cutoff = self._reference_time - timedelta(minutes=self._config.lookback_minutes)
        body = {
            "size": min(self._config.max_alerts, 10_000),
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "range": {
                    "timestamp": {"gte": cutoff.isoformat(), "lte": self._reference_time.isoformat()}
                }
            },
        }
        url = f"{os_cfg.url.rstrip('/')}/{os_cfg.index_pattern}/_search"
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        token = base64.b64encode(f"{os_cfg.username}:{os_cfg.password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
        return request

    def fetch(self) -> list[Alert]:
        os_cfg = self._config.opensearch
        request = self._build_request()
        context: Optional[ssl.SSLContext] = None
        if request.full_url.lower().startswith("https") and not os_cfg.verify_certs:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(
                request, timeout=os_cfg.timeout_seconds, context=context
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise IngestError(
                f"Indexer returned HTTP {exc.code} for {request.full_url}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise IngestError(f"Cannot reach indexer at {os_cfg.url}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise IngestError("Indexer returned a non-JSON response") from exc

        hits = (((payload or {}).get("hits") or {}).get("hits")) or []
        alerts: list[Alert] = []
        for hit in hits:
            source = hit.get("_source") if isinstance(hit, dict) else None
            if not isinstance(source, dict):
                continue
            # Preserve the indexer document id when the alert lacks its own.
            source.setdefault("_id", hit.get("_id", ""))
            alerts.append(Alert.from_wazuh(source))

        alerts.sort(key=lambda a: a.timestamp)
        logger.info("Ingested %d alerts from indexer %s", len(alerts), os_cfg.url)
        return alerts


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def build_source(config: IngestConfig, reference_time: Optional[datetime] = None) -> AlertSource:
    """Instantiate the alert source selected in configuration."""
    if config.source == "file":
        return FileAlertSource(config, reference_time)
    if config.source == "opensearch":
        return OpenSearchAlertSource(config, reference_time)
    # Unreachable when config has been validated, but kept for safety.
    raise IngestError(f"Unsupported ingest source: {config.source!r}")
