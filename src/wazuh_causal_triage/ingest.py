# SPDX-License-Identifier: GPL-2.0-only
"""Alert ingestion backends.

Two sources are provided:

* :class:`OpenSearchAlertSource` queries the Wazuh indexer over HTTP using only
  the Python standard library (``urllib``), with ``search_after`` pagination and
  retry. This is the **default** and the forward-looking path: in Wazuh 5.0,
  alerts (renamed "findings") live only on the indexer.
* :class:`FileAlertSource` tails a Wazuh ``alerts.json`` file. It has zero
  external dependencies and is fully testable offline, which suits 4.x
  deployments and local development.

Both implement :class:`AlertSource` and return already-normalized
:class:`~wazuh_causal_triage.models.Alert` objects, filtered to the configured
look-back window.
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Optional

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

    Uses HTTP Basic auth and a bounded time-range query, paginating with
    ``search_after`` so a run is not capped at OpenSearch's single-page limit.
    Transient failures are retried with linear backoff. TLS verification is
    configurable: production deployments should set ``verify_certs: true`` and
    point ``ca_cert_path`` at the indexer's CA bundle rather than disabling
    verification.
    """

    def __init__(self, config: IngestConfig, reference_time: Optional[datetime] = None) -> None:
        self._config = config
        self._reference_time = reference_time or datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------
    def _build_query_body(self, search_after: Optional[list] = None) -> dict:
        """Build one page of the search request body.

        Results are sorted by the configured timestamp field with ``_id`` as a
        tiebreaker so ``search_after`` paginates deterministically even when
        many documents share a timestamp.
        """
        os_cfg = self._config.opensearch
        ts_field = os_cfg.timestamp_field
        cutoff = self._reference_time - timedelta(minutes=self._config.lookback_minutes)
        body: dict = {
            "size": os_cfg.page_size,
            "sort": [{ts_field: {"order": "asc"}}, {"_id": {"order": "asc"}}],
            "query": {
                "range": {
                    ts_field: {
                        "gte": cutoff.isoformat(),
                        "lte": self._reference_time.isoformat(),
                    }
                }
            },
        }
        if search_after is not None:
            body["search_after"] = search_after
        return body

    def _build_request(self, body: dict) -> urllib.request.Request:
        os_cfg = self._config.opensearch
        url = f"{os_cfg.url.rstrip('/')}/{os_cfg.index_pattern}/_search"
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        token = base64.b64encode(
            f"{os_cfg.username}:{os_cfg.password}".encode("utf-8")
        ).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
        return request

    def _ssl_context(self, url: str) -> Optional[ssl.SSLContext]:
        os_cfg = self._config.opensearch
        if not url.lower().startswith("https"):
            return None
        if os_cfg.verify_certs:
            # Verify against a provided CA bundle, or the system trust store.
            return ssl.create_default_context(cafile=os_cfg.ca_cert_path)
        # Verification explicitly disabled (default for self-signed dev certs).
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    # ------------------------------------------------------------------
    # HTTP with retry
    # ------------------------------------------------------------------
    def _execute(self, body: dict) -> dict:
        """POST one search request, retrying transient failures."""
        os_cfg = self._config.opensearch
        request = self._build_request(body)
        context = self._ssl_context(request.full_url)
        last_error: Optional[Exception] = None

        for attempt in range(os_cfg.max_retries + 1):
            try:
                with urllib.request.urlopen(
                    request, timeout=os_cfg.timeout_seconds, context=context
                ) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                # 4xx (e.g. auth, bad index) are not retryable; fail fast.
                if exc.code < 500:
                    raise IngestError(
                        f"Indexer returned HTTP {exc.code} for {request.full_url}: {exc.reason}"
                    ) from exc
                last_error = exc
            except urllib.error.URLError as exc:
                last_error = exc
            except json.JSONDecodeError as exc:
                raise IngestError("Indexer returned a non-JSON response") from exc

            if attempt < os_cfg.max_retries:
                time.sleep(os_cfg.retry_backoff_seconds * (attempt + 1))

        raise IngestError(
            f"Cannot reach indexer at {os_cfg.url} after "
            f"{os_cfg.max_retries + 1} attempt(s): {last_error}"
        )

    # ------------------------------------------------------------------
    # Fetch with pagination
    # ------------------------------------------------------------------
    def fetch(self) -> list[Alert]:
        os_cfg = self._config.opensearch
        alerts: list[Alert] = []
        seen_ids: set[str] = set()
        search_after: Optional[list] = None
        # Hard cap on pages defends against an unexpected non-advancing cursor.
        max_pages = max(1, (self._config.max_alerts // max(os_cfg.page_size, 1)) + 1)

        for _ in range(max_pages):
            payload = self._execute(self._build_query_body(search_after))
            hits = (((payload or {}).get("hits") or {}).get("hits")) or []
            if not hits:
                break

            last_sort: Optional[list] = None
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                last_sort = hit.get("sort", last_sort)
                source = hit.get("_source")
                if not isinstance(source, dict):
                    continue
                doc_id = str(hit.get("_id", ""))
                if doc_id and doc_id in seen_ids:
                    continue  # Guard against overlap at page boundaries.
                if doc_id:
                    seen_ids.add(doc_id)
                    source.setdefault("_id", doc_id)
                alerts.append(Alert.from_wazuh(source))
                if len(alerts) >= self._config.max_alerts:
                    break

            if len(alerts) >= self._config.max_alerts or len(hits) < os_cfg.page_size:
                break
            if last_sort is None:
                break  # No cursor to continue from; stop rather than loop.
            search_after = last_sort

        alerts.sort(key=lambda a: a.timestamp)
        logger.info("Ingested %d alert(s)/finding(s) from indexer %s", len(alerts), os_cfg.url)
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
