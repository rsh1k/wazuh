# SPDX-License-Identifier: GPL-2.0-only
"""Wazuh Causal Triage — a companion module for Wazuh SIEM.

This package consumes Wazuh alerts, stitches causally related events into
per-host provenance graphs, scores the resulting *incidents* (not individual
alerts) using a transparent, explainable causal-decay model, and emits a
prioritized, human-readable triage verdict.

Design principles
------------------
* **Advisory, never destructive.** The module prioritizes and explains. It
  never deletes, suppresses, or mutates source alerts. Aggressive false
  positive suppression is known to also suppress true positives, so a human
  always remains in the loop.
* **Local-first / privacy-preserving.** Optional narrative generation targets
  a locally hosted LLM (Ollama). When no LLM is reachable the module degrades
  gracefully to a deterministic template narrator. No telemetry leaves the
  host.
* **Explainable scoring.** Every incident carries a full breakdown of the
  factors that produced its score, so an analyst can audit *why* something was
  prioritized.

The public API is intentionally small; see :class:`pipeline.TriagePipeline`.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.2.0"
