# Wazuh Causal Triage

A companion module for [Wazuh](https://wazuh.com) that turns a noisy stream of
individual alerts into a small set of **prioritized, explainable incidents**.

Instead of treating each alert as an isolated row, this module reconstructs the
**causal chain** behind related alerts — process lineage, shared users, temporal
proximity — and scores the *chain* rather than the alert. The scoring rests on a
well-documented principle from provenance-causality research: the probability of
independent benign events jointly forming a malicious-looking causal chain decays
*multiplicatively* with chain length. A single odd event is usually noise; a
connected chain of odd events almost never is.

> **Advisory, never destructive.** This module prioritizes and explains. It never
> deletes, suppresses, or modifies source alerts. A human analyst always stays in
> the loop. Any LLM-generated narrative is a hypothesis to verify, not a verdict.

---

## Why this exists

A typical SOC drowns in alerts, and the cost is concrete: industry estimates put
the fully-loaded cost of a single false positive at roughly **$1,400** in analyst
time and overhead. The dominant operational problem is not *finding* threats — it
is *deciding which of thousands of alerts deserve a human*. Wazuh's existing AI
features focus on hunting and enrichment; this module fills the adjacent gap:
**causal triage and prioritization**.

It rides entirely on data Wazuh already collects (Sysmon process trees, auth
events, ATT&CK rule mappings), runs **locally**, and requires no new agents or
cloud services.

---

## How it works

```
 alerts.json / indexer          provenance graph              scored incidents
 ┌──────────────────┐    ┌───────────────────────────┐    ┌────────────────────┐
 │ evt: failed login │    │  login ─┐                 │    │ INCIDENT (CRITICAL)│
 │ evt: failed login │ -> │  login ─┤                 │ -> │  score 100         │
 │ evt: powershell   │    │  powershell ─▶ cmd ─▶ net │    │  4 ATT&CK tactics  │
 │ evt: discovery    │    │            (process tree) │    │  lateral movement  │
 │ evt: net connect  │    │                           │    │  + narrative       │
 │ evt: benign noise │    │  (isolated, no seed) ✗    │    │  (noise suppressed)│
 └──────────────────┘    └───────────────────────────┘    └────────────────────┘
```

1. **Ingest** — read alerts from a Wazuh `alerts.json` file (default) or the
   Wazuh indexer (OpenSearch), filtered to a look-back window.
2. **Build provenance graph** — per host, link alerts by process GUID lineage
   (`processGuid` / `parentProcessGuid`) and by temporal proximity on the same
   user. Connected components containing at least one above-noise "seed" alert
   become incidents.
3. **Score** — compute each incident's joint benign probability (multiplicative
   decay), convert to a 0–100 maliciousness score, and add capped bonuses for
   ATT&CK kill-chain progression and lateral movement.
4. **Adaptive threshold** — prioritize incidents above `mean + k·stddev` of a
   running, persisted baseline (subject to an absolute floor), so the module
   learns each environment's noise floor instead of using a hand-tuned constant.
5. **Narrate** — generate a human-readable summary. The default narrator is
   deterministic and offline; an optional local-LLM narrator (Ollama) can write
   richer prose and **falls back to the template on any failure**.
6. **Output** — write a full JSON audit trail, optionally append prioritized
   incidents as NDJSON for Wazuh to re-ingest, and/or print to stdout.

---

## Installation

```bash
git clone https://github.com/rsh1k/wazuh.git
cd wazuh/wazuh-causal-triage      # adjust to wherever you place the module
pip install .
```

Runtime dependencies are intentionally minimal: `networkx` and `PyYAML`. HTTP
calls (OpenSearch, Ollama) use only the Python standard library.

Python 3.10+ is required.

---

## Usage

Run once with all defaults (reads `/var/ossec/logs/alerts/alerts.json`):

```bash
wazuh-causal-triage run
```

Run against a specific file or config:

```bash
wazuh-causal-triage run --alerts ./alerts.json
wazuh-causal-triage run --config config/config.example.yaml
```

Typical deployment is a cron job or systemd timer invoking `run` every few
minutes. Exit codes: `0` success, `2` config error, `3` ingestion error,
`1` unexpected error.

---

## Configuration

Copy `config/config.example.yaml` and edit. Every key is optional and falls back
to a documented default; an empty config is valid. Key knobs:

| Key | Meaning |
| --- | --- |
| `ingest.source` | `file` or `opensearch` |
| `ingest.lookback_minutes` | only consider alerts newer than this |
| `graph.correlation_window_seconds` | max time gap for temporal linkage |
| `graph.min_seed_level` | alerts at/below this level cannot start an incident |
| `scoring.adaptive_k` | threshold = `mean + k·stddev` (clamped to a floor) |
| `scoring.absolute_floor` | minimum score to ever be prioritized |
| `scoring.baseline_state_path` | where the adaptive baseline is persisted |
| `narrative.backend` | `template` (offline) or `ollama` (local LLM) |
| `output.wazuh_feedback_path` | NDJSON file for Wazuh re-ingestion |

---

## Wazuh integration

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for a step-by-step guide to
wiring the feedback channel back into Wazuh with a custom decoder and rules, so
prioritized incidents appear as first-class enriched alerts in the dashboard.

---

## Development

```bash
pip install -e ".[dev]"
pytest --cov=wazuh_causal_triage --cov-report=term-missing
mypy src/wazuh_causal_triage
```

The suite is fully offline and deterministic (no network, no live LLM). It
covers parsing, configuration validation, graph construction, the scoring model,
adaptive thresholding and baseline persistence, narrative fallback, output
sinks, the pipeline, and the CLI.

---

## Limitations and honest caveats

* This is **decision support**, not autonomous response. Aggressive false-positive
  suppression is known to also suppress *true* positives, so the module never
  suppresses anything — it ranks and explains.
* The scoring model is deliberately transparent and linear rather than a learned
  black box. That is a feature for auditability, but it means tuning the weights
  to your environment matters. Start with the defaults and adjust using the
  per-incident factor breakdown.
* The independence assumption behind multiplicative decay is an approximation;
  highly correlated rule families can inflate a chain's score. The seed
  requirement and adaptive threshold mitigate this, but review the rationale.
* No software is "100% error-free." This module ships with a passing test suite,
  static typing, graceful degradation, and atomic writes — engineered to fail
  safe, not to make impossible guarantees.

---

## License

GPL-2.0-only, to match the Wazuh project. See [`LICENSE`](LICENSE).
