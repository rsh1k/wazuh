# SPDX-License-Identifier: GPL-2.0-only
"""Causal incident scoring with an adaptive threshold.

Scoring model
-------------
The core idea, drawn from provenance-causality research, is that the
probability of *independent benign* events jointly forming a malicious-looking
causal chain decays multiplicatively with the chain length. Concretely:

1. Each alert is assigned a benign probability ``p_i`` derived from its Wazuh
   rule level (a higher level implies a lower chance the alert is benign
   noise). ``p_i`` is clamped to avoid any single alert dominating.
2. The chain's joint benign probability is ``P_benign = prod(p_i)``, assuming
   approximate independence. This is what makes long chains of individually
   weak signals collectively strong.
3. The base maliciousness score is ``(1 - P_benign) * 100``.
4. Additive, capped bonuses reward kill-chain progression (distinct ATT&CK
   tactics) and lateral movement (multiple hosts touched), both well-established
   high-signal behaviors.

Adaptive threshold
-------------------
Rather than a fixed cutoff, an incident is *prioritized* when its score exceeds
``mean + k * stddev`` of a running, exponentially-weighted baseline of recent
scores — subject to an absolute floor. This lets the module learn each
environment's noise floor instead of forcing operators to hand-tune a constant.

The baseline can be persisted between runs so the adaptation survives restarts.
All state is plain JSON; there is no hidden model.
"""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

from .config import ScoringConfig
from .models import Incident, Priority, ScoreFactor

logger = logging.getLogger(__name__)

# Wazuh rule levels run 0-15. Used to normalize a level into a benign
# probability.
_MAX_RULE_LEVEL = 15.0


@dataclass
class _Baseline:
    """Exponentially-weighted running mean/variance of incident scores."""

    mean: float = 0.0
    variance: float = 0.0
    count: int = 0

    @property
    def stddev(self) -> float:
        return math.sqrt(max(self.variance, 0.0))

    def update(self, score: float, alpha: float) -> None:
        """Update the EWMA mean and variance with a new ``score``.

        Uses the standard incremental EWMA/EWMVar formulation. The first sample
        seeds the mean directly so the baseline is not biased toward zero.
        """
        if self.count == 0:
            self.mean = score
            self.variance = 0.0
        else:
            delta = score - self.mean
            self.mean += alpha * delta
            # West's EWMA variance update.
            self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta)
        self.count += 1

    def to_dict(self) -> dict[str, float]:
        return {"mean": self.mean, "variance": self.variance, "count": self.count}

    @classmethod
    def from_dict(cls, data: dict[str, float]) -> "_Baseline":
        return cls(
            mean=float(data.get("mean", 0.0)),
            variance=float(data.get("variance", 0.0)),
            count=int(data.get("count", 0)),
        )


class CausalScorer:
    """Score incidents and decide which clear the adaptive threshold."""

    def __init__(self, config: ScoringConfig) -> None:
        self._config = config
        self._baseline = self._load_baseline()

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def score_incidents(self, incidents: list[Incident]) -> list[Incident]:
        """Score every incident, then apply the adaptive threshold.

        Scoring and thresholding are deliberately separated: all incidents are
        scored first so the threshold sees the full batch, then the baseline is
        updated *after* decisions are made (so an anomalous batch does not
        immediately desensitize the detector within the same run).
        """
        for incident in incidents:
            self._score_one(incident)

        threshold = self._current_threshold()
        for incident in incidents:
            incident.is_prioritized = incident.score >= threshold
            incident.priority = Priority.from_score(incident.score)

        # Update baseline with this batch, then persist.
        for incident in incidents:
            self._baseline.update(incident.score, self._config.baseline_alpha)
        self._save_baseline()

        prioritized = sum(1 for i in incidents if i.is_prioritized)
        logger.info(
            "Scored %d incident(s); %d prioritized (threshold=%.2f, baseline mean=%.2f sd=%.2f)",
            len(incidents),
            prioritized,
            threshold,
            self._baseline.mean,
            self._baseline.stddev,
        )
        return incidents

    def _score_one(self, incident: Incident) -> None:
        """Compute and attach the score and its factor breakdown."""
        factors: list[ScoreFactor] = []

        # 1. Multiplicative causal-decay base score.
        joint_benign = 1.0
        for alert in incident.alerts:
            joint_benign *= self._benign_probability(alert.rule_level)
        base = (1.0 - joint_benign) * 100.0
        factors.append(
            ScoreFactor(
                name="causal_chain",
                detail=(
                    f"{incident.alert_count} linked alert(s); "
                    f"joint benign probability={joint_benign:.4f}"
                ),
                contribution=round(base, 2),
            )
        )

        # 2. Kill-chain progression bonus (distinct tactics beyond the first).
        distinct_tactics = max(len(incident.tactics) - 1, 0)
        tactic_bonus = distinct_tactics * self._config.tactic_diversity_weight
        if tactic_bonus:
            factors.append(
                ScoreFactor(
                    name="killchain_progression",
                    detail=f"{len(incident.tactics)} distinct ATT&CK tactic(s): "
                    + ", ".join(incident.tactics),
                    contribution=round(tactic_bonus, 2),
                )
            )

        # 3. Lateral-movement / egress bonus (hosts beyond the origin).
        extra_hosts = max(len(incident.hosts_involved) - 1, 0)
        lateral_bonus = extra_hosts * self._config.lateral_movement_weight
        if lateral_bonus:
            factors.append(
                ScoreFactor(
                    name="lateral_movement",
                    detail=f"{len(incident.hosts_involved)} host(s)/destination(s) involved",
                    contribution=round(lateral_bonus, 2),
                )
            )

        total = base + tactic_bonus + lateral_bonus
        # Scores are reported on a 0-100 scale; bonuses can push the raw total
        # above 100, so we clamp for presentation while preserving ordering.
        incident.score = float(min(total, 100.0))
        incident.factors = factors

    def _benign_probability(self, rule_level: int) -> float:
        """Map a Wazuh rule level to a clamped benign probability.

        Level 0 -> ceil (almost certainly benign); level 15 -> floor (almost
        certainly real). Linear in between, which is transparent and easy to
        reason about for operators.
        """
        level = max(0, min(rule_level, int(_MAX_RULE_LEVEL)))
        raw = 1.0 - (level / _MAX_RULE_LEVEL)
        return max(self._config.benign_prob_floor, min(raw, self._config.benign_prob_ceil))

    # ------------------------------------------------------------------
    # Adaptive threshold
    # ------------------------------------------------------------------
    def _current_threshold(self) -> float:
        """Return the larger of the absolute floor and the adaptive cutoff."""
        if self._baseline.count == 0:
            # No history yet: rely solely on the absolute floor.
            return self._config.absolute_floor
        adaptive = self._baseline.mean + self._config.adaptive_k * self._baseline.stddev
        return max(self._config.absolute_floor, adaptive)

    # ------------------------------------------------------------------
    # Baseline persistence
    # ------------------------------------------------------------------
    def _load_baseline(self) -> _Baseline:
        path = self._config.baseline_state_path
        if not path or not os.path.exists(path):
            return _Baseline()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return _Baseline.from_dict(json.load(handle))
        except (OSError, ValueError, TypeError) as exc:
            # A corrupt or unreadable state file should not be fatal; we just
            # start a fresh baseline and warn.
            logger.warning("Could not load baseline state from %s (%s); starting fresh", path, exc)
            return _Baseline()

    def _save_baseline(self) -> None:
        path = self._config.baseline_state_path
        if not path:
            return
        try:
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
            # Atomic write: write to a temp file in the same directory, then
            # rename, so a crash mid-write never corrupts the state file.
            fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._baseline.to_dict(), handle)
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        except OSError as exc:  # pragma: no cover - filesystem-dependent
            logger.warning("Could not persist baseline state to %s: %s", path, exc)

    # ------------------------------------------------------------------
    # Introspection (useful for tests and operators)
    # ------------------------------------------------------------------
    @property
    def baseline_mean(self) -> float:
        return self._baseline.mean

    @property
    def baseline_stddev(self) -> float:
        return self._baseline.stddev
