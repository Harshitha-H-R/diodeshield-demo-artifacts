"""Statistical baseline engine using Exponentially Weighted Moving Average (EWMA)
and dynamic rolling z-scores derived from observed network telemetry.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Any

from diodeshield.configuration.settings import AnomalySettings


class MetricBaseline:
    """Tracks EWMA mean and variance for a single numeric metric."""

    def __init__(self, alpha: float = 0.1, min_obs: int = 20) -> None:
        self.alpha = alpha
        self.min_obs = min_obs
        self.count: int = 0
        self.mean: float = 0.0
        self.variance: float = 0.0

    def update(self, value: float) -> tuple[float, float]:
        """Update EWMA and return (current_zscore, anomaly_score_0_to_1)."""
        self.count += 1
        if self.count == 1:
            self.mean = value
            self.variance = 1.0  # Initial non-zero prior
            return 0.0, 0.0

        diff = value - self.mean
        incr = self.alpha * diff
        self.mean += incr
        # Welford/EWMA variance update
        self.variance = (1.0 - self.alpha) * (self.variance + diff * incr)
        std = math.sqrt(max(0.0001, self.variance))

        zscore = (value - self.mean) / std
        if self.count < self.min_obs:
            return zscore, 0.0  # Warm-up phase, not an anomaly yet

        # Sigmoidal mapping of positive zscore to [0, 1] anomaly score
        if zscore <= 0:
            anomaly_score = 0.0
        else:
            # z=3 -> ~0.7, z=5 -> ~0.95
            anomaly_score = round(1.0 / (1.0 + math.exp(-0.8 * (zscore - 3.0))), 4)

        return round(zscore, 2), anomaly_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean": round(self.mean, 3),
            "std": round(math.sqrt(max(0.0001, self.variance)), 3),
        }


class AnomalyBaselineEngine:
    """Maintains statistical baselines across key network features per interface/host/protocol."""

    def __init__(self, settings: AnomalySettings | None = None) -> None:
        self.settings = settings or AnomalySettings()
        self._baselines: dict[str, MetricBaseline] = {}
        self._lock = threading.Lock()
        self._last_snapshot_time = time.time()

    def _get_baseline(self, key: str) -> MetricBaseline:
        if key not in self._baselines:
            self._baselines[key] = MetricBaseline(
                alpha=self.settings.ewma_alpha,
                min_obs=self.settings.min_observations_for_baseline,
            )
        return self._baselines[key]

    def evaluate_observation(
        self,
        features: dict[str, Any],
        scope: str = "global",
    ) -> dict[str, Any]:
        """Evaluate a feature set against the moving baseline and update stats."""
        with self._lock:
            tracked_metrics = ["pps", "bps", "unique_dst_ports", "syn_ratio", "rst_ratio", "burst_ratio"]
            metric_results: dict[str, Any] = {}
            anomaly_scores: list[float] = []
            flagged_reasons: list[str] = []

            for metric in tracked_metrics:
                val = float(features.get(metric, 0.0))
                key = f"{scope}:{metric}"
                baseline = self._get_baseline(key)
                zscore, anomaly_score = baseline.update(val)

                metric_results[metric] = {
                    "observed": val,
                    "baseline_mean": baseline.to_dict()["mean"],
                    "baseline_std": baseline.to_dict()["std"],
                    "zscore": zscore,
                    "anomaly_score": anomaly_score,
                }
                anomaly_scores.append(anomaly_score)

                if zscore >= self.settings.critical_zscore_threshold:
                    flagged_reasons.append(
                        f"{metric} spiked to {val} (z={zscore} vs baseline mean {baseline.mean:.1f})"
                    )
                elif zscore >= self.settings.zscore_threshold:
                    flagged_reasons.append(
                        f"{metric} elevated to {val} (z={zscore} vs baseline mean {baseline.mean:.1f})"
                    )

            max_score = max(anomaly_scores) if anomaly_scores else 0.0
            is_anomaly = max_score >= 0.65 or len(flagged_reasons) > 0

            return {
                "is_anomaly": is_anomaly,
                "composite_anomaly_score": round(max_score, 4),
                "flagged_reasons": flagged_reasons,
                "metrics": metric_results,
            }

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_metric_trackers": len(self._baselines),
                "settings": {
                    "alpha": self.settings.ewma_alpha,
                    "zscore_threshold": self.settings.zscore_threshold,
                    "min_obs": self.settings.min_observations_for_baseline,
                },
                "tracked_baselines": {k: b.to_dict() for k, b in list(self._baselines.items())[:10]},
            }
