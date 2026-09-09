from __future__ import annotations

import statistics
from typing import Any


def normalize_scores(scores: dict[str, float]) -> dict[str, float]:
    return {key: max(0.0, min(1.0, float(value))) for key, value in scores.items()}


def fuse(scores: dict[str, float], weights: dict[str, float]) -> dict[str, Any]:
    scores = normalize_scores(scores)
    active = {name: weight for name, weight in weights.items() if name in scores}
    total = sum(active.values()) or 1.0
    risk = sum(scores[name] * weight for name, weight in active.items()) / total
    values = list(scores.values())
    mean = statistics.fmean(values) if values else 0.0
    disagreement = statistics.pvariance(values) if len(values) > 1 else 0.0
    return {"score": max(0.0, min(1.0, risk)), "mean_score": mean, "variance": disagreement,
            "max_score": max(values, default=0.0), "min_score": min(values, default=0.0),
            "model_disagreement": min(1.0, disagreement * 4), "consensus_score": max(0.0, mean * (1 - min(1.0, disagreement * 4))),
            "scores": scores}
