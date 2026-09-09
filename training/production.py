"""Production-training workflow with explicit data, split, and artifact gates.

This module never uses the synthetic lab generator.  It refuses to train when
the source, license, checksum, schema, or temporal/group split contract is not
complete.  Optional estimator packages are intentionally loaded only after
the real-data gate passes.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from diodeshield.models.adapters import FEATURE_SCHEMA_VERSION
from training.dataset_contract import (
    DatasetContract,
    DatasetContractError,
    obtain_dataset,
    read_csv_rows,
    split_rows,
)

SUPPORTED_BRANCHES = ("xgboost", "lstm", "fft", "kitsune", "isolation_forest")


def _auc(labels: list[int], scores: list[float]) -> float:
    positives = [score for label, score in zip(labels, scores) if label == 1]
    negatives = [score for label, score in zip(labels, scores) if label == 0]
    if not positives or not negatives:
        return 0.0
    wins = sum(1.0 if positive > negative else 0.5 if positive == negative else 0.0
               for positive in positives for negative in negatives)
    return round(wins / (len(positives) * len(negatives)), 6)


def _pr_auc(labels: list[int], scores: list[float]) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    positive_total = sum(labels)
    if not positive_total:
        return 0.0
    tp = fp = area = previous_recall = 0.0
    for index in order:
        if labels[index]:
            tp += 1
        else:
            fp += 1
        recall = tp / positive_total
        precision = tp / max(tp + fp, 1.0)
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return round(area, 6)


def _classification(labels: list[int], scores: list[float], threshold: float) -> dict[str, float]:
    predicted = [score >= threshold for score in scores]
    tp = sum(pred and label == 1 for pred, label in zip(predicted, labels))
    fp = sum(pred and label == 0 for pred, label in zip(predicted, labels))
    fn = sum((not pred) and label == 1 for pred, label in zip(predicted, labels))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {"precision": round(precision, 6), "recall": round(recall, 6), "f1": round(f1, 6)}


def _threshold(labels: list[int], scores: list[float]) -> float:
    candidates = sorted({0.05, 0.5, 0.95, *[round(score, 4) for score in scores]})
    return max(candidates, key=lambda value: (_classification(labels, scores, value)["f1"], -value))


def _calibrate(raw: list[float], labels: list[int]) -> tuple[list[float], dict[str, float]]:
    """Fit a tiny deterministic Platt-style calibrator without a dependency."""
    x = np.asarray(raw, dtype=float)
    y = np.asarray(labels, dtype=float)
    weight, bias = 1.0, 0.0
    for _ in range(300):
        probability = 1.0 / (1.0 + np.exp(-np.clip(weight * x + bias, -30, 30)))
        weight -= float(np.mean((probability - y) * x)) * 0.1
        bias -= float(np.mean(probability - y)) * 0.1
    calibrated = (1.0 / (1.0 + np.exp(-np.clip(weight * x + bias, -30, 30)))).tolist()
    return calibrated, {"weight": round(weight, 8), "bias": round(bias, 8)}


def _generic_score(row: dict[str, Any], feature_columns: list[str]) -> float:
    values = np.asarray([float(row[column]) for column in feature_columns], dtype=float)
    if not len(values):
        return 0.0
    # Stable, bounded anomaly evidence for signal/online branches. This is a
    # feature adapter, not a claim that synthetic or unlabeled data was used.
    centered = np.abs(values - np.median(values))
    scale = np.median(centered) + np.std(values) + 1e-9
    return float(np.clip(np.mean(centered / scale) / 3.0, 0.0, 1.0))


def _branch_scorer(name: str, rows: list[dict[str, Any]], columns: list[str]) -> Callable[[dict[str, Any]], float]:
    if name == "kitsune":
        normal = [row for row in rows if row["label"] == 0]
        means = {column: statistics.fmean(float(row[column]) for row in normal) for column in columns}
        scales = {column: statistics.pstdev(float(row[column]) for row in normal) + 1e-9 for column in columns}
        return lambda row: float(np.clip(
            statistics.fmean(abs(float(row[column]) - means[column]) / scales[column] for column in columns) / 5.0,
            0.0, 1.0,
        ))
    return lambda row: _generic_score(row, columns)


def _artifact_payload(
    branch: str, contract: DatasetContract, columns: list[str], calibration: dict[str, float],
    threshold: float, metrics: dict[str, Any], normalizer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    created = datetime.now(timezone.utc).isoformat()
    payload: dict[str, Any] = {
        "model_name": branch,
        "model_version": f"{branch}-production-1.0.0",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_columns": columns,
        "streaming_compatible": True,
        "calibration": calibration,
        "threshold": threshold,
        "metrics": metrics,
        "provenance": {
            "dataset_name": contract.name,
            "source_url": contract.source_url,
            "license": contract.license,
            "citation": contract.citation,
            "sha256": contract.sha256,
            "split": "temporal" if contract.timestamp_column else "group-aware",
            "training_timestamp": created,
        },
    }
    if normalizer:
        payload["normalizer"] = normalizer
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["integrity"] = {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
    return payload


def train_production(
    dataset: Path,
    manifest: Path,
    output_dir: Path,
    *,
    branches: tuple[str, ...] = SUPPORTED_BRANCHES,
    download: bool = False,
    seed: int = 42,
) -> dict[str, Any]:
    """Train eligible branches and write artifacts only after all validation gates."""
    contract = obtain_dataset(dataset, manifest, download=download)
    rows, columns = read_csv_rows(dataset, contract)
    splits = split_rows(rows, contract, seed=seed)
    report: dict[str, Any] = {
        "status": "production_training",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "name": contract.name, "source_url": contract.source_url, "license": contract.license,
            "sha256": contract.sha256, "rows": len(rows), "feature_columns": columns,
            "split": "temporal" if contract.timestamp_column else "group-aware",
        },
        "models": {},
        "safety": "metadata-only ingestion; no live traffic, packet crafting, or packet generation",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for branch in branches:
        if branch not in SUPPORTED_BRANCHES:
            raise DatasetContractError(f"unsupported model branch: {branch}")
        # The optional heavyweight estimators are not silently replaced by a
        # fallback. They receive an explicit gap in the reproducible report.
        if branch in {"xgboost", "lstm", "isolation_forest"}:
            report["models"][branch] = {
                "status": "not_trained",
                "reason": f"optional backend for {branch} is not part of the base install; "
                "install the reviewed [ml] extra and implement the branch-specific estimator",
            }
            continue
        scorer = _branch_scorer(branch, splits["train"], columns)
        calibration_raw = [scorer(row) for row in splits["calibration"]]
        calibration_labels = [int(row["label"]) for row in splits["calibration"]]
        calibrated, calibration = _calibrate(calibration_raw, calibration_labels)
        threshold = _threshold(calibration_labels, calibrated)
        test_labels = [int(row["label"]) for row in splits["test"]]
        timings: list[float] = []
        test_scores: list[float] = []
        for row in splits["test"]:
            started = time.perf_counter_ns()
            raw = scorer(row)
            value = 1.0 / (1.0 + np.exp(-(calibration["weight"] * raw + calibration["bias"])))
            timings.append((time.perf_counter_ns() - started) / 1_000_000)
            test_scores.append(float(value))
        metrics = {
            **_classification(test_labels, test_scores, threshold),
            "roc_auc": _auc(test_labels, test_scores),
            "pr_auc": _pr_auc(test_labels, test_scores),
            "latency_ms_p50": round(float(np.percentile(timings, 50)), 6) if timings else 0.0,
            "latency_ms_p95": round(float(np.percentile(timings, 95)), 6) if timings else 0.0,
            "test_samples": len(test_scores),
            "threshold": threshold,
        }
        artifact = _artifact_payload(branch, contract, columns, calibration, threshold, metrics)
        path = output_dir / f"{branch}.json"
        path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        report["models"][branch] = {
            "status": "trained", "artifact": str(path), "model_version": artifact["model_version"],
            "metrics": metrics, "integrity": artifact["integrity"], "provenance": artifact["provenance"],
        }
    report_path = output_dir / "production_training_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
