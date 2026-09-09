from __future__ import annotations

import csv
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from diodeshield.api.main import app
from training.dataset_contract import DatasetContractError, obtain_dataset
from training.production import train_production


def _dataset(tmp_path):
    path = tmp_path / "events.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "group", "feature_a", "feature_b", "label"])
        for index in range(30):
            writer.writerow([f"2026-01-01T00:{index:02d}:00Z", f"host-{index % 6}",
                             index / 10, (index % 5) / 5, int(index >= 15)])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "name": "test-open-corpus", "source_url": "https://example.invalid/events.csv",
        "license": "CC-BY-4.0", "sha256": digest, "label_column": "label",
        "timestamp_column": "timestamp", "group_column": "group",
        "feature_columns": ["feature_a", "feature_b"], "citation": "test fixture",
    }), encoding="utf-8")
    return path, manifest


def test_production_training_writes_only_verified_calibrated_artifacts(tmp_path):
    dataset, manifest = _dataset(tmp_path)
    report = train_production(dataset, manifest, tmp_path / "models", branches=("fft", "kitsune"))
    assert report["status"] == "production_training"
    assert all(item["status"] == "trained" for item in report["models"].values())
    assert set(report["models"]["fft"]["metrics"]) >= {
        "roc_auc", "pr_auc", "precision", "recall", "f1", "latency_ms_p95", "threshold"
    }
    artifact = json.loads((tmp_path / "models" / "fft.json").read_text(encoding="utf-8"))
    assert artifact["provenance"]["license"] == "CC-BY-4.0"
    assert artifact["integrity"]["sha256"]


def test_unverified_dataset_is_rejected(tmp_path):
    dataset, _ = _dataset(tmp_path)
    manifest = tmp_path / "bad.json"
    manifest.write_text(json.dumps({
        "name": "unknown", "source_url": "https://example.invalid",
        "license": "UNKNOWN", "sha256": "0" * 64, "label_column": "label",
    }), encoding="utf-8")
    with pytest.raises(DatasetContractError):
        obtain_dataset(dataset, manifest)


def test_dashboard_summary_and_model_health_are_compatible():
    with TestClient(app) as client:
        summary = client.get("/api/dashboard-summary")
        health = client.get("/api/model-health")
        assert summary.status_code == 200
        assert {"kpis", "severity", "categories", "top_sources", "top_destinations"} <= summary.json().keys()
        assert health.status_code == 200
        assert health.json()["streaming_compatible"] is True
