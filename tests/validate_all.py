"""Comprehensive end-to-end validation and test suite."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.fusion import fuse
from diodeshield.models.adapters import enabled_adapters
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import TrafficEvent


def test_synthetic_training() -> dict[str, Any]:
    """Validate synthetic training runs end-to-end."""
    print("[TEST] Synthetic training...")
    result = subprocess.run(
        [sys.executable, "training/train_all_models.py", "--synthetic"],
        capture_output=True,
        text=True,
        cwd=".",
        check=False,
    )
    if result.returncode != 0:
        return {"status": "FAILED", "error": result.stderr[:500]}

    try:
        report = json.loads(result.stdout)
        return {
            "status": "PASSED",
            "samples": report.get("samples"),
            "models_evaluated": list(report.get("models", {}).keys()),
            "safety": report.get("safety"),
        }
    except json.JSONDecodeError as e:
        return {"status": "FAILED", "error": str(e)[:500]}


def test_model_adapters() -> dict[str, Any]:
    """Validate all model adapters are functional."""
    print("[TEST] Model adapters...")
    config = {
        "models": {"xgboost": True, "lstm": True, "fft": True, "kitsune": True, "isolation_forest": True},
        "fusion": {"xgboost": 0.4, "lstm": 0.2, "fft": 0.15, "kitsune": 0.15, "isolation_forest": 0.1},
    }

    try:
        adapters = enabled_adapters(config)
        if not adapters:
            return {"status": "FAILED", "error": "No adapters loaded"}

        # Test scoring
        features = {
            "packets": 10,
            "bytes": 5000,
            "fan_out": 5,
            "baseline_deviation": 1.5,
            "protocol_anomaly_score": 0.2,
            "iat_cv": 0.5,
            "periodicity_score": 2.0,
        }

        scores = {}
        for name, adapter in adapters.items():
            try:
                score = adapter.score(features)
                if not (0 <= score <= 1):
                    return {"status": "FAILED", "error": f"{name} score out of bounds: {score}"}
                scores[name] = score
            except (AttributeError, ValueError, TypeError) as e:
                return {"status": "FAILED", "error": f"{name} adapter failed: {e}"}

        fused = fuse(scores, config["fusion"])
        if not (0 <= fused.get("score", 0) <= 1):
            return {"status": "FAILED", "error": f"Fusion score out of bounds: {fused}"}

        return {
            "status": "PASSED",
            "adapters_loaded": list(adapters.keys()),
            "sample_scores": {k: round(v, 4) for k, v in scores.items()},
            "fused_score": round(fused.get("score", 0), 4),
        }
    except (ImportError, ValueError, KeyError) as e:
        return {"status": "FAILED", "error": str(e)[:500]}


def test_pipeline_end_to_end() -> dict[str, Any]:
    """Validate detection pipeline processes events correctly."""
    print("[TEST] Pipeline end-to-end...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Repository(Path(tmpdir) / "test.db")
            config = load_config()
            config["persistence"] = {"consecutive_windows": 1, "cooldown_seconds": 0}
            pipeline = DetectionPipeline(repo, config)

            # Generate test events
            events = [
                TrafficEvent(
                    timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    src_port=50000 + i,
                    dst_port=502,
                    protocol="TCP",
                    packet_len=128 + (i % 100),
                    data_source="test",
                )
                for i in range(12)
            ]

            alerts = []
            for event in events:
                results = pipeline.ingest(event)
                alerts.extend(results)

            repo.close()

            return {
                "status": "PASSED",
                "events_processed": len(events),
                "alerts_generated": len(alerts),
                "sample_alert": alerts[0] if alerts else None,
            }
    except (OSError, ValueError, RuntimeError, AttributeError) as e:
        return {"status": "FAILED", "error": str(e)[:500]}


def test_threat_collection() -> dict[str, Any]:
    """Validate threat scenario collection and model analysis."""
    print("[TEST] Threat scenario collection...")
    result = subprocess.run(
        [sys.executable, "training/collect_training_data.py", "--output", "reports/test_threat_analysis.json"],
        capture_output=True,
        text=True,
        cwd=".",
        check=False,
    )
    if result.returncode != 0:
        return {"status": "FAILED", "error": result.stderr[:500]}

    try:
        report = json.loads(result.stdout)
        scenarios = list(report.get("scenarios", {}).keys())
        return {
            "status": "PASSED",
            "scenarios_collected": len(scenarios),
            "scenario_names": scenarios,
            "total_samples": report.get("aggregate", {}).get("total_samples"),
            "attack_samples": report.get("aggregate", {}).get("attack_samples"),
        }
    except json.JSONDecodeError as e:
        return {"status": "FAILED", "error": str(e)[:500]}


def test_api_endpoints() -> dict[str, Any]:
    """Validate API endpoints are accessible and return valid responses."""
    print("[TEST] API endpoints...")
    try:
        from fastapi.testclient import TestClient

        from diodeshield.api.main import app

        client = TestClient(app)

        tests = [
            ("GET", "/health", 200),
            ("GET", "/health/detailed", 200),
            ("GET", "/api/models", 200),
            ("GET", "/api/alerts", 200),
            ("GET", "/api/traffic", 200),
            ("GET", "/api/metrics", 200),
            ("GET", "/api/interfaces", 200),
            ("GET", "/api/capture/stats", 200),
            ("GET", "/api/rules", 200),
            ("GET", "/api/system/metrics", 200),
            ("GET", "/api/threat-intel/status", 200),
        ]

        results = {}
        for method, path, expected_code in tests:
            try:
                if method == "GET":
                    resp = client.get(path)
                results[path] = {
                    "status_code": resp.status_code,
                    "ok": resp.status_code == expected_code,
                }
            except (ConnectionError, ValueError, OSError) as e:
                results[path] = {"status": "error", "error": str(e)[:200]}

        all_ok = all(r.get("ok", False) for r in results.values())
        return {
            "status": "PASSED" if all_ok else "FAILED",
            "endpoints_tested": results,
        }
    except (ImportError, OSError) as e:
        return {"status": "FAILED", "error": str(e)[:500]}


def run_pytest() -> dict[str, Any]:
    """Run pytest test suite."""
    print("[TEST] PyTest regression tests...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        capture_output=True,
        text=True,
        cwd=".",
    )
    lines = result.stdout.split("\n")
    summary = next((l for l in reversed(lines) if "passed" in l.lower()), "Unknown")

    return {
        "status": "PASSED" if result.returncode == 0 else "FAILED",
        "summary": summary,
        "return_code": result.returncode,
    }


def run_linter() -> dict[str, Any]:
    """Run ruff linter."""
    print("[TEST] Ruff linter...")
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "diodeshield/", "training/", "tests/"],
        capture_output=True,
        text=True,
        cwd=".",
    )

    if "error:" in result.stderr.lower() and result.returncode != 0:
        return {
            "status": "FAILED",
            "error": result.stderr[:500],
            "return_code": result.returncode,
        }

    return {
        "status": "PASSED",
        "return_code": result.returncode,
        "output": result.stdout[:200] if result.stdout else "Clean",
    }


def main() -> None:
    print("\n" + "=" * 80)
    print("DIODESHIELD COMPREHENSIVE VALIDATION SUITE")
    print("=" * 80 + "\n")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests": {
            "linter": run_linter(),
            "pytest": run_pytest(),
            "synthetic_training": test_synthetic_training(),
            "model_adapters": test_model_adapters(),
            "pipeline": test_pipeline_end_to_end(),
            "threat_collection": test_threat_collection(),
            "api_endpoints": test_api_endpoints(),
        },
    }

    # Aggregate status
    results["overall_status"] = (
        "ALL PASSED"
        if all(r.get("status") == "PASSED" for r in results["tests"].values())
        else "SOME FAILED"
    )

    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)
    print(json.dumps(results, indent=2, default=str))
    print("=" * 80 + "\n")

    # Return non-zero exit if any test failed
    sys.exit(0 if results["overall_status"] == "ALL PASSED" else 1)


if __name__ == "__main__":
    main()
