"""Comprehensive training data collector and threat analyzer.

This module collects attack scenarios, trains models, and validates results.
It uses safe synthetic metadata only - no packet crafting or network traffic.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

from diodeshield.features.builder import extract_features
from diodeshield.fusion import fuse
from diodeshield.models.adapters import enabled_adapters
from diodeshield.schemas import TrafficEvent


class ThreatScenarioGenerator:
    """Generate safe synthetic attack scenarios for model training and analysis."""

    SCENARIOS: dict[str, dict[str, Any]] = {
        "normal": {"description": "Normal traffic patterns", "count": 100},
        "udp_burst": {"description": "UDP flood attack simulation", "count": 80},
        "tcp_scan": {"description": "TCP port scan reconnaissance", "count": 60},
        "dns_tunnel": {"description": "DNS exfiltration attempt", "count": 40},
        "lateral_movement": {"description": "Lateral movement detection", "count": 50},
        "protocol_anomaly": {"description": "Malformed protocol usage", "count": 45},
        "data_exfiltration": {"description": "Large data transfer anomaly", "count": 35},
        "resource_exhaustion": {"description": "CPU/memory pressure detection", "count": 30},
        "beaconing": {"description": "Command & control beacon", "count": 25},
        "encryption_anomaly": {"description": "Unexpected encryption patterns", "count": 20},
    }

    def __init__(self, base_time: datetime | None = None):
        self.base_time = base_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.event_counter = 0

    def generate_scenario(self, scenario_type: str, index: int) -> list[TrafficEvent]:
        """Generate a safe metadata-only traffic scenario."""
        events: list[TrafficEvent] = []
        start = self.base_time + timedelta(minutes=self.event_counter * 5)
        self.event_counter += 1

        if scenario_type == "normal":
            events = self._normal_traffic(start, index)
        elif scenario_type == "udp_burst":
            events = self._udp_burst(start, index)
        elif scenario_type == "tcp_scan":
            events = self._tcp_scan(start, index)
        elif scenario_type == "dns_tunnel":
            events = self._dns_tunnel(start, index)
        elif scenario_type == "lateral_movement":
            events = self._lateral_movement(start, index)
        elif scenario_type == "protocol_anomaly":
            events = self._protocol_anomaly(start, index)
        elif scenario_type == "data_exfiltration":
            events = self._data_exfiltration(start, index)
        elif scenario_type == "resource_exhaustion":
            events = self._resource_exhaustion(start, index)
        elif scenario_type == "beaconing":
            events = self._beaconing(start, index)
        elif scenario_type == "encryption_anomaly":
            events = self._encryption_anomaly(start, index)

        return events

    def _normal_traffic(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Normal HTTP/HTTPS traffic patterns."""
        events = []
        for i in range(15):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * 2),
                    src_ip="10.0.1.50",
                    dst_ip="8.8.8.8",
                    src_port=55000 + i,
                    dst_port=443 if i % 2 else 80,
                    protocol="TCP",
                    packet_len=1400 + (i % 100),
                    data_source="training_scenario",
                )
            )
        return events

    def _udp_burst(self, start: datetime, index: int) -> list[TrafficEvent]:
        """UDP flood attack pattern."""
        events = []
        for i in range(100):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(milliseconds=i * 10),
                    src_ip="192.168.1.100",
                    dst_ip="10.0.0.10",
                    src_port=12345,
                    dst_port=19001,
                    protocol="UDP",
                    packet_len=1472,
                    data_source="training_scenario",
                    metadata={"flood_indicator": True},
                )
            )
        return events

    def _tcp_scan(self, start: datetime, index: int) -> list[TrafficEvent]:
        """TCP port scan reconnaissance."""
        events = []
        for port in range(20, 200, 2):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(milliseconds=port * 5),
                    src_ip="203.0.113.50",
                    dst_ip="10.0.1.0",
                    src_port=50000 + port,
                    dst_port=port,
                    protocol="TCP",
                    packet_len=64,
                    data_source="training_scenario",
                    metadata={"scan_pattern": True},
                )
            )
        return events

    def _dns_tunnel(self, start: datetime, index: int) -> list[TrafficEvent]:
        """DNS exfiltration tunnel pattern."""
        events = []
        for i in range(50):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * 0.5),
                    src_ip="10.0.1.25",
                    dst_ip="8.8.8.8",
                    src_port=53500 + i,
                    dst_port=53,
                    protocol="UDP",
                    packet_len=200 + (i * 3),
                    data_source="training_scenario",
                    metadata={"dns_tunnel_indicator": True},
                )
            )
        return events

    def _lateral_movement(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Lateral movement within network."""
        events = []
        targets = [f"10.0.1.{100 + i}" for i in range(10)]
        for i, target in enumerate(targets):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * 1.5),
                    src_ip="10.0.1.50",
                    dst_ip=target,
                    src_port=40000 + i,
                    dst_port=445,
                    protocol="TCP",
                    packet_len=256,
                    data_source="training_scenario",
                    metadata={"lateral_movement": True},
                )
            )
        return events

    def _protocol_anomaly(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Malformed protocol usage (Modbus)."""
        events = []
        for i in range(25):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(milliseconds=i * 100),
                    src_ip="192.168.0.10",
                    dst_ip="10.0.0.2",
                    src_port=40000 + i,
                    dst_port=502,
                    protocol="TCP",
                    packet_len=256,
                    payload_hex="00010000000101ff00" if i % 3 else None,
                    data_source="training_scenario",
                    metadata={"protocol_anomaly": True},
                )
            )
        return events

    def _data_exfiltration(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Large data transfer exfiltration."""
        events = []
        for i in range(30):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * 0.3),
                    src_ip="10.0.1.50",
                    dst_ip="external.com",
                    src_port=50000 + i,
                    dst_port=443,
                    protocol="TCP",
                    packet_len=65535 - (i % 100),
                    data_source="training_scenario",
                    metadata={"high_volume_transfer": True},
                )
            )
        return events

    def _resource_exhaustion(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Resource exhaustion patterns."""
        events = []
        for i in range(40):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(milliseconds=i * 25),
                    src_ip="10.0.1.99",
                    dst_ip="10.0.0.1",
                    src_port=60000 + i,
                    dst_port=80,
                    protocol="TCP",
                    packet_len=1460,
                    data_source="training_scenario",
                    metadata={"resource_pressure": True},
                )
            )
        return events

    def _beaconing(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Command & control beacon pattern."""
        events = []
        interval = 30
        for i in range(12):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * interval),
                    src_ip="10.0.1.75",
                    dst_ip="c2.attacker.com",
                    src_port=50000 + i,
                    dst_port=443,
                    protocol="TCP",
                    packet_len=256,
                    data_source="training_scenario",
                    metadata={"beaconing_pattern": True},
                )
            )
        return events

    def _encryption_anomaly(self, start: datetime, index: int) -> list[TrafficEvent]:
        """Unexpected encryption or tunneling."""
        events = []
        for i in range(20):
            events.append(
                TrafficEvent(
                    timestamp=start + timedelta(seconds=i * 0.5),
                    src_ip="10.0.1.33",
                    dst_ip="vpn.provider.com",
                    src_port=55000 + i,
                    dst_port=1194,
                    protocol="UDP",
                    packet_len=1400,
                    data_source="training_scenario",
                    metadata={"encryption_anomaly": True},
                )
            )
        return events


def collect_training_data(output: Path, scenario_filter: str | None = None) -> dict[str, Any]:
    """Collect safe synthetic training data across all threat scenarios."""
    generator = ThreatScenarioGenerator()
    output.parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "status": "training_data_collection",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "safety": "metadata-only; no packet crafting, no external traffic, loopback-safe",
        "scenarios": {},
    }

    config = {
        "models": {"xgboost": True, "lstm": True, "fft": True, "kitsune": True, "isolation_forest": True},
        "fusion": {"xgboost": 0.4, "lstm": 0.2, "fft": 0.15, "kitsune": 0.15, "isolation_forest": 0.1},
    }
    adapters = enabled_adapters(config)

    all_features = []
    all_labels = []

    for scenario_name, scenario_config in ThreatScenarioGenerator.SCENARIOS.items():
        if scenario_filter and scenario_name != scenario_filter:
            continue

        is_attack = scenario_name != "normal"
        features_for_scenario = []
        model_scores_for_scenario = []

        for idx in range(scenario_config["count"]):
            events = generator.generate_scenario(scenario_name, idx)
            features = extract_features(events)

            # Score with all models
            scores = {name: adapter.score(features) for name, adapter in adapters.items()}
            fused_score = fuse(scores, config["fusion"])["score"]

            features_for_scenario.append(features)
            model_scores_for_scenario.append({**scores, "fused": fused_score})
            all_features.append(features)
            all_labels.append(1 if is_attack else 0)

        # Analyze scenario
        avg_scores = {}
        for model_name in adapters:
            scores_list = [s[model_name] for s in model_scores_for_scenario]
            avg_scores[model_name] = {
                "mean": round(float(np.mean(scores_list)), 4),
                "std": round(float(np.std(scores_list)), 4),
                "min": round(float(np.min(scores_list)), 4),
                "max": round(float(np.max(scores_list)), 4),
            }

        fused_scores = [s["fused"] for s in model_scores_for_scenario]
        avg_scores["fused"] = {
            "mean": round(float(np.mean(fused_scores)), 4),
            "std": round(float(np.std(fused_scores)), 4),
            "min": round(float(np.min(fused_scores)), 4),
            "max": round(float(np.max(fused_scores)), 4),
        }

        report["scenarios"][scenario_name] = {
            "description": scenario_config["description"],
            "count": scenario_config["count"],
            "is_attack": is_attack,
            "model_analysis": avg_scores,
        }

    # Compute aggregate metrics
    report["aggregate"] = {
        "total_samples": len(all_labels),
        "attack_samples": sum(all_labels),
        "normal_samples": len(all_labels) - sum(all_labels),
        "feature_schema_version": "1.0.0",
    }

    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect training data and analyze threat scenarios")
    parser.add_argument("--output", type=Path, default=Path("reports/threat_analysis_report.json"))
    parser.add_argument("--scenario", type=str, help="Collect data for a specific scenario only")
    args = parser.parse_args()

    report = collect_training_data(args.output, args.scenario)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
