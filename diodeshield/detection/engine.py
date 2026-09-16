"""Unified multi-layered detection orchestrator coordinating signatures, behaviors,
statistical baselines, threat intelligence, ML inference, and correlation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from diodeshield.anomaly.baseline import AnomalyBaselineEngine
from diodeshield.configuration.settings import AppConfig
from diodeshield.correlation.correlator import CorrelationEngine
from diodeshield.detection.behavioral.detector import BehavioralDetector
from diodeshield.detection.signatures.rules import SignatureEngine
from diodeshield.feature_engine.extractor import extract_window_features
from diodeshield.ml.manager import MLModelManager
from diodeshield.schemas import TrafficEvent
from diodeshield.threat_intelligence.client import ThreatIntelClient


class MultiLayerDetectionEngine:
    """Orchestrates all 5 detection layers on real network events and flows."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.signatures = SignatureEngine()
        self.behavioral = BehavioralDetector(config.detection)
        self.anomaly = AnomalyBaselineEngine(config.anomaly)
        self.threat_intel = ThreatIntelClient(config.threat_intel)
        self.ml = MLModelManager()
        self.correlator = CorrelationEngine(config.alerting.dedup_window_seconds)

    def analyze_packet(self, event: TrafficEvent) -> list[dict[str, Any]]:
        """Inspect a single decoded live packet for signatures, behaviors, and threat intel."""
        raw_signals: list[dict[str, Any]] = []

        # 1. Signatures
        if self.config.detection.signatures_enabled:
            sig_matches = self.signatures.evaluate_packet(event)
            for m in sig_matches:
                raw_signals.append({
                    "detection_method": "Signature Detection",
                    "category": m["category"],
                    "severity": m["severity"],
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                    "evidence": f"Rule {m['rule_id']} ({m['rule_name']}): {m['evidence']}",
                    "score": 0.90 if m["severity"] in ("CRITICAL", "HIGH") else 0.60,
                    "mitre_technique": m.get("mitre_technique", ""),
                })

        # 2. Behavioral Patterns
        if self.config.detection.behavioral_enabled:
            behav_matches = self.behavioral.process_event(event)
            raw_signals.extend(behav_matches)

        # 3. Threat Intelligence Reputation Check
        if self.config.threat_intel.enabled:
            ti_res = self.threat_intel.check_ip(event.src_ip)
            if ti_res.get("is_malicious"):
                raw_signals.append({
                    "detection_method": "Threat Intelligence",
                    "category": "KNOWN_MALICIOUS_INFRASTRUCTURE",
                    "severity": "CRITICAL" if ti_res.get("reputation_score", 0) >= 0.8 else "HIGH",
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                    "evidence": f"Threat Intelligence Match via {ti_res.get('source')}: {ti_res.get('attribution')}",
                    "score": ti_res.get("reputation_score", 0.85),
                    "ti_source": ti_res.get("source"),
                })

        # Correlate signals into structured alerts
        return self._format_and_correlate(raw_signals, event)

    def analyze_window(self, events: list[TrafficEvent]) -> list[dict[str, Any]]:
        """Inspect a window/batch of live packets for statistical deviations and ML patterns."""
        if not events:
            return []

        features = extract_window_features(events)
        raw_signals: list[dict[str, Any]] = []

        # Anomaly Baseline Check
        if self.config.detection.anomaly_enabled:
            anomaly_eval = self.anomaly.evaluate_observation(features)
            if anomaly_eval["is_anomaly"]:
                raw_signals.append({
                    "detection_method": "Anomaly Detection",
                    "category": "TRAFFIC_VOLUME_ANOMALY",
                    "severity": "HIGH" if anomaly_eval["composite_anomaly_score"] >= 0.85 else "MEDIUM",
                    "src_ip": events[0].src_ip if len(set(e.src_ip for e in events)) == 1 else "multiple",
                    "dst_ip": events[0].dst_ip if len(set(e.dst_ip for e in events)) == 1 else "multiple",
                    "protocol": "MIXED" if len(set(e.protocol for e in events)) > 1 else events[0].protocol,
                    "evidence": "; ".join(anomaly_eval["flagged_reasons"]),
                    "score": anomaly_eval["composite_anomaly_score"],
                    "feature_values": features,
                })

        # Machine Learning Inference (if trained and ready)
        if self.config.detection.ml_enabled and self.ml.is_ready:
            f_vec = [
                features["pps"], features["bps"], features["unique_dst_ports"],
                features["tcp_ratio"], features["udp_ratio"], features["syn_ratio"],
                features["mean_len"], features["iat_mean"], features["port_entropy"]
            ]
            ml_res = self.ml.predict(f_vec)
            if ml_res.get("status") == "SUCCESS" and ml_res.get("mean_anomaly_score", 0) >= 0.75:
                raw_signals.append({
                    "detection_method": "Machine Learning",
                    "category": "ML_ANOMALOUS_CLUSTER",
                    "severity": "HIGH",
                    "src_ip": events[0].src_ip,
                    "dst_ip": events[0].dst_ip,
                    "protocol": events[0].protocol,
                    "evidence": f"Ensemble model scored {ml_res['mean_anomaly_score']} on real features (Latency: {ml_res['inference_latency_microseconds']}us)",
                    "score": ml_res["mean_anomaly_score"],
                    "model_scores": ml_res["scores"],
                })

        return self._format_and_correlate(raw_signals, events[-1])

    def _format_and_correlate(
        self,
        raw_signals: list[dict[str, Any]],
        trigger_event: TrafficEvent,
    ) -> list[dict[str, Any]]:
        if not raw_signals:
            return []

        correlated = self.correlator.correlate(raw_signals)
        formatted_alerts: list[dict[str, Any]] = []

        for inc in correlated:
            alert_id = f"alt_{uuid.uuid4().hex[:12]}"
            methods = inc["detection_methods"]
            primary_method = methods[0] if len(methods) == 1 else "Multiple Detection Methods"

            # Recommend investigation action based on category
            cat = inc["primary_category"]
            action = "Inspect source host and isolate network interface."
            if "SCAN" in cat or "SWEEP" in cat:
                action = "Verify authorization for scanning activity; block source IP if unapproved."
            elif "BEACON" in cat:
                action = "Inspect endpoint processes for active C2 communication or reverse shells."
            elif "OT" in cat:
                action = "CRITICAL: Check physical plant state immediately; verify PLC programming access."
            elif "MALICIOUS" in cat:
                action = "Block source IP at perimeter firewall and review external connection logs."

            formatted_alerts.append({
                "alert_id": alert_id,
                "incident_id": inc["incident_id"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "first_seen": inc["first_seen"],
                "last_seen": inc["last_seen"],
                "src_ip": inc["src_ip"],
                "dst_ip": inc["dst_ip"],
                "protocol": trigger_event.protocol,
                "src_port": trigger_event.src_port,
                "dst_port": trigger_event.dst_port,
                "attack_category": cat,
                "risk_level": inc["max_severity"],
                "risk_score": round(0.85 if inc["max_severity"] in ("CRITICAL", "HIGH") else 0.60, 2),
                "confidence": inc["confidence"],
                "detection_method": primary_method,
                "all_detection_methods": methods,
                "evidence": inc["evidence"],
                "event_count": inc["event_count"],
                "recommended_action": action,
            })

        return formatted_alerts
