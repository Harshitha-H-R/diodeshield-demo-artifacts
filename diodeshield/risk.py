from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


class PersistenceEngine:
    def __init__(self, consecutive_windows: int = 3, cooldown_seconds: int = 30):
        self.required = max(1, consecutive_windows)
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.counts: defaultdict[str, int] = defaultdict(int)
        self.last_alert: dict[str, datetime] = {}

    def observe(self, key: str, score: float, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        self.counts[key] = self.counts[key] + 1 if score >= 0.5 else 0
        if self.counts[key] < self.required:
            return False
        if now - self.last_alert.get(key, datetime.min.replace(tzinfo=timezone.utc)) < self.cooldown:
            return False
        self.last_alert[key] = now
        return True


class RiskEngine:
    def __init__(self, config: dict[str, Any]):
        self.thresholds = config.get("risk", {})
        p = config.get("persistence", {})
        self.persistence = PersistenceEngine(p.get("consecutive_windows", 3), p.get("cooldown_seconds", 30))

    def evaluate(self, fusion: dict[str, Any], features: dict[str, Any], protocol: dict[str, Any] | None = None,
                 asset_criticality: float = 0.5, key: str = "global") -> dict[str, Any]:
        protocol = protocol or {}
        # Independent protocol evidence is deliberately material but not a verdict:
        # malformed/unexpected traffic is an investigation signal, not proof of compromise.
        score = min(1.0, float(fusion["score"]) * 0.75 +
                    float(protocol.get("protocol_anomaly_score", 0)) * 0.45 +
                    float(features.get("udp_burst_score", 0)) * 0.45 +
                    float(features.get("ttl_anomaly_score", 0)) * 0.35 +
                    float(features.get("payload_integrity_anomaly", 0)) * 0.35 +
                    float(features.get("ip_spoofing_score", features.get("identity_anomaly_score", 0))) * 0.45 +
                    float(features.get("packet_alteration_score", 0)) * 0.45 +
                    float(features.get("behavior_anomaly_score", 0)) * 0.25 +
                    min(1.0, float(features.get("fan_out", 0)) / 10.0) * 0.30 +
                    min(1.0, float(features.get("port_diversity", 0)) / 10.0) * 0.15 +
                    float(asset_criticality) * 0.05)
        t = self.thresholds
        level = "CRITICAL" if score >= t.get("critical", .85) else "HIGH" if score >= t.get("high", .7) else "MEDIUM" if score >= t.get("medium", .5) else "LOW" if score >= t.get("low", .3) else "INFO"
        reasons = []
        if features.get("fan_out", 0) > 5:
            reasons.append("unusual destination fan-out")
        if features.get("baseline_deviation", 0) > 0.5:
            reasons.append("behavior differs from baseline")
        if protocol.get("protocol_anomaly_score", 0) > 0:
            reasons.append("protocol anomaly observed")
        if features.get("udp_burst_score", 0) >= 0.5:
            reasons.append("high-rate UDP burst observed")
        if features.get("ttl_anomaly_score", 0) >= 0.5:
            reasons.append("unexpected TTL variation observed")
        if features.get("payload_integrity_anomaly", 0) > 0:
            reasons.append("payload integrity mismatch metadata observed")
        if features.get("ip_spoofing_score", features.get("identity_anomaly_score", 0)) > 0:
            reasons.append("source identity mismatch metadata observed")
        if features.get("packet_alteration_score", 0) > 0:
            reasons.append("packet alteration or checksum mismatch metadata observed")
        if features.get("behavior_anomaly_score", 0) >= 0.5:
            reasons.append("packet behavior differs from the receive-side baseline")
        return {"risk_score": score, "risk_level": level, "confidence": max(0.0, 1.0 - fusion.get("model_disagreement", 0)),
                "reasons": reasons, "persistent": self.persistence.observe(key, score)}
