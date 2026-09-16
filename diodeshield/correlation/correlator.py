"""Security Event Correlation & Deduplication Engine."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class CorrelatedIncident:
    incident_id: str
    src_ip: str
    dst_ip: str
    first_seen: float
    last_seen: float
    primary_category: str
    max_severity: str
    confidence: float
    event_count: int = 1
    detection_methods: set[str] = field(default_factory=set)
    evidence_list: list[str] = field(default_factory=list)
    raw_signals: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "first_seen": datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "primary_category": self.primary_category,
            "max_severity": self.max_severity,
            "confidence": round(self.confidence, 3),
            "event_count": self.event_count,
            "detection_methods": sorted(self.detection_methods),
            "evidence": self.evidence_list[:10],
        }


SEVERITY_RANKS = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
REVERSE_SEVERITY = {v: k for k, v in SEVERITY_RANKS.items()}


class CorrelationEngine:
    """Correlates multiple disparate detection findings across sliding time windows."""

    def __init__(self, dedup_window_seconds: float = 10.0) -> None:
        self.dedup_window_seconds = dedup_window_seconds
        # Key: (src_ip, dst_ip, primary_category) -> CorrelatedIncident
        self.active_incidents: dict[tuple[str, str, str], CorrelatedIncident] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def correlate(self, signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ingest raw detection signals, deduplicate, aggregate into correlated events."""
        if not signals:
            return []

        now = time.time()
        correlated_alerts: list[dict[str, Any]] = []

        with self._lock:
            for sig in signals:
                src = sig.get("src_ip", "0.0.0.0")
                dst = sig.get("dst_ip", "0.0.0.0")
                category = sig.get("category", "ANOMALY")
                method = sig.get("detection_method", "Signature Detection")
                severity = sig.get("severity", "MEDIUM")
                evidence = sig.get("evidence", "")

                key = (src, dst, category)
                if key in self.active_incidents:
                    inc = self.active_incidents[key]
                    if now - inc.last_seen <= self.dedup_window_seconds:
                        # Deduplicate into ongoing incident
                        inc.last_seen = now
                        inc.event_count += 1
                        inc.detection_methods.add(method)
                        if evidence and evidence not in inc.evidence_list:
                            inc.evidence_list.append(evidence)
                        inc.raw_signals.append(sig)

                        # Upgrade severity if higher
                        current_rank = SEVERITY_RANKS.get(inc.max_severity, 2)
                        new_rank = SEVERITY_RANKS.get(severity, 2)
                        if new_rank > current_rank:
                            inc.max_severity = severity

                        # Multi-method confidence boost
                        base_conf = 0.70 + (0.08 * len(inc.detection_methods))
                        inc.confidence = min(0.99, base_conf)
                        continue

                # Create new incident
                inc_id = f"inc_{uuid.uuid4().hex[:12]}"
                new_inc = CorrelatedIncident(
                    incident_id=inc_id,
                    src_ip=src,
                    dst_ip=dst,
                    first_seen=now,
                    last_seen=now,
                    primary_category=category,
                    max_severity=severity,
                    confidence=0.75,
                    event_count=1,
                    detection_methods={method},
                    evidence_list=[evidence] if evidence else [],
                    raw_signals=[sig],
                )
                self.active_incidents[key] = new_inc
                correlated_alerts.append(new_inc.to_dict())

            # Periodic cleanup of old incidents
            if now - self._last_cleanup > 30.0:
                self._last_cleanup = now
                expired = [k for k, inc in self.active_incidents.items() if now - inc.last_seen > 60.0]
                for k in expired:
                    del self.active_incidents[k]

        return correlated_alerts
