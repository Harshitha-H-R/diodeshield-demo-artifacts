"""Behavioral detection engine tracking port scans, host sweeps, C2 beaconing, and connection bursts."""
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Any

import numpy as np

from diodeshield.configuration.settings import DetectionSettings
from diodeshield.schemas import TrafficEvent


class BehavioralDetector:
    """Tracks stateful entity behaviors across sliding time windows on real observed traffic."""

    def __init__(self, settings: DetectionSettings | None = None) -> None:
        self.settings = settings or DetectionSettings()
        # IP -> list of (timestamp, dst_ip, dst_port, protocol, flags)
        self._host_activity: dict[str, list[tuple[float, str, int, str, str]]] = defaultdict(list)
        # Flow key -> list of packet timestamps
        self._flow_timestamps: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def process_event(self, event: TrafficEvent) -> list[dict[str, Any]]:
        """Process a single real traffic event and evaluate behavioral indicators."""
        now = event.timestamp.timestamp() if hasattr(event.timestamp, "timestamp") else time.time()
        src = event.src_ip
        dst = event.dst_ip
        dport = event.dst_port or 0
        proto = event.protocol.upper()
        flags = event.tcp_flags or ""

        alerts: list[dict[str, Any]] = []

        with self._lock:
            # Append activity
            self._host_activity[src].append((now, dst, dport, proto, flags))
            flow_key = (src, dst, dport)
            self._flow_timestamps[flow_key].append(now)

            # Prune activity older than 10 seconds
            cutoff = now - 10.0
            self._host_activity[src] = [x for x in self._host_activity[src] if x[0] >= cutoff]
            self._flow_timestamps[flow_key] = [t for t in self._flow_timestamps[flow_key] if t >= cutoff]

            history = self._host_activity[src]

            # 1. Vertical Port Scan Detection: Single source hitting > threshold unique ports on one destination
            dst_ports_map = defaultdict(set)
            for t, d_ip, d_p, pr, fl in history:
                if now - t <= self.settings.port_scan_window_seconds:
                    dst_ports_map[d_ip].add(d_p)

            for target_ip, ports in dst_ports_map.items():
                if len(ports) >= self.settings.port_scan_threshold_ports:
                    alerts.append({
                        "category": "PORT_SCAN",
                        "detection_method": "Behavioral Detection",
                        "severity": "HIGH",
                        "src_ip": src,
                        "dst_ip": target_ip,
                        "protocol": proto,
                        "evidence": f"Host probed {len(ports)} unique destination ports on {target_ip} within {self.settings.port_scan_window_seconds}s (Threshold: {self.settings.port_scan_threshold_ports})",
                        "score": 0.85,
                        "timestamp": now,
                    })

            # 2. Horizontal Host Sweep: Single source contacting > threshold unique hosts on same port
            port_hosts_map = defaultdict(set)
            for t, d_ip, d_p, pr, fl in history:
                if now - t <= self.settings.host_sweep_window_seconds:
                    port_hosts_map[d_p].add(d_ip)

            for target_port, hosts in port_hosts_map.items():
                if len(hosts) >= self.settings.host_sweep_threshold_hosts:
                    alerts.append({
                        "category": "NETWORK_SWEEP",
                        "detection_method": "Behavioral Detection",
                        "severity": "HIGH",
                        "src_ip": src,
                        "dst_ip": "multiple",
                        "dst_port": target_port,
                        "protocol": proto,
                        "evidence": f"Host swept {len(hosts)} distinct IP addresses on port {target_port} within {self.settings.host_sweep_window_seconds}s",
                        "score": 0.80,
                        "timestamp": now,
                    })

            # 3. C2 Beaconing (Periodicity & Low Jitter)
            timestamps = self._flow_timestamps[flow_key]
            if len(timestamps) >= self.settings.c2_beacon_min_intervals:
                intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
                mean_int = float(np.mean(intervals))
                std_int = float(np.std(intervals))
                if mean_int > 0.2:  # Periodic rather than continuous line-rate burst
                    jitter_cv = std_int / mean_int
                    if jitter_cv < self.settings.c2_beacon_max_jitter:
                        alerts.append({
                            "category": "BEACONING",
                            "detection_method": "Behavioral Detection",
                            "severity": "HIGH",
                            "src_ip": src,
                            "dst_ip": dst,
                            "dst_port": dport,
                            "protocol": proto,
                            "evidence": f"Regular periodic communication detected ({len(intervals)} intervals, mean={mean_int:.2f}s, jitter_cv={jitter_cv:.3f} < {self.settings.c2_beacon_max_jitter})",
                            "score": 0.88,
                            "timestamp": now,
                        })

            # 4. Failed Connection Storm (RST or Unanswered SYN burst)
            rst_count = sum(1 for _, _, _, _, fl in history if "R" in fl)
            if rst_count >= 25:
                alerts.append({
                    "category": "CONNECTION_ANOMALY",
                    "detection_method": "Behavioral Detection",
                    "severity": "MEDIUM",
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": "TCP",
                    "evidence": f"Excessive connection resets ({rst_count} TCP RST packets in < 10s)",
                    "score": 0.65,
                    "timestamp": now,
                })

            # Periodic cleanup of inactive hosts
            if now - self._last_cleanup > 30.0:
                self._last_cleanup = now
                dead_hosts = [h for h, acts in self._host_activity.items() if not acts]
                for h in dead_hosts:
                    del self._host_activity[h]
                dead_flows = [k for k, ts in self._flow_timestamps.items() if not ts]
                for k in dead_flows:
                    del self._flow_timestamps[k]

        return alerts
