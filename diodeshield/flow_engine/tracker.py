"""Real-time bidirectional network flow tracking and session reconstruction engine."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from diodeshield.schemas import TrafficEvent


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_lengths: list[int] = field(default_factory=list)
    bwd_lengths: list[int] = field(default_factory=list)
    inter_arrival_times: list[float] = field(default_factory=list)
    tcp_state: str = "UNKNOWN"
    flags_seen: set[str] = field(default_factory=set)
    app_protocol: str | None = None
    tls_sni: str | None = None
    dns_query: str | None = None
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def packets_per_second(self) -> float:
        dur = self.duration_seconds
        return round(self.total_packets / dur, 2) if dur > 0 else float(self.total_packets)

    @property
    def bytes_per_second(self) -> float:
        dur = self.duration_seconds
        return round(self.total_bytes / dur, 2) if dur > 0 else float(self.total_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": round(self.duration_seconds, 3),
            "start_time": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "pps": self.packets_per_second,
            "bps": self.bytes_per_second,
            "tcp_state": self.tcp_state,
            "app_protocol": self.app_protocol,
            "tls_sni": self.tls_sni,
            "dns_query": self.dns_query,
            "flags": "".join(sorted(self.flags_seen)),
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
        }


def make_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> tuple[str, str, int, int, str]:
    """Symmetric canonical 5-tuple key for bidirectional matching."""
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    return (dst_ip, src_ip, dst_port, src_port, protocol)


class FlowTracker:
    """Manages active and historical network flow sessions with automatic expiration."""

    def __init__(
        self,
        idle_timeout: float = 60.0,
        active_timeout: float = 300.0,
        max_active_flows: int = 10000,
    ) -> None:
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_active_flows = max_active_flows
        self.active_flows: dict[tuple[str, str, int, int, str], FlowRecord] = {}
        self.completed_flows: list[FlowRecord] = []
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def process_event(self, event: TrafficEvent) -> FlowRecord:
        now = event.timestamp.timestamp() if hasattr(event.timestamp, "timestamp") else time.time()
        sport = event.src_port or 0
        dport = event.dst_port or 0
        proto = event.protocol.upper()
        canonical_key = make_flow_key(event.src_ip, event.dst_ip, sport, dport, proto)

        with self._lock:
            if canonical_key in self.active_flows:
                flow = self.active_flows[canonical_key]
                is_fwd = (event.src_ip == flow.src_ip and sport == flow.src_port)
            else:
                flow_id = f"flow_{int(now * 1000)}_{sport}_{dport}"
                flow = FlowRecord(
                    flow_id=flow_id,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    start_time=now,
                    last_seen=now,
                )
                self.active_flows[canonical_key] = flow
                is_fwd = True

            # Calculate inter-arrival time
            iat = max(0.0, now - flow.last_seen)
            if len(flow.inter_arrival_times) < 100:
                flow.inter_arrival_times.append(iat)
            flow.last_seen = now

            # Update byte and packet counters
            size = event.packet_len or 0
            if is_fwd:
                flow.fwd_packets += 1
                flow.fwd_bytes += size
                if len(flow.fwd_lengths) < 50:
                    flow.fwd_lengths.append(size)
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += size
                if len(flow.bwd_lengths) < 50:
                    flow.bwd_lengths.append(size)

            # Metadata propagation
            meta = event.metadata or {}
            if meta.get("app_protocol"):
                flow.app_protocol = meta["app_protocol"]
            if meta.get("tls_sni"):
                flow.tls_sni = meta["tls_sni"]
            if meta.get("dns_query"):
                flow.dns_query = meta["dns_query"]

            # TCP state tracking
            if proto == "TCP" and event.tcp_flags:
                for ch in event.tcp_flags:
                    flow.flags_seen.add(ch)

                if "S" in event.tcp_flags and "A" not in event.tcp_flags:
                    flow.syn_count += 1
                    flow.tcp_state = "SYN_SENT"
                elif "S" in event.tcp_flags and "A" in event.tcp_flags:
                    flow.syn_count += 1
                    flow.ack_count += 1
                    flow.tcp_state = "SYN_RCVD"
                elif "R" in event.tcp_flags:
                    flow.rst_count += 1
                    flow.tcp_state = "RESET"
                elif "F" in event.tcp_flags:
                    flow.fin_count += 1
                    flow.tcp_state = "FIN_WAIT"
                elif "A" in event.tcp_flags and flow.tcp_state in ("SYN_RCVD", "UNKNOWN"):
                    flow.ack_count += 1
                    flow.tcp_state = "ESTABLISHED"

            # Periodic cleanup
            if now - self._last_cleanup > 5.0:
                self._cleanup_expired_locked(now)

            return flow

    def _cleanup_expired_locked(self, now: float) -> None:
        self._last_cleanup = now
        expired_keys = []
        for key, flow in self.active_flows.items():
            idle = now - flow.last_seen
            active = now - flow.start_time
            if idle > self.idle_timeout or active > self.active_timeout or flow.tcp_state in ("RESET", "CLOSED"):
                expired_keys.append(key)

        for key in expired_keys:
            flow = self.active_flows.pop(key)
            self.completed_flows.append(flow)

        # Cap completed flows ring buffer
        if len(self.completed_flows) > 5000:
            self.completed_flows = self.completed_flows[-5000:]

    def get_active_flows(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            flows = sorted(self.active_flows.values(), key=lambda f: f.last_seen, reverse=True)
            return [f.to_dict() for f in flows[:limit]]

    def get_flow_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_flow_count": len(self.active_flows),
                "completed_flow_count": len(self.completed_flows),
            }
