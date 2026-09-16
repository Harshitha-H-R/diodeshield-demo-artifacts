"""Comprehensive automated test suite for production network threat detection platform."""
from __future__ import annotations

import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

from diodeshield.api.main import app
from diodeshield.authentication.rbac import Role, create_access_token, verify_token
from diodeshield.capture.sniffer import list_network_interfaces
from diodeshield.configuration.settings import AppConfig, load_app_config
from diodeshield.correlation.correlator import CorrelationEngine
from diodeshield.decoder.packet import decode_scapy_packet, parse_tcp_flags
from diodeshield.detection.behavioral.detector import BehavioralDetector
from diodeshield.detection.engine import MultiLayerDetectionEngine
from diodeshield.detection.signatures.rules import SignatureEngine
from diodeshield.anomaly.baseline import AnomalyBaselineEngine, MetricBaseline
from diodeshield.feature_engine.extractor import calculate_entropy, extract_window_features
from diodeshield.flow_engine.tracker import FlowTracker
from diodeshield.schemas import TrafficEvent
from diodeshield.threat_intelligence.client import ThreatIntelClient


client = TestClient(app)


# --- 1. Dynamic Interface Discovery Tests ---

def test_interface_discovery():
    interfaces = list_network_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    first = interfaces[0]
    assert "name" in first
    assert "ipv4" in first
    assert "is_up" in first


# --- 2. Packet Decoder Tests ---

def test_packet_decoder_tcp():
    pkt = IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) / TCP(sport=54321, dport=80, flags="S")
    event = decode_scapy_packet(pkt, interface="eth0")
    assert event is not None
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.20"
    assert event.protocol == "TCP"
    assert event.src_port == 54321
    assert event.dst_port == 80
    assert "S" in (event.tcp_flags or "")
    assert event.data_source == "live_capture"


def test_packet_decoder_udp_dns():
    pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=43210, dport=53)
    event = decode_scapy_packet(pkt, interface="eth0")
    assert event is not None
    assert event.protocol == "UDP"
    assert event.dst_port == 53
    assert event.metadata.get("app_protocol") == "DNS"


# --- 3. Bidirectional Flow Engine Tests ---

def test_flow_tracker_bidirectional():
    tracker = FlowTracker(idle_timeout=10.0, active_timeout=60.0)

    # Forward packet
    e1 = TrafficEvent(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=80,
        protocol="TCP", packet_len=100, tcp_flags="S"
    )
    flow1 = tracker.process_event(e1)
    assert flow1.fwd_packets == 1
    assert flow1.bwd_packets == 0
    assert flow1.tcp_state == "SYN_SENT"

    # Backward packet (response)
    e2 = TrafficEvent(
        src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=50000,
        protocol="TCP", packet_len=200, tcp_flags="SA"
    )
    flow2 = tracker.process_event(e2)
    assert flow2.flow_id == flow1.flow_id  # Matched same session
    assert flow2.fwd_packets == 1
    assert flow2.bwd_packets == 1
    assert flow2.total_packets == 2
    assert flow2.total_bytes == 300
    assert flow2.tcp_state == "SYN_RCVD"


# --- 4. Feature Extraction Tests ---

def test_feature_extraction():
    now = datetime.now(timezone.utc)
    events = [
        TrafficEvent(timestamp=now, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, protocol="TCP", packet_len=100, tcp_flags="S"),
        TrafficEvent(timestamp=now, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=443, protocol="TCP", packet_len=200, tcp_flags="A"),
        TrafficEvent(timestamp=now, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=53, protocol="UDP", packet_len=80),
    ]
    feats = extract_window_features(events)
    assert feats["packets"] == 3
    assert feats["bytes"] == 380
    assert feats["unique_dst_ports"] == 3
    assert feats["tcp_ratio"] == round(2 / 3, 4)
    assert feats["udp_ratio"] == round(1 / 3, 4)
    assert calculate_entropy([80, 443, 53]) > 0


# --- 5. Signature Engine Tests ---

def test_signature_detection():
    sig_engine = SignatureEngine()

    # Xmas scan packet
    xmas = TrafficEvent(src_ip="192.168.1.50", dst_ip="192.168.1.1", protocol="TCP", tcp_flags="FPU", packet_len=60)
    matches = sig_engine.evaluate_packet(xmas)
    assert any(m["rule_id"] == "SIG-SCAN-001" for m in matches)

    # Null scan packet
    null_scan = TrafficEvent(src_ip="192.168.1.50", dst_ip="192.168.1.1", protocol="TCP", tcp_flags="", packet_len=40)
    matches = sig_engine.evaluate_packet(null_scan)
    assert any(m["rule_id"] == "SIG-SCAN-002" for m in matches)

    # Modbus single coil write (Function code 0x05)
    modbus_pkt = TrafficEvent(
        src_ip="192.168.1.50", dst_ip="192.168.1.10", dst_port=502, protocol="TCP",
        payload_hex="00010000000601050001ff00", packet_len=64
    )
    matches = sig_engine.evaluate_packet(modbus_pkt)
    assert any(m["rule_id"] == "SIG-OT-001" for m in matches)


# --- 6. Behavioral Detection Tests ---

def test_behavioral_port_scan():
    detector = BehavioralDetector()
    alerts = []
    # Probing 25 different destination ports
    for p in range(1, 26):
        evt = TrafficEvent(src_ip="10.0.0.99", dst_ip="10.0.0.1", dst_port=p, protocol="TCP", tcp_flags="S")
        res = detector.process_event(evt)
        alerts.extend(res)

    assert any(a["category"] == "PORT_SCAN" for a in alerts)


def test_behavioral_beaconing():
    detector = BehavioralDetector()
    alerts = []
    # Exact periodic interval (every 0.5s)
    t0 = time.time()
    for i in range(7):
        ts = datetime.fromtimestamp(t0 + (i * 0.5), tz=timezone.utc)
        evt = TrafficEvent(timestamp=ts, src_ip="10.0.0.55", dst_ip="198.51.100.4", dst_port=4444, protocol="TCP")
        res = detector.process_event(evt)
        alerts.extend(res)

    assert any(a["category"] == "BEACONING" for a in alerts)


# --- 7. Anomaly Baseline Tests ---

def test_anomaly_baseline():
    engine = AnomalyBaselineEngine()

    # Train baseline with normal rate
    for _ in range(25):
        engine.evaluate_observation({"pps": 10.0, "bps": 8000.0, "unique_dst_ports": 2, "syn_ratio": 0.1, "rst_ratio": 0.0, "burst_ratio": 1.0})

    # Sudden massive spike
    spike_eval = engine.evaluate_observation({"pps": 500.0, "bps": 500000.0, "unique_dst_ports": 50, "syn_ratio": 0.9, "rst_ratio": 0.8, "burst_ratio": 5.0})
    assert spike_eval["is_anomaly"] is True
    assert len(spike_eval["flagged_reasons"]) > 0


# --- 8. Threat Intelligence Tests ---

def test_threat_intel_local_private_filter():
    client = ThreatIntelClient()
    res = client.check_ip("192.168.1.1")
    assert res["is_malicious"] is False
    assert res["source"] == "LocalSubnetFilter"

    res_loopback = client.check_ip("127.0.0.1")
    assert res_loopback["is_malicious"] is False


# --- 9. Correlation Engine Tests ---

def test_correlation_engine():
    correlator = CorrelationEngine(dedup_window_seconds=5.0)

    sig1 = {
        "src_ip": "198.51.100.9", "dst_ip": "10.0.0.2", "category": "PORT_SCAN",
        "detection_method": "Signature Detection", "severity": "MEDIUM", "evidence": "Xmas Scan"
    }
    sig2 = {
        "src_ip": "198.51.100.9", "dst_ip": "10.0.0.2", "category": "PORT_SCAN",
        "detection_method": "Behavioral Detection", "severity": "HIGH", "evidence": "25 ports probed"
    }

    alerts1 = correlator.correlate([sig1])
    assert len(alerts1) == 1
    inc_id = alerts1[0]["incident_id"]

    # Second signal within window should deduplicate and upgrade
    alerts2 = correlator.correlate([sig2])
    assert len(alerts2) == 0  # Deduplicated into ongoing incident
    active = correlator.active_incidents[("198.51.100.9", "10.0.0.2", "PORT_SCAN")]
    assert active.incident_id == inc_id
    assert active.event_count == 2
    assert active.max_severity == "HIGH"
    assert "Behavioral Detection" in active.detection_methods
    assert "Signature Detection" in active.detection_methods


# --- 10. Authentication & RBAC Tests ---

def test_auth_rbac_tokens():
    token = create_access_token("analyst_user", role=Role.ANALYST)
    payload = verify_token(token)
    assert payload["sub"] == "analyst_user"
    assert payload["role"] == "ANALYST"


# --- 11. REST API Endpoints Verification ---

def test_api_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "diodeshield-soc"


def test_api_interfaces():
    resp = client.get("/api/interfaces")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_rules():
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) > 0
    assert any(r["rule_id"] == "SIG-SCAN-001" for r in rules)


def test_api_capture_stats():
    resp = client.get("/api/capture/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert "current_pps" in stats
    assert "current_bps" in stats


def test_api_system_metrics():
    resp = client.get("/api/system/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "process" in data
    assert "host" in data
