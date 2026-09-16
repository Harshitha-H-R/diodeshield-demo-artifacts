"""Production signature-based detection engine with versioned rules and ATT&CK mappings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diodeshield.schemas import TrafficEvent


@dataclass
class SignatureRule:
    rule_id: str
    name: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    version: str = "1.0.0"
    enabled: bool = True
    mitre_technique: str = ""
    cve: str = ""
    source: str = "DIODESHIELD-Core-Signatures"


class SignatureEngine:
    """Evaluates individual packets and flow events against versioned deterministic signatures."""

    def __init__(self) -> None:
        self.rules: dict[str, SignatureRule] = {}
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        default_rules = [
            SignatureRule(
                rule_id="SIG-SCAN-001",
                name="TCP Xmas Scan Detected",
                description="Packet observed with FIN, PSH, and URG flags set simultaneously (RFC 793 violation).",
                severity="HIGH",
                category="RECONNAISSANCE",
                mitre_technique="T1046",
            ),
            SignatureRule(
                rule_id="SIG-SCAN-002",
                name="TCP Null Scan Detected",
                description="TCP packet observed with zero flags set, indicating active OS fingerprinting probe.",
                severity="MEDIUM",
                category="RECONNAISSANCE",
                mitre_technique="T1046",
            ),
            SignatureRule(
                rule_id="SIG-SCAN-003",
                name="TCP SYN-FIN Scan Probe",
                description="TCP packet with illegal SYN and FIN flags set simultaneously.",
                severity="HIGH",
                category="RECONNAISSANCE",
                mitre_technique="T1046",
            ),
            SignatureRule(
                rule_id="SIG-DOS-001",
                name="TCP SYN-Flood Pattern",
                description="High-frequency TCP connection request with SYN flag without ACK completion.",
                severity="HIGH",
                category="DENIAL_OF_SERVICE",
                mitre_technique="T1498",
            ),
            SignatureRule(
                rule_id="SIG-OT-001",
                name="Unauthorized Modbus Coil Modification",
                description="Modbus TCP command attempting Write Single Coil (0x05) or Write Multiple (0x0F).",
                severity="CRITICAL",
                category="OT_INTEGRITY_VIOLATION",
                mitre_technique="T0855",
            ),
            SignatureRule(
                rule_id="SIG-OT-002",
                name="Industrial Protocol Stop Command (S7comm)",
                description="Industrial PLC stop execution request detected on port 102.",
                severity="CRITICAL",
                category="OT_INTEGRITY_VIOLATION",
                mitre_technique="T0816",
            ),
            SignatureRule(
                rule_id="SIG-NET-001",
                name="Cleartext Telnet Administration Detected",
                description="Insecure remote administration connection attempted on port 23.",
                severity="MEDIUM",
                category="INSECURE_PROTOCOL",
                mitre_technique="T1021",
            ),
        ]
        for r in default_rules:
            self.rules[r.rule_id] = r

    def evaluate_packet(self, event: TrafficEvent) -> list[dict[str, Any]]:
        """Match packet attributes against enabled signatures."""
        matches: list[dict[str, Any]] = []
        flags = event.tcp_flags or ""
        dport = event.dst_port or 0
        sport = event.src_port or 0
        proto = event.protocol.upper()

        # SIG-SCAN-001: Xmas Scan (F, P, U)
        r = self.rules.get("SIG-SCAN-001")
        if r and r.enabled and proto == "TCP" and "F" in flags and "P" in flags and "U" in flags:
            matches.append(self._make_match(r, event, f"TCP flags: {flags}"))

        # SIG-SCAN-002: Null Scan (no flags on TCP packet)
        r = self.rules.get("SIG-SCAN-002")
        if r and r.enabled and proto == "TCP" and flags == "" and event.packet_len > 0:
            matches.append(self._make_match(r, event, "TCP packet has zero flags"))

        # SIG-SCAN-003: SYN-FIN probe
        r = self.rules.get("SIG-SCAN-003")
        if r and r.enabled and proto == "TCP" and "S" in flags and "F" in flags:
            matches.append(self._make_match(r, event, f"Illegal TCP flag combination: {flags}"))

        # SIG-OT-001: Modbus Write
        r = self.rules.get("SIG-OT-001")
        if r and r.enabled and (dport == 502 or sport == 502) and event.payload_hex:
            # Modbus TCP header is 7 bytes, function code is byte 8 (index 14..16 in hex)
            if len(event.payload_hex) >= 16:
                try:
                    fc = int(event.payload_hex[14:16], 16)
                    if fc in (0x05, 0x06, 0x0F, 0x10):
                        matches.append(self._make_match(r, event, f"Modbus Write Function Code 0x{fc:02X}"))
                except ValueError:
                    pass

        # SIG-OT-002: S7comm Stop CPU on port 102
        r = self.rules.get("SIG-OT-002")
        if r and r.enabled and (dport == 102 or sport == 102) and event.payload_hex:
            # Check S7comm stop function (0x29) in payload
            if "29000000000009" in event.payload_hex.lower() or "stop" in event.payload_hex.lower():
                matches.append(self._make_match(r, event, "S7comm Stop CPU command sequence"))

        # SIG-NET-001: Telnet 23
        r = self.rules.get("SIG-NET-001")
        if r and r.enabled and (dport == 23 or sport == 23):
            matches.append(self._make_match(r, event, f"Cleartext telnet connection {event.src_ip} -> {event.dst_ip}:23"))

        return matches

    def _make_match(self, rule: SignatureRule, event: TrafficEvent, evidence: str) -> dict[str, Any]:
        return {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "rule_version": rule.version,
            "description": rule.description,
            "severity": rule.severity,
            "category": rule.category,
            "mitre_technique": rule.mitre_technique,
            "cve": rule.cve,
            "source": rule.source,
            "evidence": evidence,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
        }

    def list_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "category": r.category,
                "version": r.version,
                "enabled": r.enabled,
                "mitre_technique": r.mitre_technique,
            }
            for r in self.rules.values()
        ]
