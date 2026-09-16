"""Network packet decoder supporting Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, and TLS SNI."""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from diodeshield.schemas import TrafficEvent


def parse_tcp_flags(flags_val: Any) -> tuple[str, dict[str, bool]]:
    """Convert TCP flags to string notation (e.g. 'S', 'SA', 'FA', 'R') and boolean map."""
    flag_map = {"F": False, "S": False, "R": False, "P": False, "A": False, "U": False}
    if flags_val is None:
        return "", flag_map

    s = str(flags_val).upper()
    flag_str = ""
    for char in ["F", "S", "R", "P", "A", "U"]:
        if char in s or (isinstance(flags_val, int) and (
            (char == "F" and flags_val & 0x01) or
            (char == "S" and flags_val & 0x02) or
            (char == "R" and flags_val & 0x04) or
            (char == "P" and flags_val & 0x08) or
            (char == "A" and flags_val & 0x10) or
            (char == "U" and flags_val & 0x20)
        )):
            flag_map[char] = True
            flag_str += char

    return flag_str, flag_map


def extract_tls_sni(payload_bytes: bytes) -> str | None:
    """Extract Server Name Indication (SNI) from TLS ClientHello without decrypting."""
    try:
        if len(payload_bytes) < 44:
            return None
        # TLS Handshake ContentType == 22, Handshake Type == 1 (ClientHello)
        if payload_bytes[0] != 0x16 or payload_bytes[5] != 0x01:
            return None

        pos = 43  # Skip record header (5) + handshake header (4) + client_version (2) + random (32)
        if pos >= len(payload_bytes):
            return None

        # Session ID length
        session_id_len = payload_bytes[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload_bytes):
            return None

        # Cipher suites length
        cipher_suites_len = struct.unpack("!H", payload_bytes[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload_bytes):
            return None

        # Compression methods length
        comp_methods_len = payload_bytes[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload_bytes):
            return None

        # Extensions length
        extensions_len = struct.unpack("!H", payload_bytes[pos:pos + 2])[0]
        pos += 2
        end = min(pos + extensions_len, len(payload_bytes))

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload_bytes[pos:pos + 4])
            pos += 4
            if ext_type == 0:  # server_name extension
                if pos + 5 <= end:
                    list_len = struct.unpack("!H", payload_bytes[pos:pos + 2])[0]
                    name_type = payload_bytes[pos + 2]
                    name_len = struct.unpack("!H", payload_bytes[pos + 3:pos + 5])[0]
                    if name_type == 0 and pos + 5 + name_len <= end:
                        return payload_bytes[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None


def decode_scapy_packet(
    pkt: Packet,
    interface: str = "unknown",
    local_ips: set[str] | None = None,
) -> TrafficEvent | None:
    """Decode a live Scapy packet into a standardized TrafficEvent with rich metadata."""
    try:
        # Determine IP layer (v4 or v6)
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        ttl = None
        ip_id = None
        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags_str = None
        meta: dict[str, Any] = {"interface": interface}

        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(ip_layer.ttl)
            ip_id = int(ip_layer.id)
            meta["ip_version"] = 4
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(ip_layer.hlim)
            meta["ip_version"] = 6
        else:
            return None  # Non-IP packets (e.g. ARP, STP) skipped for IP flow analysis

        # Determine Direction if local IPs known
        if local_ips:
            if src_ip in local_ips and dst_ip in local_ips:
                meta["direction"] = "LOCAL"
            elif src_ip in local_ips:
                meta["direction"] = "OUTBOUND"
            elif dst_ip in local_ips:
                meta["direction"] = "INBOUND"
            else:
                meta["direction"] = "TRANSIT"
        else:
            meta["direction"] = "UNKNOWN"

        # Transport layer decoding
        payload_bytes = bytes(pkt.payload.payload.payload) if hasattr(pkt, "payload") else b""

        if TCP in pkt:
            tcp = pkt[TCP]
            protocol = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags_str, flag_map = parse_tcp_flags(tcp.flags)
            meta["tcp_flags_map"] = flag_map
            meta["tcp_window"] = int(tcp.window)
            meta["tcp_seq"] = int(tcp.seq)
            meta["tcp_ack"] = int(tcp.ack)

            # Check for TLS SNI on common TLS ports or TLS handshake headers
            if dst_port in (443, 8443) or src_port in (443, 8443) or payload_bytes.startswith(b"\x16\x03"):
                sni = extract_tls_sni(payload_bytes)
                if sni:
                    meta["tls_sni"] = sni

            # Protocol hints
            if dst_port == 502 or src_port == 502:
                meta["app_protocol"] = "MODBUS_TCP"
            elif dst_port == 20000 or src_port == 20000:
                meta["app_protocol"] = "DNP3"
            elif dst_port == 2404 or src_port == 2404:
                meta["app_protocol"] = "IEC104"
            elif dst_port == 102 or src_port == 102:
                meta["app_protocol"] = "S7COMM"
            elif dst_port in (80, 8080) or src_port in (80, 8080):
                meta["app_protocol"] = "HTTP"
            elif dst_port in (443, 8443) or src_port in (443, 8443):
                meta["app_protocol"] = "HTTPS"
            elif dst_port == 22 or src_port == 22:
                meta["app_protocol"] = "SSH"
            elif dst_port == 3389 or src_port == 3389:
                meta["app_protocol"] = "RDP"

        elif UDP in pkt:
            udp = pkt[UDP]
            protocol = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)

            # DNS Inspection
            if DNS in pkt:
                dns = pkt[DNS]
                meta["app_protocol"] = "DNS"
                if dns.qr == 0 and DNSQR in dns:  # DNS Query
                    qname = dns[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    meta["dns_query"] = qname
                    meta["dns_qtype"] = int(dns[DNSQR].qtype)
                elif dns.qr == 1:  # DNS Response
                    meta["dns_rcode"] = int(dns.rcode)
            elif dst_port == 53 or src_port == 53:
                meta["app_protocol"] = "DNS"
            elif dst_port in (123, 161, 162, 514):
                meta["app_protocol"] = {123: "NTP", 161: "SNMP", 162: "SNMP-TRAP", 514: "SYSLOG"}[dst_port]

        elif ICMP in pkt:
            icmp = pkt[ICMP]
            protocol = "ICMP"
            meta["icmp_type"] = int(icmp.type)
            meta["icmp_code"] = int(icmp.code)

        packet_len = len(pkt)
        timestamp = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc) if hasattr(pkt, "time") else datetime.now(timezone.utc)

        return TrafficEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_len=packet_len,
            ttl=ttl,
            ip_id=ip_id,
            tcp_flags=tcp_flags_str,
            data_source="live_capture",
            metadata=meta,
        )
    except Exception:
        return None
