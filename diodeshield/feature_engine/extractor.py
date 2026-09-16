"""Production feature extraction engine for flow windows and host behavior."""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime
from typing import Any

import numpy as np

from diodeshield.schemas import TrafficEvent


def calculate_entropy(items: list[Any]) -> float:
    """Calculate Shannon entropy for a list of discrete items (e.g. ports, IPs)."""
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_window_features(events: list[TrafficEvent]) -> dict[str, Any]:
    """Extract comprehensive statistical, volumetric, spatial, and temporal features from a packet batch."""
    if not events:
        return {
            "packets": 0,
            "bytes": 0,
            "pps": 0.0,
            "bps": 0.0,
            "duration": 0.0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_dst_ports": 0,
            "tcp_ratio": 0.0,
            "udp_ratio": 0.0,
            "icmp_ratio": 0.0,
            "syn_ratio": 0.0,
            "rst_ratio": 0.0,
            "mean_len": 0.0,
            "std_len": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "beacon_jitter_cv": 0.0,
            "port_entropy": 0.0,
            "dominant_frequency": 0.0,
            "burst_ratio": 0.0,
        }

    total_packets = len(events)
    total_bytes = sum(e.packet_len or 0 for e in events)

    # Time and Duration
    timestamps = [e.timestamp.timestamp() if hasattr(e.timestamp, "timestamp") else 0.0 for e in events]
    timestamps.sort()
    t_start = timestamps[0]
    t_end = timestamps[-1]
    duration = max(0.001, t_end - t_start)
    pps = round(total_packets / duration, 2)
    bps = round((total_bytes * 8) / duration, 2)

    # Inter-Arrival Times (IAT)
    iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    if iats:
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        beacon_jitter_cv = round(iat_std / iat_mean, 4) if iat_mean > 0 else 0.0
    else:
        iat_mean, iat_std, beacon_jitter_cv = 0.0, 0.0, 0.0

    # Packet Length Stats
    lens = [e.packet_len or 0 for e in events]
    mean_len = float(np.mean(lens))
    std_len = float(np.std(lens))

    # Protocol Distribution
    proto_counts = Counter(e.protocol.upper() for e in events)
    tcp_count = proto_counts.get("TCP", 0)
    udp_count = proto_counts.get("UDP", 0)
    icmp_count = proto_counts.get("ICMP", 0)
    tcp_ratio = round(tcp_count / total_packets, 4)
    udp_ratio = round(udp_count / total_packets, 4)
    icmp_ratio = round(icmp_count / total_packets, 4)

    # TCP Flags
    syn_count = 0
    rst_count = 0
    ack_count = 0
    for e in events:
        flags = e.tcp_flags or ""
        if "S" in flags:
            syn_count += 1
        if "R" in flags:
            rst_count += 1
        if "A" in flags:
            ack_count += 1

    syn_ratio = round(syn_count / max(1, tcp_count), 4)
    rst_ratio = round(rst_count / max(1, tcp_count), 4)

    # Spatial Distribution
    src_ips = [e.src_ip for e in events]
    dst_ips = [e.dst_ip for e in events]
    dst_ports = [e.dst_port for e in events if e.dst_port is not None]

    unique_src_ips = len(set(src_ips))
    unique_dst_ips = len(set(dst_ips))
    unique_dst_ports = len(set(dst_ports))
    port_entropy = calculate_entropy(dst_ports)

    # Burst Ratio (Peak rate over 100ms sub-window vs average)
    bins: dict[int, int] = Counter()
    for t in timestamps:
        bin_idx = int((t - t_start) * 10)  # 100ms bins
        bins[bin_idx] += 1
    max_bin_count = max(bins.values()) if bins else 1
    avg_bin_count = max(1.0, total_packets / max(1, len(bins)))
    burst_ratio = round(max_bin_count / avg_bin_count, 3)

    # Spectral / FFT Dominant Frequency
    dominant_frequency = 0.0
    if len(events) >= 8 and duration > 0:
        try:
            # Resample packet arrivals into uniform 100Hz time series
            num_samples = min(256, max(16, int(duration * 50)))
            time_bins = np.linspace(t_start, t_end, num_samples)
            hist, _ = np.histogram(timestamps, bins=num_samples)
            fft_vals = np.abs(np.fft.rfft(hist - np.mean(hist)))
            freqs = np.fft.rfftfreq(num_samples, d=(duration / num_samples))
            if len(fft_vals) > 1:
                peak_idx = int(np.argmax(fft_vals[1:])) + 1
                dominant_frequency = round(float(freqs[peak_idx]), 3)
        except Exception:
            pass

    return {
        "packets": total_packets,
        "bytes": total_bytes,
        "duration": round(duration, 3),
        "pps": pps,
        "bps": bps,
        "unique_src_ips": unique_src_ips,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "icmp_ratio": icmp_ratio,
        "syn_ratio": syn_ratio,
        "rst_ratio": rst_ratio,
        "mean_len": round(mean_len, 2),
        "std_len": round(std_len, 2),
        "iat_mean": round(iat_mean, 4),
        "iat_std": round(iat_std, 4),
        "beacon_jitter_cv": beacon_jitter_cv,
        "port_entropy": port_entropy,
        "dominant_frequency": dominant_frequency,
        "burst_ratio": burst_ratio,
    }
