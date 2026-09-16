"""Production command-line interface for DIODESHIELD."""
from __future__ import annotations

import argparse
import json
import sys
import time

from diodeshield.capture.sniffer import LiveNetworkCapture, list_network_interfaces
from diodeshield.configuration.settings import load_app_config
from diodeshield.db import Repository
from diodeshield.pipeline import DetectionPipeline
from diodeshield.threat_intelligence.client import ThreatIntelClient


def main() -> None:
    parser = argparse.ArgumentParser(description="DIODESHIELD Production CLI")
    parser.add_argument("--list-interfaces", action="store_true", help="List all host network interfaces")
    parser.add_argument("--check-integrity", action="store_true", help="Verify SHA-256 tamper-evident hash chain")
    parser.add_argument("--threat-intel", type=str, metavar="IP", help="Check IP threat intelligence reputation")
    parser.add_argument("--capture", action="store_true", help="Start real-time live capture in foreground")
    parser.add_argument("--interface", type=str, default="auto", help="Interface name or ID for capture")
    parser.add_argument("--db-metrics", action="store_true", help="Show database metrics and alert counts")

    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = list_network_interfaces()
        print(json.dumps(ifaces, indent=2))
        return

    if args.check_integrity:
        repo = Repository()
        res = repo.verify_integrity()
        print(json.dumps(res, indent=2))
        return

    if args.threat_intel:
        client = ThreatIntelClient()
        res = client.check_ip(args.threat_intel)
        print(json.dumps(res, indent=2))
        return

    if args.db_metrics:
        repo = Repository()
        print(json.dumps(repo.metrics(), indent=2))
        return

    if args.capture:
        print(f"[*] Starting DIODESHIELD live network capture on interface: {args.interface}")
        app_cfg = load_app_config()
        repo = Repository(app_cfg.database_path)
        pipeline = DetectionPipeline(repo)

        def on_event(event):
            print(f"[{event.timestamp.strftime('%H:%M:%S')}] {event.protocol} {event.src_ip}:{event.src_port or '*'} -> {event.dst_ip}:{event.dst_port or '*'} ({event.packet_len}B)")

        capture = LiveNetworkCapture(
            interface=args.interface,
            on_event_callback=lambda evt: [on_event(evt), pipeline.ingest(evt)],
        )
        capture.start()
        print("[*] Capture running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1.0)
                stats = capture.stats.to_dict()
                sys.stdout.write(f"\rPackets: {stats['total_packets_received']} | PPS: {stats['current_pps']} | BPS: {stats['current_bps']} | Dropped: {stats['total_packets_dropped']}")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n[*] Stopping capture...")
            capture.stop()
            print("[*] Stopped.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
