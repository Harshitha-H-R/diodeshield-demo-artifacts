from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from diodeshield.schemas import TrafficEvent


def generate_synthetic(scenario: str = "normal", count: int = 30, seed: int = 7) -> Iterator[TrafficEvent]:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc)
    for i in range(count):
        if scenario == "recon":
            dst = f"10.0.0.{(i % 20) + 10}"
            port = 502 if i % 2 else 80
        elif scenario == "protocol":
            dst, port = "10.0.0.20", 502
        elif scenario == "beacon":
            dst, port = "10.0.0.20", 4444
        else:
            dst, port = "10.0.0.20", 502
        payload = None
        if scenario == "protocol":
            # Reserved function code demonstrates protocol evidence safely.
            payload = "000100000006015a00000001"
        yield TrafficEvent(timestamp=start + timedelta(seconds=i * (0.2 if scenario == "recon" else 1.0) + (rng.random() * 0.02 if scenario != "normal" else 0)),
                            src_ip="10.0.0.10", dst_ip=dst, src_port=40000 + i % 3, dst_port=port,
                            protocol="TCP", packet_len=rng.randint(60, 220), ttl=64, ip_id=i,
                            payload_hex=payload, data_source="synthetic", asset_id="PLC-001")
