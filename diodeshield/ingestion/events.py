from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from diodeshield.schemas import TrafficEvent


def parse_event(value: str | bytes | dict[str, Any]) -> TrafficEvent:
    if isinstance(value, (str, bytes)):
        value = json.loads(value)
    return TrafficEvent.model_validate(value)


def parse_jsonl(lines: Iterable[str]) -> Iterable[TrafficEvent]:
    for line in lines:
        if line.strip():
            try:
                yield parse_event(line)
            except (ValueError, TypeError):
                continue


def tshark_row(row: dict[str, Any]) -> TrafficEvent:
    """Map a tshark -T json/fields row without requiring tshark at runtime."""
    ts = row.get("frame.time_epoch") or row.get("timestamp")
    try:
        timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts else datetime.now(timezone.utc)
    except (TypeError, ValueError, OSError):
        timestamp = datetime.now(timezone.utc)
    metadata = {
        key: value for key, value in row.items()
        if not any(token in key.lower() for token in ("payload", "data.data", "tcp.segment_data"))
    }
    checksum_status = str(row.get("ip.checksum.status") or row.get("tcp.checksum.status")
                          or row.get("udp.checksum.status") or "").lower()
    if checksum_status in {"bad", "invalid", "0", "false"}:
        metadata["checksum_valid"] = False
    return TrafficEvent(timestamp=timestamp, src_ip=row.get("ip.src", "0.0.0.0"),
                        dst_ip=row.get("ip.dst", "0.0.0.0"),
                        src_port=_integer(row.get("tcp.srcport") or row.get("udp.srcport")),
                        dst_port=_integer(row.get("tcp.dstport") or row.get("udp.dstport")),
                        protocol=str(row.get("_ws.col.Protocol") or row.get("protocol", "TCP")),
                        packet_len=_integer(row.get("frame.len")) or 0,
                        ttl=_integer(row.get("ip.ttl")), ip_id=_integer(row.get("ip.id")),
                        data_source="tshark", metadata=metadata)


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
