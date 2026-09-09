from __future__ import annotations

import csv
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from diodeshield.schemas import TrafficEvent


def read_zeek_conn(path: str | Path) -> Iterator[TrafficEvent]:
    """Read a Zeek conn.log TSV export without retaining raw payloads."""
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        fieldnames: list[str] | None = None
        data_lines: list[str] = []
        for line in fh:
            if line.startswith("#fields"):
                fieldnames = line.rstrip("\n").split("\t")[1:]
            elif not line.startswith("#") and line.strip():
                data_lines.append(line)
        rows = csv.DictReader(data_lines, fieldnames=fieldnames or
                              ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                               "proto", "service", "duration", "orig_bytes", "resp_bytes"], delimiter="\t")
        for row in rows:
            try:
                timestamp = datetime.fromtimestamp(float(row.get("ts", 0)), timezone.utc)
            except (TypeError, ValueError, OSError):
                timestamp = datetime.now(timezone.utc)
            orig_bytes = _int(row.get("orig_bytes"))
            resp_bytes = _int(row.get("resp_bytes"))
            yield TrafficEvent(timestamp=timestamp, src_ip=row.get("id.orig_h", "0.0.0.0"),
                                dst_ip=row.get("id.resp_h", "0.0.0.0"),
                                src_port=_port(row.get("id.orig_p")), dst_port=_port(row.get("id.resp_p")),
                                protocol=row.get("proto", "unknown"),
                                packet_len=orig_bytes + resp_bytes,
                                data_source="zeek", metadata={
                                    "uid": row.get("uid", ""),
                                    "service": row.get("service", ""),
                                    "duration": _float(row.get("duration")),
                                    "orig_bytes": orig_bytes,
                                    "resp_bytes": resp_bytes,
                                })


def _int(value: str | None) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _float(value: str | None) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _port(value: str | None) -> int | None:
    result = _int(value)
    return result or None
