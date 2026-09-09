from __future__ import annotations

from typing import Any


def parse_observable(protocol: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Safe placeholders: unsupported protocols remain explicitly limited."""
    name = protocol.upper()
    if name in {"DNP3", "IEC104", "S7COMM"}:
        return {"protocol": name, "visibility_status": "metadata_only", "protocol_anomaly_score": 0.0}
    return {"protocol": name, "visibility_status": "generic", "protocol_anomaly_score": 0.0}
