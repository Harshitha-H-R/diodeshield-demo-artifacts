from __future__ import annotations

import struct
from typing import Any


def parse_modbus_tcp(payload: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "Modbus/TCP", "malformed_message_score": 0.0}
    if not payload:
        result["malformed_message_score"] = 0.2
        result["protocol_anomaly_score"] = 0.2
        return result
    try:
        raw = bytes.fromhex(payload) if isinstance(payload, str) else payload
        if len(raw) < 8:
            raise ValueError("short MBAP")
        transaction, protocol_id, length, unit = struct.unpack(">HHHB", raw[:7])
        function = raw[7]
        result.update(transaction_id=transaction, protocol_id=protocol_id, mbap_length=length,
                      unit_id=unit, function_code=function, operation="write" if function in {5, 6, 15, 16, 22, 23} else "read")
        if protocol_id != 0 or length != len(raw) - 6:
            result["malformed_message_score"] = 0.8
        if function & 0x80:
            result["exception_response"] = True
            result["function_code"] = function & 0x7F
        if len(raw) >= 12 and function in {1, 2, 3, 4, 5, 6, 15, 16, 22, 23}:
            result["starting_address"] = int.from_bytes(raw[8:10], "big")
            result["quantity"] = int.from_bytes(raw[10:12], "big")
            if result["quantity"] == 0 or result["quantity"] > 2000:
                result["malformed_message_score"] = max(result["malformed_message_score"], 0.7)
        result["unexpected_function_score"] = 1.0 if function in {8, 43, 90, 91} else 0.0
        result["write_operation_risk_score"] = 0.7 if result["operation"] == "write" else 0.0
        result["protocol_anomaly_score"] = min(1.0, max(result["malformed_message_score"], result["unexpected_function_score"]))
    except (ValueError, struct.error):
        result.update(protocol_anomaly_score=0.9, malformed_message_score=1.0)
    return result
