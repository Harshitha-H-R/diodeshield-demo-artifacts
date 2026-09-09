def parse_iec104(metadata: dict) -> dict:
    return {"protocol": "IEC-104", "visibility_status": "metadata_only", **metadata}
