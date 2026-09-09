def parse_s7comm(metadata: dict) -> dict:
    return {"protocol": "S7comm", "visibility_status": "metadata_only", **metadata}
