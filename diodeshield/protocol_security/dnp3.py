def parse_dnp3(metadata: dict) -> dict:
    return {"protocol": "DNP3", "visibility_status": "metadata_only", **metadata}
