from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from typing import Any

from diodeshield.ingestion.events import tshark_row
from diodeshield.schemas import TrafficEvent


class TSharkManager:
    def __init__(self, command: str = "tshark"):
        self.command = command

    def replay_json(self, path: str) -> Iterator[TrafficEvent]:
        """Read TShark JSON export; captures remain read-only."""
        process = subprocess.Popen(
            [self.command, "-r", path, "-T", "json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stdout, _ = process.communicate()
        if process.returncode:
            raise RuntimeError(f"TShark replay failed with exit code {process.returncode}")
        try:
            rows = json.loads(stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError("TShark did not return valid JSON") from exc
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows if isinstance(rows, list) else []:
            layers: dict[str, Any] = row.get("_source", {}).get("layers", row)
            flattened = {key: value[0] if isinstance(value, list) and value else value for key, value in layers.items()}
            yield tshark_row(flattened)
