from __future__ import annotations

import hashlib
import json
from typing import Any


class HashChain:
    def __init__(self) -> None:
        self.previous = "0" * 64
        self.sequence = 0

    def append(self, alert: dict[str, Any]) -> dict[str, Any]:
        self.sequence += 1
        previous = self.previous
        payload = json.dumps(alert, sort_keys=True, default=str, separators=(",", ":"))
        digest = hashlib.sha256((previous + payload + str(alert.get("timestamp", ""))).encode()).hexdigest()
        self.previous = digest
        alert["previous_hash"], alert["evidence_hash"], alert["chain_sequence"] = previous, digest, self.sequence
        return alert
