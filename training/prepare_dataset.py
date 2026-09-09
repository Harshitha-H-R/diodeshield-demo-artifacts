"""Prepare JSONL feature rows. Payloads are intentionally not required."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.output.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")


if __name__ == "__main__":
    main()
