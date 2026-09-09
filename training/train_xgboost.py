"""Optional supervised export; falls back to a metadata artifact when xgboost is unavailable."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="models/xgboost.json")
    args = parser.parse_args()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"model_name": "xgboost", "model_version": "0.1.0",
                                "status": "prototype; train with optional xgboost dependency"}), encoding="utf-8")


if __name__ == "__main__":
    main()
