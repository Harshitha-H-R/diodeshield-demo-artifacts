from __future__ import annotations

import argparse
import json

from diodeshield.pipeline import DetectionPipeline
from diodeshield.synthetic import generate_synthetic


def main() -> None:
    parser = argparse.ArgumentParser(description="DIODESHIELD demo/replay")
    parser.add_argument("--scenario", default="normal", choices=["normal", "beacon", "recon", "protocol"])
    parser.add_argument("--count", type=int, default=30)
    args = parser.parse_args()
    pipeline = DetectionPipeline()
    alerts = []
    for event in generate_synthetic(args.scenario, args.count):
        alerts.extend(pipeline.ingest(event))
    print(json.dumps({"scenario": args.scenario, "alerts": len(alerts), "database": str(pipeline.repository.path)}, indent=2))


if __name__ == "__main__":
    main()
