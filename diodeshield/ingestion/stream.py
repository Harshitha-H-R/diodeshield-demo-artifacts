from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable

from diodeshield.ingestion.events import parse_jsonl
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import TrafficEvent


def replay(events: Iterable[TrafficEvent], pipeline: DetectionPipeline | None = None) -> list[dict]:
    """Replay a finite receive-side stream without requiring a live interface."""
    detector = pipeline or DetectionPipeline()
    alerts: list[dict] = []
    for event in events:
        alerts.extend(detector.ingest(event))
    return alerts


async def consume_jsonl(lines: Iterable[str], pipeline: DetectionPipeline | None = None) -> AsyncIterator[dict]:
    detector = pipeline or DetectionPipeline()
    for event in parse_jsonl(lines):
        for alert in detector.ingest(event):
            yield alert
        await asyncio.sleep(0)
