from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from diodeshield.schemas import TrafficEvent


class SlidingWindow:
    """Time-based window tolerant of out-of-order and duplicate events."""

    def __init__(self, size_seconds: float = 5, slide_seconds: float = 1):
        self.size = timedelta(seconds=size_seconds)
        self.slide = timedelta(seconds=slide_seconds)
        self.events: deque[TrafficEvent] = deque()
        self.last_emit: datetime | None = None
        self.seen: set[tuple[str, str, str, str, int]] = set()

    def add(self, event: TrafficEvent) -> list[list[TrafficEvent]]:
        if event.timestamp.tzinfo is None:
            event.timestamp = event.timestamp.replace(tzinfo=timezone.utc)
        key = (event.timestamp.isoformat(), event.src_ip, event.dst_ip, event.protocol, event.packet_len)
        if key in self.seen:
            return []
        self.seen.add(key)
        self.events.append(event)
        ordered = sorted(self.events, key=lambda e: e.timestamp)
        self.events = deque(ordered)
        newest = ordered[-1].timestamp
        if self.last_emit is None:
            self.last_emit = newest - self.slide
        emitted: list[list[TrafficEvent]] = []
        while newest - self.last_emit >= self.slide:
            end = self.last_emit + self.slide
            start = end - self.size
            emitted.append([e for e in ordered if start < e.timestamp <= end])
            self.last_emit = end
        cutoff = newest - self.size - self.slide
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()
        if len(self.seen) > 10000:
            self.seen = set(list(self.seen)[-5000:])
        return emitted

    def flush(self) -> Iterable[list[TrafficEvent]]:
        if not self.events:
            return []
        newest = self.events[-1].timestamp
        if self.last_emit is None or newest > self.last_emit:
            self.last_emit = newest
            return [[e for e in self.events if e.timestamp > newest - self.size]]
        return []
