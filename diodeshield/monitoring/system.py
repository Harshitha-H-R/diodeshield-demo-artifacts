"""System observability and performance telemetry collector."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

import psutil


class SystemMonitor:
    """Monitors host resources, process memory, and security engine telemetry."""

    def __init__(self) -> None:
        self.process = psutil.Process(os.getpid())
        self._start_time = time.time()

    def get_metrics(self, capture_stats: dict[str, Any] | None = None) -> dict[str, Any]:
        """Collect snapshot of CPU, RAM, capture rates, and process stats."""
        try:
            mem_info = self.process.memory_info()
            cpu_percent = self.process.cpu_percent(interval=None)
            system_cpu = psutil.cpu_percent(interval=None)
            system_mem = psutil.virtual_memory()

            uptime_sec = round(time.time() - self._start_time, 1)

            metrics = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "uptime_seconds": uptime_sec,
                "process": {
                    "cpu_percent": cpu_percent,
                    "rss_memory_mb": round(mem_info.rss / (1024 * 1024), 2),
                    "vms_memory_mb": round(mem_info.vms / (1024 * 1024), 2),
                    "open_files_count": len(self.process.open_files()) if hasattr(self.process, "open_files") else 0,
                    "num_threads": self.process.num_threads(),
                },
                "host": {
                    "total_cpu_percent": system_cpu,
                    "total_memory_used_mb": round((system_mem.total - system_mem.available) / (1024 * 1024), 2),
                    "total_memory_total_mb": round(system_mem.total / (1024 * 1024), 2),
                    "memory_percent": system_mem.percent,
                },
                "capture": capture_stats or {},
            }
            return metrics
        except Exception as exc:
            return {"error": str(exc), "timestamp": datetime.now(timezone.utc).isoformat()}
