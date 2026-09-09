"""Read-only live metadata capture through TShark."""
from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable

from diodeshield.ingestion.events import tshark_row
from diodeshield.schemas import TrafficEvent

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "_ws.col.Protocol", "frame.len", "ip.ttl",
    "ip.id", "ip.flags", "tcp.flags",
]


class LiveCaptureWorker:
    """TShark metadata reader. It never writes, injects, or modifies packets."""

    def __init__(self, pipeline, interface: str, command: str = "tshark",
                 on_event: Callable[[TrafficEvent], None] | None = None):
        self.pipeline = pipeline
        self.interface = interface
        self.command = command
        self.on_event = on_event
        self.process: subprocess.Popen[str] | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="diodeshield-live-capture", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        interface = self._resolve_interface()
        if not interface:
            return
        self.interface = interface
        args = [self.command, "-i", interface, "-l", "-n", "-T", "fields"]
        for field in FIELDS:
            args.extend(["-e", field])
        try:
            self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            text=True, bufsize=1)
        except OSError as exc:
            self.pipeline.latest_health.update({"status": "CRITICAL", "visibility": "capture_unavailable",
                                                "capture_error": str(exc)})
            return
        self.pipeline.latest_health.update({"status": "HEALTHY", "visibility": "live_capture",
                                            "interface": self.interface})
        assert self.process.stdout is not None
        for line in self.process.stdout:
            if self.stop_event.is_set():
                break
            values = line.rstrip("\r\n").split("\t")
            row = dict(zip(FIELDS, values))
            if not row.get("frame.time_epoch") or not row.get("ip.src") or not row.get("ip.dst"):
                continue
            try:
                event = tshark_row(row)
                event.data_source = "tshark_live"
                self.pipeline.ingest(event)
                if self.on_event:
                    self.on_event(event)
            except (ValueError, TypeError):
                self.pipeline.latest_health["parser_errors"] = self.pipeline.latest_health.get("parser_errors", 0) + 1
        self.pipeline.latest_health.update({"status": "WARNING" if self.stop_event.is_set() else "CRITICAL",
                                            "visibility": "capture_stopped"})

    def _resolve_interface(self) -> str | None:
        if self.interface.lower() not in {"auto", "any"}:
            return self.interface
        if self.interface.lower() == "any":
            return self.interface
        try:
            result = subprocess.run([self.command, "-D"], capture_output=True, text=True,
                                    timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            self.pipeline.latest_health.update({"status": "CRITICAL", "visibility": "capture_unavailable",
                                                "capture_error": str(exc)})
            return None
        if result.returncode:
            self.pipeline.latest_health.update(
                {"status": "CRITICAL", "visibility": "capture_unavailable",
                 "capture_error": result.stderr.strip() or "TShark interface discovery failed"}
            )
            return None
        for line in result.stdout.splitlines():
            value = line.strip()
            if value and not any(token in value.lower() for token in ("loopback", "npcap loopback")):
                return value.split(".", 1)[0].strip()
        self.pipeline.latest_health.update({"status": "CRITICAL", "visibility": "capture_unavailable",
                                            "capture_error": "No non-loopback capture interface found"})
        return None

    def stop(self) -> None:
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
        if self.thread:
            self.thread.join(timeout=2)
