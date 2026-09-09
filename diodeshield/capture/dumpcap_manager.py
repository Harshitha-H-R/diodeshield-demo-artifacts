from __future__ import annotations

import subprocess


class DumpcapManager:
    """Minimal receive-side process manager; no injection or packet writes are exposed."""

    def __init__(self, command: str = "dumpcap"):
        self.command = command
        self.process: subprocess.Popen | None = None

    def start(self, interface: str, output: str) -> None:
        self.process = subprocess.Popen([self.command, "-i", interface, "-w", output])

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
