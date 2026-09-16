"""Production Alert Dispatcher with SHA-256 tamper-evident hash chaining,
thread-safe subscriber queues, and asynchronous webhook dispatching.
"""
from __future__ import annotations

import hashlib
import json
import logging
import queue
import threading
import time
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from diodeshield.configuration.settings import AlertingSettings

logger = logging.getLogger("diodeshield.alerting")


class AlertDispatcher:
    """Dispatches alerts with cryptographic tamper-evident chaining and SIEM integration."""

    def __init__(self, settings: AlertingSettings | None = None) -> None:
        self.settings = settings or AlertingSettings()
        self._subscribers: set[Callable[[dict[str, Any]], None]] = set()
        self._subscribers_lock = threading.Lock()
        self._chain_lock = threading.Lock()
        self._last_hash = "0" * 64
        self._sequence = 0
        self._webhook_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)
        self._webhook_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        if self.settings.webhook_url:
            self._start_webhook_worker()

    def _start_webhook_worker(self) -> None:
        self._stop_event.clear()
        self._webhook_thread = threading.Thread(
            target=self._webhook_loop,
            name="diodeshield-webhook-worker",
            daemon=True,
        )
        self._webhook_thread.start()

    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        with self._subscribers_lock:
            self._subscribers.add(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        with self._subscribers_lock:
            self._subscribers.discard(callback)

    def dispatch(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Compute cryptographic hash chain and dispatch alert to subscribers and webhooks."""
        with self._chain_lock:
            self._sequence += 1
            prev = self._last_hash
            ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

            # Canonical representation for hashing
            hashable_body = {
                "alert_id": alert.get("alert_id"),
                "src_ip": alert.get("src_ip"),
                "dst_ip": alert.get("dst_ip"),
                "category": alert.get("attack_category"),
                "risk_level": alert.get("risk_level"),
                "timestamp": ts,
            }
            raw_canonical = json.dumps(hashable_body, sort_keys=True, separators=(",", ":"))
            evidence_hash = hashlib.sha256(f"{prev}:{raw_canonical}".encode("utf-8")).hexdigest()

            alert["chain_sequence"] = self._sequence
            alert["previous_hash"] = prev
            alert["evidence_hash"] = evidence_hash
            self._last_hash = evidence_hash

        # Dispatch to in-memory subscribers (e.g., WebSocket broadcaster)
        with self._subscribers_lock:
            subs = list(self._subscribers)

        for callback in subs:
            try:
                callback(alert)
            except Exception as exc:
                logger.debug("Subscriber callback failed: %s", exc)

        # Enqueue for external SIEM webhook
        if self.settings.webhook_url:
            try:
                self._webhook_queue.put_nowait(alert)
            except queue.Full:
                logger.warning("Webhook queue full, dropping SIEM notification")

        return alert

    def _webhook_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                alert = self._webhook_queue.get(timeout=1.0)
                data = json.dumps(alert).encode("utf-8")
                req = urllib.request.Request(
                    self.settings.webhook_url,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "DIODESHIELD-Alert-Dispatcher/1.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.settings.webhook_timeout_seconds) as resp:
                    if resp.status not in (200, 201, 202, 204):
                        logger.warning("Webhook responded with status %d", resp.status)
                self._webhook_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.debug("Webhook delivery error: %s", exc)
