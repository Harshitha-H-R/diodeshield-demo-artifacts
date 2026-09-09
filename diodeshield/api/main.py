from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse

from diodeshield.capture.live import LiveCaptureWorker
from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.firewall import block_ip
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import BlockRequest, ConfigUpdate, Feedback, TrafficEvent

config = load_config()
repository = Repository()
pipeline = DetectionPipeline(repository, config)
event_queues: set[asyncio.Queue[dict[str, Any]]] = set()


def publish(alert: dict[str, Any]) -> None:
    for queue in list(event_queues):
        try:
            queue.put_nowait({"event_type": "alert", **alert})
        except asyncio.QueueFull:
            pass


pipeline.subscribe(publish)
live_capture: LiveCaptureWorker | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global live_capture
    if config.get("system", {}).get("live_capture"):
        interface = os.getenv("DIODESHIELD_INTERFACE", "auto")
        live_capture = LiveCaptureWorker(pipeline, interface,
                                         os.getenv("DIODESHIELD_TSHARK", "tshark"))
        live_capture.start()
    yield
    if live_capture:
        live_capture.stop()


app = FastAPI(title="DIODESHIELD", version="0.1.0", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("DIODESHIELD_CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"])
if os.path.isdir("dashboard"):
    app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


@app.middleware("http")
async def optional_api_key(request, call_next):
    if config.get("security", {}).get("api_key_required") and request.url.path.startswith("/api/"):
        expected = os.getenv("DIODESHIELD_API_KEY", "")
        if not expected or request.headers.get("X-API-Key") != expected:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "diodeshield", **repository.health()}


@app.get("/health/detailed")
def detailed_health() -> dict[str, Any]:
    return {"status": "ok", "components": {"database": repository.health(), "pipeline": pipeline.latest_health,
                                            "models": {name: adapter.get_metadata() for name, adapter in pipeline.adapters.items()}}}


@app.get("/api/capture-status")
def capture_status() -> dict[str, Any]:
    enabled = bool(config.get("system", {}).get("live_capture"))
    worker = live_capture
    return {"enabled": enabled, "running": bool(worker and worker.process and worker.process.poll() is None),
            "interface": getattr(worker, "interface", None),
            "tshark": getattr(worker, "command", os.getenv("DIODESHIELD_TSHARK", "tshark")),
            "visibility": pipeline.latest_health.get("visibility"),
            "error": pipeline.latest_health.get("capture_error")}


@app.get("/api/alerts")
def alerts(
    limit: int = 100, severity: str | None = None, category: str | None = None,
    source: str | None = None, destination: str | None = None,
) -> list[dict[str, Any]]:
    rows = repository.alerts(limit)
    return [
        row for row in rows
        if (not severity or row.get("risk_level") == severity)
        and (not category or row.get("attack_category") == category)
        and (not source or row.get("src_ip") == source)
        and (not destination or row.get("dst_ip") == destination)
    ]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return result


@app.get("/api/features/{alert_id}")
def features(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return result.get("feature_values", {})


@app.get("/api/explanation/{alert_id}")
def explanation(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return {"top_features": result.get("top_features", []),
            "explanation": result.get("explanation", {}),
            "reasons": result.get("reasons", []),
            "calibration": "not validated; confidence is model agreement, not probability"}


@app.get("/api/alerts/{alert_id}/validation")
def validate_alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    features = result.get("feature_values") or {}
    return {
        "alert": result,
        "verdict": {"category": result.get("attack_category"), "risk_level": result.get("risk_level"),
                    "risk_score": result.get("risk_score"), "confidence": result.get("confidence")},
        "why": result.get("reasons", []),
        "evidence": {"top_features": result.get("top_features", []),
                     "protocol": result.get("protocol_evidence", {}),
                     "source": result.get("src_ip"), "destination": result.get("dst_ip"),
                     "feature_values": features},
        "models": result.get("model_scores", {}),
        "integrity": {"evidence_hash": result.get("evidence_hash"),
                      "previous_hash": result.get("previous_hash"),
                      "chain_sequence": result.get("chain_sequence")},
        "limitations": ["This is an evidence-based triage verdict, not proof of compromise.",
                        "Packet alteration and spoofing require trusted capture metadata or baselines."],
    }


@app.get("/api/traffic")
def traffic(limit: int = 100) -> list[dict[str, Any]]:
    return repository.flows(limit)


@app.get("/api/assets")
def assets() -> list[dict[str, Any]]:
    return repository.assets()


@app.get("/api/models")
def models() -> list[dict[str, Any]]:
    return [adapter.get_metadata() for adapter in pipeline.adapters.values()]


@app.get("/api/model-health")
def model_health() -> dict[str, Any]:
    """Operational model metadata for the dashboard without changing /api/models."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "streaming_compatible": True,
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "pipeline": pipeline.latest_health,
    }


@app.get("/api/training/provenance")
def training_provenance() -> dict[str, Any]:
    return {
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "registered_versions": repository.model_versions(),
        "synthetic_evaluation": {
            "allowed": "evaluation_only",
            "production_training": False,
            "report": "reports/synthetic_training_report.json",
        },
    }


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return repository.metrics()


@app.get("/api/dashboard-summary")
def dashboard_summary(
    start: str | None = None, end: str | None = None, severity: str | None = None,
    category: str | None = None, source: str | None = None, destination: str | None = None,
) -> dict[str, Any]:
    return repository.dashboard_summary(start=start, end=end, severity=severity, category=category,
                                       source=source, destination=destination)


@app.get("/api/diode-status")
def diode_status() -> dict[str, Any]:
    return pipeline.latest_health


@app.get("/api/heatmap")
def heatmap(start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
    return repository.heatmap(start, end)


@app.get("/api/model-timeseries")
def model_timeseries(limit: int = 100) -> list[dict[str, Any]]:
    return repository.model_timeseries(limit)


@app.get("/api/evidence-chain")
def evidence_chain(limit: int = 100) -> list[dict[str, Any]]:
    return repository.evidence_chain(limit)


@app.get("/api/report")
def report(start: str | None = None, end: str | None = None,
           category: str | None = None) -> JSONResponse:
    rows = repository.alerts(1000)
    filtered = [
        row for row in rows
        if (not start or str(row.get("timestamp", "")) >= start)
        and (not end or str(row.get("timestamp", "")) <= end)
        and (not category or row.get("attack_category") == category)
    ]
    counts: dict[str, int] = {}
    for row in filtered:
        key = str(row.get("attack_category") or "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return JSONResponse({"generated_at": datetime.now(timezone.utc).isoformat(),
                         "filters": {"start": start, "end": end, "category": category},
                         "alert_count": len(filtered), "categories": counts,
                         "risk_levels": {level: sum(1 for row in filtered if row.get("risk_level") == level)
                                         for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
                         "alerts": filtered})


@app.post("/api/ingest")
def ingest(event: TrafficEvent) -> dict[str, Any]:
    return {"alerts": pipeline.ingest(event)}


@app.post("/api/config")
def update_config(update: ConfigUpdate) -> dict[str, Any]:
    config.update(update.values)
    return {"status": "updated", "config": config}


@app.post("/api/feedback")
def feedback(item: Feedback) -> dict[str, str]:
    repository.feedback(item.model_dump())
    return {"status": "stored"}


@app.post("/api/alerts/{alert_id}/block")
def block_alert_ip(alert_id: str, request: BlockRequest) -> dict[str, Any]:
    alert = repository.alert(alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    if not request.confirm:
        return {"status": "confirmation_required", "ip": alert.get("src_ip"),
                "message": "Set confirm=true only after validating this alert"}
    ip = alert.get("src_ip")
    if not ip:
        raise HTTPException(400, "alert has no source IP")
    try:
        result = block_ip(str(ip), alert_id, request.reason)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    repository.audit("firewall_block", {"alert_id": alert_id, "ip": ip, **result})
    return result


async def stream(queue: asyncio.Queue[dict[str, Any]], websocket: WebSocket) -> None:
    while True:
        await websocket.send_text(json.dumps(await queue.get(), default=str))


@app.websocket("/ws/{channel}")
async def websocket_channel(websocket: WebSocket, channel: str) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    event_queues.add(queue)
    try:
        await websocket.send_json({"event_type": "connected", "channel": channel})
        while True:
            await websocket.send_json({"event_type": "heartbeat", "channel": channel, "health": pipeline.latest_health})
            try:
                item = await asyncio.wait_for(queue.get(), timeout=5)
                await websocket.send_json(item)
            except asyncio.TimeoutError:
                pass
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        event_queues.discard(queue)
