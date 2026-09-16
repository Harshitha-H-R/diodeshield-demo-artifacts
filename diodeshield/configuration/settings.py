"""Production configuration management using environment variables and YAML settings."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import yaml


class SystemSettings(BaseModel):
    mode: str = Field(default="production")
    sensor_version: str = Field(default="1.0.0")
    live_capture: bool = Field(default=True)
    capture_interface: str = Field(default="auto")
    capture_queue_size: int = Field(default=20000)
    bpf_filter: str = Field(default="")
    log_level: str = Field(default="INFO")


class ThreatIntelSettings(BaseModel):
    enabled: bool = Field(default=True)
    cache_ttl_seconds: int = Field(default=86400)  # 24 hours
    abuseipdb_api_key: str = Field(default="")
    otx_api_key: str = Field(default="")
    virustotal_api_key: str = Field(default="")
    tor_exit_list_enabled: bool = Field(default=True)
    tor_exit_url: str = Field(default="https://check.torproject.org/torbulkexitlist")
    max_requests_per_minute: int = Field(default=30)
    request_timeout_seconds: float = Field(default=3.0)


class AnomalySettings(BaseModel):
    enabled: bool = Field(default=True)
    ewma_alpha: float = Field(default=0.1)
    zscore_threshold: float = Field(default=3.0)
    critical_zscore_threshold: float = Field(default=5.0)
    min_observations_for_baseline: int = Field(default=20)


class DetectionSettings(BaseModel):
    signatures_enabled: bool = Field(default=True)
    behavioral_enabled: bool = Field(default=True)
    anomaly_enabled: bool = Field(default=True)
    ml_enabled: bool = Field(default=True)
    correlation_enabled: bool = Field(default=True)
    port_scan_threshold_ports: int = Field(default=20)
    port_scan_window_seconds: float = Field(default=2.0)
    host_sweep_threshold_hosts: int = Field(default=15)
    host_sweep_window_seconds: float = Field(default=2.0)
    c2_beacon_min_intervals: int = Field(default=5)
    c2_beacon_max_jitter: float = Field(default=0.15)


class SecuritySettings(BaseModel):
    api_key_required: bool = Field(default=False)
    api_key: str = Field(default="")
    jwt_secret: str = Field(default="diodeshield-production-secret-change-in-env")
    token_expire_minutes: int = Field(default=480)
    admin_password_hash: str = Field(default="")


class RetentionSettings(BaseModel):
    raw_flows_max_rows: int = Field(default=50000)
    alerts_max_rows: int = Field(default=10000)
    audit_max_rows: int = Field(default=5000)
    flow_idle_timeout_seconds: float = Field(default=60.0)
    flow_active_timeout_seconds: float = Field(default=300.0)


class AlertingSettings(BaseModel):
    webhook_url: str = Field(default="")
    webhook_timeout_seconds: float = Field(default=4.0)
    dedup_window_seconds: float = Field(default=10.0)


class AppConfig(BaseModel):
    system: SystemSettings = Field(default_factory=SystemSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    alerting: AlertingSettings = Field(default_factory=AlertingSettings)
    database_path: str = Field(default="data/diodeshield.db")


def load_app_config(config_path: str | Path | None = None) -> AppConfig:
    path = Path(config_path or os.getenv("DIODESHIELD_CONFIG", "configs/default.yaml"))
    data: dict[str, Any] = {}
    if path.exists():
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    config = AppConfig(**data)

    # Environment overrides
    if os.getenv("DIODESHIELD_INTERFACE"):
        config.system.capture_interface = os.environ["DIODESHIELD_INTERFACE"]
    if os.getenv("DIODESHIELD_API_KEY"):
        config.security.api_key = os.environ["DIODESHIELD_API_KEY"]
        config.security.api_key_required = True
    if os.getenv("DIODESHIELD_JWT_SECRET"):
        config.security.jwt_secret = os.environ["DIODESHIELD_JWT_SECRET"]
    if os.getenv("ABUSEIPDB_API_KEY"):
        config.threat_intel.abuseipdb_api_key = os.environ["ABUSEIPDB_API_KEY"]
    if os.getenv("OTX_API_KEY"):
        config.threat_intel.otx_api_key = os.environ["OTX_API_KEY"]
    if os.getenv("VIRUSTOTAL_API_KEY"):
        config.threat_intel.virustotal_api_key = os.environ["VIRUSTOTAL_API_KEY"]
    if os.getenv("ALERT_WEBHOOK_URL"):
        config.alerting.webhook_url = os.environ["ALERT_WEBHOOK_URL"]
    if os.getenv("DIODESHIELD_DB"):
        config.database_path = os.environ["DIODESHIELD_DB"]

    return config
