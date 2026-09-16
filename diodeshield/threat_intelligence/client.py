"""Real-time external threat intelligence client with TTL caching, rate limiting, and source attribution."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any
import urllib.request
import urllib.error
import json

from diodeshield.configuration.settings import ThreatIntelSettings

logger = logging.getLogger("diodeshield.threat_intel")


class ThreatIntelClient:
    """Queries real external threat intelligence feeds with local TTL caching and rate limits."""

    def __init__(self, settings: ThreatIntelSettings | None = None) -> None:
        self.settings = settings or ThreatIntelSettings()
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}  # ip -> (result, expire_time)
        self._lock = threading.Lock()
        self._tor_exit_ips: set[str] = set()
        self._last_tor_refresh = 0.0
        self._request_timestamps: list[float] = []

    def _rate_limit_check(self) -> bool:
        """Token bucket check for external API queries."""
        now = time.time()
        with self._lock:
            self._request_timestamps = [t for t in self._request_timestamps if now - t < 60.0]
            if len(self._request_timestamps) >= self.settings.max_requests_per_minute:
                return False
            self._request_timestamps.append(now)
            return True

    def _refresh_tor_exit_nodes(self) -> None:
        """Dynamically fetch official Tor Project bulk exit node directory."""
        now = time.time()
        if now - self._last_tor_refresh < 3600.0 and self._tor_exit_ips:
            return

        url = self.settings.tor_exit_url
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "DIODESHIELD-SOC-Monitor/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.settings.request_timeout_seconds) as resp:
                if resp.status == 200:
                    text = resp.read().decode("utf-8", errors="ignore")
                    ips = set(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))
                    with self._lock:
                        self._tor_exit_ips = ips
                        self._last_tor_refresh = now
                    logger.info("Refreshed Tor exit node directory (%d IPs)", len(ips))
        except Exception as exc:
            logger.debug("Failed to refresh Tor exit list: %s", exc)

    def _query_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        if not self.settings.abuseipdb_api_key or not self._rate_limit_check():
            return None

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Key": self.settings.abuseipdb_api_key,
                    "Accept": "application/json",
                    "User-Agent": "DIODESHIELD-Production/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=self.settings.request_timeout_seconds) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    data = body.get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    is_malicious = score >= 40
                    return {
                        "match": is_malicious,
                        "source": "AbuseIPDB",
                        "abuse_confidence_score": score,
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "is_tor": data.get("isTor", False),
                        "last_reported": data.get("lastReportedAt"),
                    }
        except urllib.error.HTTPError as err:
            logger.warning("AbuseIPDB API error: %s", err)
        except Exception as exc:
            logger.debug("AbuseIPDB request exception: %s", exc)
        return None

    def check_ip(self, ip: str) -> dict[str, Any]:
        """Check IP reputation with caching, multiple sources, and explicit attribution."""
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1") or ip.startswith("10.") or ip.startswith("192.168."):
            return {
                "ip": ip,
                "is_malicious": False,
                "reputation_score": 0.0,
                "source": "LocalSubnetFilter",
                "attribution": "Private / Local Loopback IP",
                "cached": False,
            }

        now = time.time()
        # 1. Check in-memory TTL Cache
        with self._lock:
            if ip in self._cache:
                cached_data, exp = self._cache[ip]
                if now < exp:
                    cached_data_copy = dict(cached_data)
                    cached_data_copy["cached"] = True
                    return cached_data_copy

        # 2. Check Tor Exit Node feed
        if self.settings.tor_exit_list_enabled:
            self._refresh_tor_exit_nodes()
            if ip in self._tor_exit_ips:
                res = {
                    "ip": ip,
                    "is_malicious": True,
                    "reputation_score": 0.85,
                    "source": "TorProject-ExitDirectory",
                    "attribution": "Active Tor Exit Node",
                    "cached": False,
                }
                with self._lock:
                    self._cache[ip] = (res, now + self.settings.cache_ttl_seconds)
                return res

        # 3. Check AbuseIPDB API if configured
        abuse_res = self._query_abuseipdb(ip)
        if abuse_res:
            res = {
                "ip": ip,
                "is_malicious": abuse_res["match"],
                "reputation_score": round(abuse_res.get("abuse_confidence_score", 0) / 100.0, 2),
                "source": "AbuseIPDB",
                "attribution": f"AbuseIPDB Score {abuse_res.get('abuse_confidence_score')}% ({abuse_res.get('total_reports')} reports)",
                "details": abuse_res,
                "cached": False,
            }
            with self._lock:
                self._cache[ip] = (res, now + self.settings.cache_ttl_seconds)
            return res

        # 4. Unlisted / Clean
        clean_res = {
            "ip": ip,
            "is_malicious": False,
            "reputation_score": 0.0,
            "source": "LiveThreatIntelFeeds",
            "attribution": "Not listed on active threat feeds",
            "cached": False,
        }
        with self._lock:
            self._cache[ip] = (clean_res, now + min(self.settings.cache_ttl_seconds, 3600.0))
        return clean_res

    def get_provider_status(self) -> dict[str, Any]:
        return {
            "abuseipdb_configured": bool(self.settings.abuseipdb_api_key),
            "otx_configured": bool(self.settings.otx_api_key),
            "tor_exit_feed_enabled": self.settings.tor_exit_list_enabled,
            "tor_exit_nodes_cached": len(self._tor_exit_ips),
            "cache_entries": len(self._cache),
            "last_tor_refresh": self._last_tor_refresh,
        }
