"""Explicit, audited host-firewall actions for validated indicators."""

from __future__ import annotations

import ipaddress
import os
import platform
import subprocess
from typing import Any


def block_ip(ip: str, alert_id: str, reason: str = "") -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("refusing to block loopback, unspecified, or multicast addresses")
    if os.getenv("DIODESHIELD_FIREWALL_BLOCKING", "").lower() not in {"1", "true", "yes"}:
        return {"status": "disabled", "dry_run": True, "ip": str(address),
                "message": "Set DIODESHIELD_FIREWALL_BLOCKING=true and run with administrator rights to apply a rule"}
    if platform.system() != "Windows":
        raise RuntimeError("automatic firewall integration currently supports Windows only")
    name = f"DIODESHIELD-{alert_id[:12]}"
    command = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
               "dir=in", "action=block", f"remoteip={address}", "enable=yes"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "netsh failed")
    return {"status": "blocked", "dry_run": False, "ip": str(address), "rule": name, "reason": reason}
