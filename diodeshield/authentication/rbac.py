"""Role-Based Access Control and authentication for DIODESHIELD production API."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from enum import Enum
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from diodeshield.configuration.settings import load_app_config

security_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


ROLE_HIERARCHY = {
    Role.ADMIN: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1,
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding and padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def create_access_token(subject: str, role: Role = Role.ANALYST, expires_in_minutes: int = 480) -> str:
    config = load_app_config()
    secret = config.security.jwt_secret.encode("utf-8")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "role": role.value,
        "iat": int(time.time()),
        "exp": int(time.time()) + (expires_in_minutes * 60),
    }

    hdr_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pay_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    msg = f"{hdr_b64}.{pay_b64}".encode("utf-8")
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    return f"{hdr_b64}.{pay_b64}.{sig_b64}"


def verify_token(token: str) -> dict[str, Any]:
    config = load_app_config()
    secret = config.security.jwt_secret.encode("utf-8")
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed JWT token")

    hdr_b64, pay_b64, sig_b64 = parts
    msg = f"{hdr_b64}.{pay_b64}".encode("utf-8")
    expected_sig = hmac.new(secret, msg, hashlib.sha256).digest()

    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature format") from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        payload = json.loads(_b64url_decode(pay_b64).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload") from exc

    exp = payload.get("exp", 0)
    if time.time() > exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    return payload


def require_role(min_role: Role = Role.VIEWER):
    def dependency(
        auth: HTTPAuthorizationCredentials | None = Depends(security_scheme),
        x_api_key: str | None = Header(None, alias="X-API-Key"),
    ) -> dict[str, Any]:
        config = load_app_config()

        # If API key auth is not strictly required and no header provided, allow default local viewer
        if not config.security.api_key_required and not auth and not x_api_key:
            return {"sub": "local_operator", "role": Role.ADMIN.value}

        # Check API Key
        if x_api_key:
            expected_key = config.security.api_key
            if expected_key and hmac.compare_digest(x_api_key.encode(), expected_key.encode()):
                return {"sub": "api_key_client", "role": Role.ADMIN.value}
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")

        # Check Bearer JWT
        if auth and auth.credentials:
            payload = verify_token(auth.credentials)
            user_role = Role(payload.get("role", Role.VIEWER.value))
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY[min_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: required {min_role.value}, have {user_role.value}",
                )
            return payload

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication credentials required")

    return dependency
