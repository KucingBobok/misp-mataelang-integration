"""
Inter-service authentication — v1.1
====================================
Implements API Key authentication for all REST endpoints.

Design decisions:
  • Header-based: clients send  X-API-Key: <key>
  • Keys stored in env vars SERVICE_API_KEY / SERVICE_API_KEYS (comma-separated)
  • Constant-time comparison (secrets.compare_digest) to resist timing attacks
  • Configurable exempt paths (health, docs) — no key required there
  • Startup validation: service refuses to start if no keys are configured

Usage in routes:
    from app.core.security import require_api_key
    @router.post("/sync/misp", dependencies=[Depends(require_api_key)])
    async def trigger_sync(): ...

Or applied globally via middleware (see app/core/auth_middleware.py).
"""

import secrets
from typing import List, Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings
from app.core.logging import logger

# FastAPI security scheme — shows lock icon in Swagger UI
_api_key_scheme = APIKeyHeader(
    name=settings.API_KEY_HEADER,
    auto_error=False,
    description="API key for inter-service authentication. Pass in the X-API-Key header.",
)


def validate_api_key(key: Optional[str]) -> bool:
    """
    Constant-time comparison against all configured API keys.
    Returns True if key matches any configured key, False otherwise.
    """
    allowed = settings.allowed_api_keys
    if not allowed:
        # Should not happen — startup check prevents this — but fail-safe
        logger.critical("No API keys configured! All requests will be rejected.")
        return False

    for allowed_key in allowed:
        if secrets.compare_digest(key or "", allowed_key):
            return True
    return False


async def require_api_key(api_key: Optional[str] = Security(_api_key_scheme)) -> str:
    """
    FastAPI dependency — inject into routes or router dependencies.
    Raises HTTP 401 if the key is missing or invalid.
    Returns the validated key string on success.
    """
    if not validate_api_key(api_key):
        logger.warning("Rejected request: invalid or missing API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


def check_keys_configured() -> None:
    """
    Called at startup. Raises RuntimeError if no API keys are configured,
    so the service refuses to start rather than running in an open state.
    """
    keys = settings.allowed_api_keys
    if not keys:
        raise RuntimeError(
            "SECURITY ERROR: No API keys configured. "
            "Set SERVICE_API_KEY or SERVICE_API_KEYS in .env before starting the service."
        )
    logger.info("Auth: %d API key(s) configured", len(keys))
