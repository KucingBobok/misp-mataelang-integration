"""
API Key Authentication Middleware — v1.1
=========================================
Starlette middleware that enforces API key authentication on every request
before it reaches any route handler.

Exempt paths (configurable via AUTH_EXEMPT_PATHS env var):
  /health, /docs, /redoc, /openapi.json, /

All other paths require the  X-API-Key  header to contain a valid key.

Why middleware instead of per-route Depends()?
  → Centrally enforced — no risk of forgetting auth on a new route.
  → Works for WebSocket upgrades and any future routes.
  → Returns a clean 401 JSON response before FastAPI routing runs.
"""

import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.security import validate_api_key
from app.core.logging import logger

_401_BODY = json.dumps({"detail": "Invalid or missing API key"}).encode()
_401_HEADERS = {
    "Content-Type": "application/json",
    "WWW-Authenticate": "ApiKey",
}


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Intercepts every HTTP request.
    If the path is not exempt, validates the X-API-Key header.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Allow exempt paths through without authentication
        if path in settings.exempt_paths:
            return await call_next(request)

        # Extract key from configured header
        api_key = request.headers.get(settings.API_KEY_HEADER)

        if not validate_api_key(api_key):
            logger.warning(
                "Auth rejected: path=%s client=%s",
                path,
                request.client.host if request.client else "unknown",
            )
            return Response(
                content=_401_BODY,
                status_code=401,
                headers=_401_HEADERS,
            )

        return await call_next(request)
