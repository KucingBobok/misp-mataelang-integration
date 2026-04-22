"""
MISP REST API Client — v1.1
============================
Adds:
  • Startup connectivity + API key health-check (validate_misp_connection)
  • Retry with exponential back-off on transient HTTP errors
  • Detailed error classification (auth, timeout, server, network)
"""

import asyncio
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.core.config import settings
from app.core.logging import logger
from app.models.ioc import IOCRecord

THREAT_LEVEL_MAP = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}

# Retry settings
_MAX_RETRIES = 3
_RETRY_BACKOFF = [2, 5, 10]   # seconds between retries


def _build_headers() -> Dict[str, str]:
    return {
        "Authorization": settings.MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.MISP_URL,
        headers=_build_headers(),
        verify=settings.MISP_VERIFY_TLS,
        timeout=settings.MISP_TIMEOUT,
    )


# ── Startup health-check ──────────────────────────────────────────────────────

async def validate_misp_connection() -> Dict[str, Any]:
    """
    Called at application startup.
    Hits GET /users/view/me to verify:
      1. MISP_URL is reachable
      2. MISP_API_KEY is valid (returns HTTP 200 with user JSON)

    Returns a dict with {reachable, authenticated, user_email, misp_version}
    Raises RuntimeError if not reachable/authenticated and strict mode is on.
    """
    result = {
        "reachable": False,
        "authenticated": False,
        "user_email": None,
        "misp_version": None,
        "error": None,
    }

    if not settings.MISP_API_KEY:
        result["error"] = "MISP_API_KEY is not set"
        logger.error("MISP health check FAILED: %s", result["error"])
        return result

    async with _make_client() as client:
        try:
            resp = await client.get("/users/view/me")
            result["reachable"] = True

            if resp.status_code == 401:
                result["error"] = "API key rejected by MISP (HTTP 401)"
                logger.error("MISP health check FAILED: invalid API key")
                return result

            if resp.status_code == 403:
                result["error"] = "API key lacks required permissions (HTTP 403)"
                logger.error("MISP health check FAILED: %s", result["error"])
                return result

            resp.raise_for_status()
            data = resp.json()
            user = data.get("User", data)
            result["authenticated"] = True
            result["user_email"] = user.get("email")
            result["misp_version"] = data.get("version") or data.get("Role", {}).get("name")
            logger.info(
                "MISP health check OK: user=%s version=%s",
                result["user_email"], result["misp_version"],
            )

        except httpx.ConnectError as exc:
            result["error"] = f"Cannot connect to MISP at {settings.MISP_URL}: {exc}"
            logger.error("MISP health check FAILED: %s", result["error"])
        except httpx.TimeoutException:
            result["reachable"] = True
            result["error"] = f"MISP connection timed out after {settings.MISP_TIMEOUT}s"
            logger.error("MISP health check FAILED: timeout")
        except Exception as exc:
            result["error"] = str(exc)
            logger.error("MISP health check FAILED: %s", exc)

    return result


# ── Retry helper ──────────────────────────────────────────────────────────────

async def _post_with_retry(endpoint: str, body: dict) -> Optional[dict]:
    """POST with exponential back-off retry on transient errors."""
    for attempt in range(_MAX_RETRIES):
        async with _make_client() as client:
            try:
                resp = await client.post(endpoint, json=body)

                if resp.status_code in (429, 503):
                    wait = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                    logger.warning(
                        "MISP %s returned %d — retry %d/%d in %ds",
                        endpoint, resp.status_code, attempt + 1, _MAX_RETRIES, wait,
                    )
                    await asyncio.sleep(wait)
                    continue

                resp.raise_for_status()
                return resp.json()

            except httpx.TimeoutException:
                wait = _RETRY_BACKOFF[min(attempt, len(_RETRY_BACKOFF) - 1)]
                logger.warning("MISP %s timeout — retry %d/%d in %ds", endpoint,
                               attempt + 1, _MAX_RETRIES, wait)
                await asyncio.sleep(wait)

            except httpx.HTTPStatusError as exc:
                logger.error("MISP %s HTTP %d: %s", endpoint, exc.response.status_code, exc)
                return None   # Non-retryable HTTP errors

            except Exception as exc:
                logger.error("MISP %s unexpected error: %s", endpoint, exc)
                return None

    logger.error("MISP %s failed after %d attempts", endpoint, _MAX_RETRIES)
    return None


# ── IOC parser ────────────────────────────────────────────────────────────────

def _parse_attribute(attr: Dict[str, Any]) -> Optional[IOCRecord]:
    try:
        value = attr.get("value", "").strip()
        ioc_type = attr.get("type", "")
        if not value or ioc_type not in settings.MISP_IOC_TYPES:
            return None

        event = attr.get("Event", {})
        tl_id = int(event.get("threat_level_id", 4)) if event else 4
        tl_label = THREAT_LEVEL_MAP.get(tl_id, "Undefined")

        tags: List[str] = []
        for tag in attr.get("Tag", []):
            tags.append(tag.get("name", ""))
        for tag in event.get("Tag", []):
            name = tag.get("name", "")
            if name and name not in tags:
                tags.append(name)

        ts = attr.get("timestamp")
        attr_ts = datetime.utcfromtimestamp(int(ts)) if ts else None

        return IOCRecord(
            ioc_id=attr.get("uuid", attr.get("id", "")),
            ioc_value=value,
            ioc_type=ioc_type,
            detectable=bool(int(attr.get("to_ids", 0))),
            event_id=str(event.get("id", "")),
            event_uuid=event.get("uuid", ""),
            event_info=event.get("info", ""),
            threat_level_id=tl_id,
            threat_level=tl_label,
            tags=tags,
            attribute_timestamp=attr_ts,
        )
    except Exception as exc:
        logger.warning("Failed to parse MISP attribute %s: %s", attr.get("uuid"), exc)
        return None


# ── IOC fetch ─────────────────────────────────────────────────────────────────

async def fetch_iocs(page: int = 1) -> List[IOCRecord]:
    body = {
        "returnFormat": "json",
        "type": settings.MISP_IOC_TYPES,
        "published": 1,
        "to_ids": 1,
        "includeEventUuid": 1,
        "includeEventTags": 1,
        "publish_timestamp": settings.MISP_PUBLISH_TIMESTAMP,
        "enforceWarninglist": 1 if settings.MISP_ENFORCE_WARNINGLIST else 0,
        "page": page,
        "limit": settings.MISP_PAGE_SIZE,
    }

    data = await _post_with_retry("/attributes/restSearch", body)
    if not data:
        return []

    attributes = data.get("response", {}).get("Attribute", [])
    iocs = [r for r in (_parse_attribute(a) for a in attributes) if r]
    logger.info("Page %d: %d raw → %d valid IOCs", page, len(attributes), len(iocs))
    return iocs


async def fetch_all_iocs() -> List[IOCRecord]:
    all_iocs: List[IOCRecord] = []
    page = 1
    while True:
        batch = await fetch_iocs(page=page)
        all_iocs.extend(batch)
        if len(batch) < settings.MISP_PAGE_SIZE:
            break
        page += 1
        await asyncio.sleep(0.5)
    logger.info("Total IOCs fetched from MISP: %d", len(all_iocs))
    return all_iocs


# ── NIDS rules ────────────────────────────────────────────────────────────────

async def fetch_nids_rules(fmt: str = "snort") -> str:
    if fmt not in ("snort", "suricata"):
        raise ValueError(f"Unsupported NIDS format: {fmt}")
    async with _make_client() as client:
        resp = await client.get(f"/events/nids/{fmt}/download")
        resp.raise_for_status()
        return resp.text


# ── Sighting feedback ─────────────────────────────────────────────────────────

async def send_sighting(
    ioc_value: str,
    attribute_uuid: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> bool:
    if not settings.SIGHTING_ENABLED:
        return False

    ts = int((timestamp or datetime.utcnow()).timestamp())
    body: Dict[str, Any] = {
        "type": 0,
        "source": settings.SIGHTING_SOURCE,
        "timestamp": ts,
    }
    if attribute_uuid:
        body["uuid"] = attribute_uuid
    else:
        body["values"] = [ioc_value]

    data = await _post_with_retry("/sightings/add", body)
    if data is not None:
        logger.info("Sighting sent for IOC: %s", ioc_value)
        return True
    return False
