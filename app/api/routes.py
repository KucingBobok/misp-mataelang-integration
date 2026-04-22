"""
FastAPI routes — v1.1
======================
All protected endpoints now require X-API-Key authentication
(enforced globally by APIKeyMiddleware, documented here via dependencies
for correct Swagger UI lock-icon display).

GET  /health            → Public (no auth required)
POST /sync/misp         → Protected
GET  /ioc/search        → Protected
GET  /ioc/stats         → Protected
POST /enrich/alert      → Protected
POST /sighting          → Protected
GET  /rules/{fmt}       → Protected
DELETE /ioc/store       → Protected (admin — clear IOC store)
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import PlainTextResponse
from typing import Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.security import require_api_key
from app.models.ioc import IOCSearchResponse
from app.models.alert import EnrichmentRequest, EnrichmentResponse
from app.services.misp_client import send_sighting, fetch_nids_rules
from app.services.ioc_store import ioc_store
from app.services.enrichment import enrich_alert
from app.services.scheduler import sync_misp_iocs, get_last_sync_status
from app.core.config import settings
from app.core.logging import logger

router = APIRouter()

# Shorthand dependency tuple for protected routes
_auth = [Depends(require_api_key)]


# ── Health (public) ────────────────────────────────────────────────────────────

@router.get("/health", tags=["Status"])
async def health():
    """Public endpoint — no API key required. Used by Docker HEALTHCHECK."""
    store_stats = await ioc_store.stats()
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "ioc_store": store_stats,
        "last_sync": get_last_sync_status(),
    }


# ── MISP Sync ──────────────────────────────────────────────────────────────────

@router.post("/sync/misp", tags=["MISP"], dependencies=_auth)
async def trigger_misp_sync():
    """Manually trigger an IOC sync from MISP. Requires API key."""
    logger.info("Manual MISP sync triggered via API")
    return await sync_misp_iocs()


# ── IOC Store ─────────────────────────────────────────────────────────────────

@router.get("/ioc/stats", tags=["IOC Store"], dependencies=_auth)
async def ioc_stats():
    """IOC store metrics (backend type, total count, hit/miss stats). Requires API key."""
    return await ioc_store.stats()


@router.get("/ioc/search", tags=["IOC Store"], response_model=IOCSearchResponse, dependencies=_auth)
async def ioc_search(value: str = Query(..., description="IP, domain, hostname, or URL to look up")):
    """Look up a single network observable in the local IOC store. Requires API key."""
    ioc = await ioc_store.lookup(value)
    if ioc:
        return IOCSearchResponse(found=True, ioc=ioc, message="IOC found")
    return IOCSearchResponse(found=False, message="No match in IOC store")


@router.delete("/ioc/store", tags=["IOC Store"], dependencies=_auth)
async def clear_ioc_store():
    """
    Danger: Clears ALL IOC entries from the store.
    Use before a full resync if you want to remove stale entries.
    Requires API key.
    """
    await ioc_store.clear()
    return {"status": "ok", "message": "IOC store cleared"}


# ── Alert Enrichment ──────────────────────────────────────────────────────────

@router.post("/enrich/alert", tags=["Enrichment"], response_model=EnrichmentResponse, dependencies=_auth)
async def enrich_alert_endpoint(req: EnrichmentRequest):
    """
    Enrich a Mata Elang NIDS alert with MISP threat-intelligence context.
    Requires API key.

    Observables checked (in order): src_ip, dst_ip, domain, hostname, url.
    On a match: returns misp_context + indexes to OpenSearch + sends MISP sighting.
    """
    observables = [f for f in [req.src_ip, req.dst_ip, req.domain, req.hostname, req.url] if f]
    if not observables:
        raise HTTPException(
            status_code=422,
            detail="At least one observable required: src_ip, dst_ip, domain, hostname, or url",
        )
    return await enrich_alert(req)


# ── Sighting Feedback ─────────────────────────────────────────────────────────

class ManualSightingRequest(BaseModel):
    ioc_value: str
    attribute_uuid: Optional[str] = None
    timestamp: Optional[datetime] = None


@router.post("/sighting", tags=["MISP"], dependencies=_auth)
async def send_manual_sighting(req: ManualSightingRequest):
    """Send a sighting to MISP for a known IOC value. Requires API key."""
    if not settings.SIGHTING_ENABLED:
        raise HTTPException(status_code=403, detail="Sighting feedback disabled (SIGHTING_ENABLED=false)")

    success = await send_sighting(
        ioc_value=req.ioc_value,
        attribute_uuid=req.attribute_uuid,
        timestamp=req.timestamp,
    )
    if success:
        return {"status": "ok", "message": f"Sighting sent for {req.ioc_value}"}
    raise HTTPException(status_code=502, detail="Failed to send sighting to MISP")


# ── NIDS Rule Export ──────────────────────────────────────────────────────────

@router.get("/rules/{fmt}", tags=["NIDS Rules"], response_class=PlainTextResponse, dependencies=_auth)
async def get_nids_rules(fmt: str):
    """
    Download NIDS rules from MISP. Requires API key.
    fmt: snort | suricata
    """
    if fmt not in ("snort", "suricata"):
        raise HTTPException(status_code=400, detail="Format must be 'snort' or 'suricata'")
    try:
        rules = await fetch_nids_rules(fmt)
        return PlainTextResponse(content=rules, media_type="text/plain")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch NIDS rules from MISP: {exc}")
