"""
Alert enrichment engine.

Given a Mata Elang alert, looks up all observable network fields
(src_ip, dst_ip, domain, hostname, url) against the IOC store.
Returns the first match with full MISP context.
"""

from typing import Optional, List
from datetime import datetime

from app.models.alert import EnrichmentRequest, EnrichmentResponse, MISPContext
from app.models.ioc import IOCRecord
from app.services.ioc_store import ioc_store
from app.services.opensearch_client import index_enriched_alert
from app.services.misp_client import send_sighting
from app.core.logging import logger


def _extract_observables(req: EnrichmentRequest) -> List[str]:
    """Collect all non-null network observables from the alert."""
    candidates = []
    for field in (req.src_ip, req.dst_ip, req.domain, req.hostname, req.url):
        if field and field.strip():
            candidates.append(field.strip())
    return candidates


def _build_misp_context(ioc: IOCRecord) -> MISPContext:
    return MISPContext(
        matched_ioc_value=ioc.ioc_value,
        matched_ioc_type=ioc.ioc_type,
        event_id=ioc.event_id,
        event_uuid=ioc.event_uuid,
        event_info=ioc.event_info,
        threat_level_id=ioc.threat_level_id,
        threat_level=ioc.threat_level,
        tags=ioc.tags,
    )


async def enrich_alert(req: EnrichmentRequest) -> EnrichmentResponse:
    """
    Main enrichment pipeline:
      1. Extract observables from alert.
      2. Look each up in the IOC store.
      3. On first match, build MISPContext.
      4. Index the enriched alert to OpenSearch.
      5. Optionally send a sighting back to MISP.
    """
    observables = _extract_observables(req)
    matched_ioc: Optional[IOCRecord] = None
    matched_value: Optional[str] = None

    for obs in observables:
        ioc = await ioc_store.lookup(obs)
        if ioc:
            matched_ioc = ioc
            matched_value = obs
            logger.info(
                "IOC match: alert_id=%s observable=%s ioc_type=%s event_uuid=%s",
                req.alert_id, obs, ioc.ioc_type, ioc.event_uuid,
            )
            break

    if matched_ioc:
        context = _build_misp_context(matched_ioc)
        response = EnrichmentResponse(
            alert_id=req.alert_id,
            misp_match=True,
            misp_context=context,
            message=f"Matched IOC: {matched_ioc.ioc_value} [{matched_ioc.ioc_type}]",
        )

        # Index to OpenSearch
        await index_enriched_alert(req, response)

        # Send sighting to MISP
        await send_sighting(
            ioc_value=matched_ioc.ioc_value,
            attribute_uuid=matched_ioc.ioc_id if matched_ioc.ioc_id else None,
            timestamp=req.timestamp or datetime.utcnow(),
        )
    else:
        response = EnrichmentResponse(
            alert_id=req.alert_id,
            misp_match=False,
            message="No IOC match found",
        )
        # Still index to OpenSearch (as raw/non-enriched alert)
        await index_enriched_alert(req, response)

    return response
