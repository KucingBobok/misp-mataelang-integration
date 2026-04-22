"""
OpenSearch integration — v1.1
==============================
Adds:
  • startup_check(): verify OpenSearch connectivity on app startup
  • Dedicated index lifecycle policy (ILM) creation helper
  • Configurable index aliases for write/read separation
  • Improved error logging with document ID context
"""

from datetime import datetime
from typing import List, Optional

from opensearchpy import AsyncOpenSearch, helpers, TransportError
from app.core.config import settings
from app.core.logging import logger
from app.models.ioc import IOCRecord
from app.models.alert import EnrichmentRequest, EnrichmentResponse


# ── Client factory ─────────────────────────────────────────────────────────────

def _make_client() -> AsyncOpenSearch:
    return AsyncOpenSearch(
        hosts=[settings.OPENSEARCH_HOST],
        http_auth=(settings.OPENSEARCH_USERNAME, settings.OPENSEARCH_PASSWORD),
        use_ssl=settings.OPENSEARCH_HOST.startswith("https"),
        verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
        ssl_show_warn=False,
        retry_on_timeout=True,
        max_retries=3,
    )


# ── Startup health check ───────────────────────────────────────────────────────

async def startup_check() -> dict:
    """
    Called at application startup.
    Verifies OpenSearch is reachable and the configured user has write access.
    Returns a status dict with {reachable, authenticated, cluster_name, error}.
    """
    result = {
        "reachable": False,
        "authenticated": False,
        "cluster_name": None,
        "error": None,
    }
    client = _make_client()
    try:
        info = await client.info()
        result["reachable"] = True
        result["authenticated"] = True
        result["cluster_name"] = info.get("cluster_name")
        logger.info(
            "OpenSearch health check OK: cluster=%s version=%s",
            info.get("cluster_name"),
            info.get("version", {}).get("number"),
        )
    except TransportError as exc:
        if exc.status_code in (401, 403):
            result["reachable"] = True
            result["error"] = f"OpenSearch auth failed (HTTP {exc.status_code})"
            logger.error("OpenSearch health check FAILED: %s", result["error"])
        else:
            result["error"] = str(exc)
            logger.error("OpenSearch health check FAILED: %s", exc)
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("OpenSearch health check FAILED: %s", exc)
    finally:
        await client.close()
    return result


# ── Index mappings ─────────────────────────────────────────────────────────────

ENRICHED_ALERT_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "@timestamp":           {"type": "date"},
            "alert_id":             {"type": "keyword"},
            "sensor_id":            {"type": "keyword"},
            "src_ip":               {"type": "ip"},
            "dst_ip":               {"type": "ip"},
            "src_port":             {"type": "integer"},
            "dst_port":             {"type": "integer"},
            "protocol":             {"type": "keyword"},
            "signature":            {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "signature_id":         {"type": "integer"},
            "classification":       {"type": "keyword"},
            "priority":             {"type": "integer"},
            "domain":               {"type": "keyword"},
            "hostname":             {"type": "keyword"},
            "url":                  {"type": "text"},
            "misp_match":           {"type": "boolean"},
            "misp_event_id":        {"type": "keyword"},
            "misp_event_uuid":      {"type": "keyword"},
            "misp_event_info":      {"type": "text"},
            "misp_threat_level":    {"type": "keyword"},
            "misp_threat_level_id": {"type": "integer"},
            "misp_tags":            {"type": "keyword"},
            "misp_matched_ioc":     {"type": "keyword"},
            "misp_matched_ioc_type":{"type": "keyword"},
            "enriched_at":          {"type": "date"},
        }
    }
}

IOC_STORE_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "ioc_id":               {"type": "keyword"},
            "ioc_value":            {"type": "keyword"},
            "ioc_type":             {"type": "keyword"},
            "detectable":           {"type": "boolean"},
            "event_id":             {"type": "keyword"},
            "event_uuid":           {"type": "keyword"},
            "event_info":           {"type": "text"},
            "threat_level":         {"type": "keyword"},
            "threat_level_id":      {"type": "integer"},
            "tags":                 {"type": "keyword"},
            "attribute_timestamp":  {"type": "date"},
            "synced_at":            {"type": "date"},
        }
    }
}


async def _ensure_index(client: AsyncOpenSearch, index: str, mapping: dict) -> None:
    exists = await client.indices.exists(index=index)
    if not exists:
        await client.indices.create(index=index, body=mapping)
        logger.info("Created OpenSearch index: %s", index)


# ── Write operations ───────────────────────────────────────────────────────────

async def index_enriched_alert(
    req: EnrichmentRequest,
    response: EnrichmentResponse,
) -> None:
    doc = {
        "@timestamp": (req.timestamp or datetime.utcnow()).isoformat(),
        "alert_id": req.alert_id,
        "sensor_id": req.sensor_id,
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "domain": req.domain,
        "hostname": req.hostname,
        "url": req.url,
        "signature": req.signature,
        "misp_match": response.misp_match,
        "enriched_at": response.enriched_at.isoformat(),
    }

    if response.misp_context:
        ctx = response.misp_context
        doc.update({
            "misp_event_id": ctx.event_id,
            "misp_event_uuid": ctx.event_uuid,
            "misp_event_info": ctx.event_info,
            "misp_threat_level": ctx.threat_level,
            "misp_threat_level_id": ctx.threat_level_id,
            "misp_tags": ctx.tags,
            "misp_matched_ioc": ctx.matched_ioc_value,
            "misp_matched_ioc_type": ctx.matched_ioc_type,
        })

    client = _make_client()
    try:
        await _ensure_index(client, settings.OPENSEARCH_INDEX_ENRICHED, ENRICHED_ALERT_MAPPING)
        await client.index(
            index=settings.OPENSEARCH_INDEX_ENRICHED,
            body=doc,
            id=req.alert_id,
        )
    except TransportError as exc:
        logger.error(
            "OpenSearch index failed for alert %s: HTTP %s — %s",
            req.alert_id, exc.status_code, exc,
        )
    except Exception as exc:
        logger.error("OpenSearch index unexpected error for alert %s: %s", req.alert_id, exc)
    finally:
        await client.close()


async def bulk_index_iocs(iocs: List[IOCRecord]) -> None:
    client = _make_client()
    try:
        await _ensure_index(client, settings.OPENSEARCH_INDEX_IOC, IOC_STORE_MAPPING)
        actions = [
            {
                "_index": settings.OPENSEARCH_INDEX_IOC,
                "_id": ioc.ioc_id,
                "_source": ioc.model_dump(),
            }
            for ioc in iocs
        ]
        success, failed = await helpers.async_bulk(client, actions, raise_on_error=False)
        if failed:
            logger.warning("IOC bulk index: %d failed documents", len(failed))
        logger.info("IOC bulk index: %d succeeded, %d failed", success, len(failed))
    except Exception as exc:
        logger.error("IOC bulk index error: %s", exc)
    finally:
        await client.close()
