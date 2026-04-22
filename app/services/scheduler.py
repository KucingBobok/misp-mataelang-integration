"""
Scheduler — v1.1
=================
Unchanged job logic; updated to call Redis-aware ioc_store
and to expose last_sync_status for the /health endpoint.
"""

from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.core.logging import logger
from app.services.misp_client import fetch_all_iocs
from app.services.ioc_store import ioc_store
from app.services.opensearch_client import bulk_index_iocs

scheduler = AsyncIOScheduler(timezone="UTC")
_last_sync: dict = {"timestamp": None, "ioc_count": 0, "status": "never_run"}


async def sync_misp_iocs() -> dict:
    global _last_sync
    logger.info("Starting MISP IOC sync...")
    started = datetime.utcnow()

    try:
        iocs = await fetch_all_iocs()

        if not iocs:
            logger.warning("MISP sync returned 0 IOCs — check MISP connectivity and filter params")
            _last_sync = {"timestamp": started.isoformat(), "ioc_count": 0, "status": "empty"}
            return _last_sync

        count = await ioc_store.bulk_upsert(iocs)
        logger.info("IOC store updated: %d records upserted", count)

        await bulk_index_iocs(iocs)

        _last_sync = {
            "timestamp": started.isoformat(),
            "ioc_count": count,
            "status": "ok",
            "duration_seconds": round((datetime.utcnow() - started).total_seconds(), 2),
        }
        logger.info(
            "MISP sync complete: %d IOCs in %.1fs",
            count, (datetime.utcnow() - started).total_seconds(),
        )

    except Exception as exc:
        _last_sync = {
            "timestamp": started.isoformat(),
            "ioc_count": 0,
            "status": f"error: {exc}",
        }
        logger.error("MISP sync failed: %s", exc)

    return _last_sync


async def evict_expired_iocs() -> None:
    await ioc_store.evict_expired()


def get_last_sync_status() -> dict:
    return _last_sync


def start_scheduler() -> None:
    if not settings.SYNC_ENABLED:
        logger.info("MISP sync scheduler disabled via SYNC_ENABLED=false")
        return

    scheduler.add_job(
        sync_misp_iocs,
        trigger=IntervalTrigger(seconds=settings.SYNC_INTERVAL_SECONDS),
        id="misp_ioc_sync",
        name="MISP IOC Sync",
        replace_existing=True,
        max_instances=1,
    )

    # Eviction is a no-op for Redis (TTL-native) but kept for memory-backend compatibility
    scheduler.add_job(
        evict_expired_iocs,
        trigger=IntervalTrigger(hours=1),
        id="ioc_eviction",
        name="IOC Store Eviction",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(
        "Scheduler started — MISP sync every %ds",
        settings.SYNC_INTERVAL_SECONDS,
    )


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
