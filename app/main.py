"""
MISP ↔ Mata Elang Integration Service — v1.1
=============================================
Startup sequence:
  1. Validate API keys configured (security gate — refuse to start if none)
  2. Connect Redis IOC store (if IOC_BACKEND=redis)
  3. Health-check MISP connectivity + API key
  4. Health-check OpenSearch connectivity
  5. Start APScheduler (periodic IOC sync)
  6. Run initial MISP IOC sync (populate store before accepting requests)
  7. Start Kafka consumer background task

All checks log clearly on startup so operators know exactly what is working.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.core.logging import logger
from app.core.security import check_keys_configured
from app.core.auth_middleware import APIKeyMiddleware
from app.services.ioc_store import ioc_store, RedisIOCStore
from app.services.misp_client import validate_misp_connection
from app.services.opensearch_client import startup_check as opensearch_startup_check
from app.services.scheduler import start_scheduler, stop_scheduler, sync_misp_iocs
from app.kafka.consumer import run_kafka_consumer

_kafka_stop_event: asyncio.Event = asyncio.Event()
_kafka_task: asyncio.Task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _kafka_task

    logger.info("=" * 60)
    logger.info("  %s v%s", settings.APP_NAME, settings.APP_VERSION)
    logger.info("=" * 60)

    # ── 1. Security gate ───────────────────────────────────────────────────────
    check_keys_configured()

    # ── 2. Connect Redis (if enabled) ──────────────────────────────────────────
    if isinstance(ioc_store, RedisIOCStore):
        await ioc_store.connect()
    else:
        logger.info("IOC backend: in-memory (fallback)")

    # ── 3. MISP health check ───────────────────────────────────────────────────
    misp_status = await validate_misp_connection()
    if not misp_status["authenticated"]:
        logger.warning(
            "MISP health check failed: %s — continuing, but sync will produce 0 IOCs",
            misp_status.get("error"),
        )

    # ── 4. OpenSearch health check ─────────────────────────────────────────────
    os_status = await opensearch_startup_check()
    if not os_status["authenticated"]:
        logger.warning(
            "OpenSearch health check failed: %s — enriched alerts will not be indexed",
            os_status.get("error"),
        )

    # ── 5. Start scheduler ─────────────────────────────────────────────────────
    start_scheduler()

    # ── 6. Initial IOC sync ────────────────────────────────────────────────────
    if misp_status["authenticated"]:
        logger.info("Running initial MISP IOC sync...")
        await sync_misp_iocs()
    else:
        logger.warning("Skipping initial sync — MISP not authenticated")

    # ── 7. Kafka consumer ──────────────────────────────────────────────────────
    _kafka_stop_event.clear()
    _kafka_task = asyncio.create_task(
        run_kafka_consumer(_kafka_stop_event),
        name="kafka-consumer",
    )
    logger.info("Kafka consumer task started (topic=%s)", settings.KAFKA_INPUT_TOPIC)
    logger.info("Service ready — listening on port 8080")

    yield  # ── Application runs ──────────────────────────────────────────────

    # ── Shutdown ───────────────────────────────────────────────────────────────
    logger.info("Shutting down...")

    _kafka_stop_event.set()
    if _kafka_task and not _kafka_task.done():
        try:
            await asyncio.wait_for(_kafka_task, timeout=10.0)
        except asyncio.TimeoutError:
            _kafka_task.cancel()
            logger.warning("Kafka consumer cancelled (timeout)")

    stop_scheduler()

    if isinstance(ioc_store, RedisIOCStore):
        await ioc_store.disconnect()

    logger.info("Shutdown complete")


# ── App factory ────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Integration middleware between MISP Threat Intelligence Platform "
        "and Mata Elang NIDS. v1.1 adds Redis-backed IOC persistence "
        "and inter-service API key authentication."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Auth middleware — enforces X-API-Key on all non-exempt paths
app.add_middleware(APIKeyMiddleware)

# CORS — tighten allow_origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }
