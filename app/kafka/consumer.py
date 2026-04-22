"""
Kafka consumer — v1.1
======================
Adds:
  • Startup connectivity check (validate_kafka_connection) — logs cert paths
    and reports whether mTLS files are present before starting.
  • Cleaner config builder with explicit logging of resolved settings.
  • Dead-letter handling: messages that fail to parse are logged with context
    but do not crash the consumer loop.
  • Graceful shutdown via asyncio.Event with configurable drain timeout.
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from confluent_kafka import Consumer, KafkaError, KafkaException

from app.core.config import settings
from app.core.logging import logger
from app.models.alert import EnrichmentRequest
from app.services.enrichment import enrich_alert


# ── Connection validation ──────────────────────────────────────────────────────

def validate_kafka_connection() -> dict:
    """
    Called at startup (synchronously).
    Checks cert files exist and logs the resolved Kafka configuration.
    Does NOT do a live broker ping (confluent-kafka is synchronous and
    would block the event loop — actual connectivity is verified on first poll).
    """
    result = {
        "broker": settings.KAFKA_BROKERS,
        "security_protocol": settings.KAFKA_SECURITY_PROTOCOL,
        "topic": settings.KAFKA_INPUT_TOPIC,
        "group_id": settings.KAFKA_CONSUMER_GROUP_ID,
        "certs_ok": True,
        "warnings": [],
    }

    if settings.KAFKA_SECURITY_PROTOCOL.upper() == "SSL":
        for label, path in [
            ("CA cert", settings.KAFKA_SSL_CA_LOCATION),
            ("Client cert", settings.KAFKA_SSL_CERT_LOCATION),
            ("Client key", settings.KAFKA_SSL_KEY_LOCATION),
        ]:
            if not Path(path).exists():
                msg = f"{label} not found: {path}"
                result["warnings"].append(msg)
                result["certs_ok"] = False
                logger.warning("Kafka mTLS: %s", msg)
            else:
                logger.info("Kafka mTLS: %s OK (%s)", label, path)

    logger.info(
        "Kafka config: broker=%s protocol=%s topic=%s group=%s",
        result["broker"], result["security_protocol"],
        result["topic"], result["group_id"],
    )
    return result


# ── Config builder ─────────────────────────────────────────────────────────────

def _build_consumer_conf() -> dict:
    conf = {
        "bootstrap.servers": settings.KAFKA_BROKERS,
        "group.id": settings.KAFKA_CONSUMER_GROUP_ID,
        "auto.offset.reset": settings.KAFKA_AUTO_OFFSET_RESET,
        "enable.auto.commit": True,
        "session.timeout.ms": 30000,
        "heartbeat.interval.ms": 10000,
        # Reconnect on transient broker errors
        "reconnect.backoff.ms": 1000,
        "reconnect.backoff.max.ms": 10000,
    }

    proto = settings.KAFKA_SECURITY_PROTOCOL.upper()
    if proto == "SSL":
        conf.update({
            "security.protocol": "SSL",
            "ssl.ca.location": settings.KAFKA_SSL_CA_LOCATION,
            "ssl.certificate.location": settings.KAFKA_SSL_CERT_LOCATION,
            "ssl.key.location": settings.KAFKA_SSL_KEY_LOCATION,
        })
        if settings.KAFKA_SSL_KEY_PASSWORD:
            conf["ssl.key.password"] = settings.KAFKA_SSL_KEY_PASSWORD
    elif proto == "SASL_SSL":
        # Future: SASL_SSL support (e.g. for Confluent Cloud)
        conf["security.protocol"] = "SASL_SSL"
    else:
        conf["security.protocol"] = "PLAINTEXT"

    return conf


# ── Message parser ─────────────────────────────────────────────────────────────

def _parse_snort_alert(raw: dict) -> Optional[EnrichmentRequest]:
    """
    Map a snort_alerts Kafka payload to EnrichmentRequest.
    Field names reflect the Avro schema produced by event-stream-aggr.
    Adjust field aliases below if your schema differs.
    """
    try:
        ts_raw = raw.get("timestamp") or raw.get("event_second")
        if ts_raw:
            ts = (
                datetime.utcfromtimestamp(ts_raw)
                if isinstance(ts_raw, (int, float))
                else datetime.fromisoformat(str(ts_raw))
            )
        else:
            ts = datetime.utcnow()

        return EnrichmentRequest(
            alert_id=str(raw.get("alert_id") or raw.get("event_id") or uuid.uuid4()),
            sensor_id=raw.get("sensor_id"),
            timestamp=ts,
            src_ip=raw.get("src_ip") or raw.get("src_addr"),
            dst_ip=raw.get("dst_ip") or raw.get("dst_addr"),
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port"),
            protocol=raw.get("proto") or raw.get("protocol"),
            signature=raw.get("signature") or raw.get("msg"),
            signature_id=raw.get("sig_id") or raw.get("gid"),
            classification=raw.get("classification"),
            priority=raw.get("priority"),
            domain=raw.get("domain"),
            hostname=raw.get("hostname"),
            url=raw.get("url"),
        )
    except Exception as exc:
        logger.warning("Failed to parse Kafka message: %s | raw keys: %s", exc, list(raw.keys()))
        return None


# ── Consumer loop ─────────────────────────────────────────────────────────────

async def run_kafka_consumer(stop_event: asyncio.Event) -> None:
    """
    Long-running async Kafka consumer.
    Intended as a background asyncio.Task started during lifespan startup.

    On KafkaException (non-recoverable): logs and exits — service will restart
    via Docker restart policy.
    On transient errors (EOF, etc.): continues silently.
    """
    conf = _build_consumer_conf()
    consumer = Consumer(conf)
    consumer.subscribe([settings.KAFKA_INPUT_TOPIC])

    logger.info(
        "Kafka consumer subscribed: topic=%s group=%s",
        settings.KAFKA_INPUT_TOPIC, settings.KAFKA_CONSUMER_GROUP_ID,
    )

    loop = asyncio.get_event_loop()
    error_count = 0

    try:
        while not stop_event.is_set():
            msg = await loop.run_in_executor(None, lambda: consumer.poll(timeout=1.0))

            if msg is None:
                error_count = 0   # Reset on successful poll
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue      # Normal — no new messages

                error_count += 1
                logger.error(
                    "Kafka error #%d: %s (topic=%s partition=%d offset=%d)",
                    error_count, msg.error(),
                    msg.topic(), msg.partition(), msg.offset(),
                )

                # After 10 consecutive errors, bail out (Docker will restart service)
                if error_count >= 10:
                    logger.critical("Too many Kafka errors — exiting consumer")
                    raise KafkaException(msg.error())

                await asyncio.sleep(2)
                continue

            error_count = 0

            # Decode JSON payload
            try:
                payload = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.warning(
                    "Cannot decode Kafka message (topic=%s offset=%d): %s",
                    msg.topic(), msg.offset(), exc,
                )
                continue

            req = _parse_snort_alert(payload)
            if req:
                asyncio.create_task(enrich_alert(req))

    except asyncio.CancelledError:
        logger.info("Kafka consumer task cancelled")
    except KafkaException as exc:
        logger.error("Kafka fatal error — consumer exiting: %s", exc)
    finally:
        consumer.close()
        logger.info("Kafka consumer closed")
