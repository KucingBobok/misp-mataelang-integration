"""
IOC Store — v1.1
=================
Two implementations behind a common abstract interface:

  InMemoryIOCStore  — v1.0 fallback (IOC_BACKEND=memory)
  RedisIOCStore     — v1.1 default  (IOC_BACKEND=redis)

Storage model in Redis (Hash per IOC):
  Key:   mataelang:ioc:<normalised_value>
  Type:  Hash  (HSET with all IOCRecord fields as string-encoded values)
  TTL:   IOC_TTL_SECONDS (EXPIRE set on every upsert)

Index key for stats:
  mataelang:ioc:__index__   (Redis Set of all active IOC keys)

This design allows:
  • O(1) lookup by normalised value
  • Atomic HSET + EXPIRE per IOC
  • Pipeline bulk-upsert in chunks for high-throughput syncs
  • TTL enforced natively by Redis — no background eviction thread needed
  • Persistence across service restarts (Redis RDB/AOF)
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import redis.asyncio as aioredis
from redis.asyncio import ConnectionPool
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.logging import logger
from app.models.ioc import IOCRecord

# ── Shared normalisation ───────────────────────────────────────────────────────

def _norm(value: str) -> str:
    return value.strip().lower()


# ══════════════════════════════════════════════════════════════════════════════
# Abstract interface
# ══════════════════════════════════════════════════════════════════════════════

class BaseIOCStore(ABC):
    @abstractmethod
    async def upsert(self, ioc: IOCRecord) -> None: ...

    @abstractmethod
    async def bulk_upsert(self, iocs: List[IOCRecord]) -> int: ...

    @abstractmethod
    async def lookup(self, value: str) -> Optional[IOCRecord]: ...

    @abstractmethod
    async def lookup_multi(self, values: List[str]) -> List[Tuple[str, Optional[IOCRecord]]]: ...

    @abstractmethod
    async def stats(self) -> Dict: ...

    @abstractmethod
    async def clear(self) -> None: ...

    # Optional — only Redis implements real eviction (TTL-based)
    async def evict_expired(self) -> int:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# In-memory implementation (v1.0 — fallback)
# ══════════════════════════════════════════════════════════════════════════════

class InMemoryIOCStore(BaseIOCStore):
    def __init__(self, ttl_seconds: int = settings.IOC_TTL_SECONDS):
        self._store: Dict[str, IOCRecord] = {}
        self._expiry: Dict[str, float] = {}
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()
        self._stats: Dict[str, int] = defaultdict(int)

    def _is_expired(self, key: str) -> bool:
        exp = self._expiry.get(key)
        return exp is not None and time.time() > exp

    async def upsert(self, ioc: IOCRecord) -> None:
        key = _norm(ioc.ioc_value)
        async with self._lock:
            self._store[key] = ioc
            self._expiry[key] = time.time() + self._ttl
            self._stats["upserted"] += 1

    async def bulk_upsert(self, iocs: List[IOCRecord]) -> int:
        count = 0
        async with self._lock:
            now = time.time()
            for ioc in iocs:
                key = _norm(ioc.ioc_value)
                self._store[key] = ioc
                self._expiry[key] = now + self._ttl
                count += 1
            self._stats["upserted"] += count
        return count

    async def lookup(self, value: str) -> Optional[IOCRecord]:
        key = _norm(value)
        async with self._lock:
            if key not in self._store:
                self._stats["miss"] += 1
                return None
            if self._is_expired(key):
                del self._store[key]
                del self._expiry[key]
                self._stats["expired"] += 1
                return None
            self._stats["hit"] += 1
            return self._store[key]

    async def lookup_multi(self, values: List[str]) -> List[Tuple[str, Optional[IOCRecord]]]:
        return [(v, await self.lookup(v)) for v in values]

    async def evict_expired(self) -> int:
        now = time.time()
        expired_keys = []
        async with self._lock:
            for k, exp in list(self._expiry.items()):
                if now > exp:
                    expired_keys.append(k)
            for k in expired_keys:
                self._store.pop(k, None)
                self._expiry.pop(k, None)
            self._stats["evicted"] += len(expired_keys)
        logger.info("IOC eviction: removed %d expired entries", len(expired_keys))
        return len(expired_keys)

    async def stats(self) -> Dict:
        async with self._lock:
            return {"backend": "memory", "total_iocs": len(self._store), **dict(self._stats)}

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()
            self._expiry.clear()
        logger.warning("IOC store cleared")


# ══════════════════════════════════════════════════════════════════════════════
# Redis implementation (v1.1)
# ══════════════════════════════════════════════════════════════════════════════

_INDEX_KEY = f"{settings.REDIS_KEY_PREFIX}:__index__"


def _ioc_redis_key(normalised_value: str) -> str:
    return f"{settings.REDIS_KEY_PREFIX}:{normalised_value}"


def _ioc_to_hash(ioc: IOCRecord) -> Dict[str, str]:
    """Serialise IOCRecord to a flat string dict for Redis HSET."""
    d = ioc.model_dump()
    result = {}
    for k, v in d.items():
        if v is None:
            result[k] = ""
        elif isinstance(v, list):
            result[k] = json.dumps(v)
        elif hasattr(v, "isoformat"):          # datetime
            result[k] = v.isoformat()
        else:
            result[k] = str(v)
    return result


def _hash_to_ioc(raw: Dict[bytes, bytes]) -> Optional[IOCRecord]:
    """Deserialise Redis hash bytes back to IOCRecord."""
    if not raw:
        return None
    try:
        d: Dict = {}
        for k, v in raw.items():
            key = k.decode() if isinstance(k, bytes) else k
            val = v.decode() if isinstance(v, bytes) else v
            d[key] = val if val != "" else None

        # Deserialise list fields
        for list_field in ("tags", "MISP_IOC_TYPES"):
            if list_field in d and d[list_field]:
                try:
                    d[list_field] = json.loads(d[list_field])
                except (json.JSONDecodeError, TypeError):
                    d[list_field] = []

        # Cast numeric fields
        for int_field in ("threat_level_id",):
            if d.get(int_field):
                try:
                    d[int_field] = int(d[int_field])
                except (ValueError, TypeError):
                    d[int_field] = None

        # Cast bool fields
        for bool_field in ("detectable",):
            if d.get(bool_field) is not None:
                d[bool_field] = d[bool_field].lower() in ("true", "1", "yes")

        return IOCRecord(**d)
    except Exception as exc:
        logger.warning("Failed to deserialise IOC hash from Redis: %s", exc)
        return None


class RedisIOCStore(BaseIOCStore):
    """
    Production IOC store backed by Redis.

    Connection pool is created once and reused across all operations.
    Call connect() during app startup, disconnect() during shutdown.
    """

    def __init__(self):
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[aioredis.Redis] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create connection pool and verify Redis is reachable."""
        pool_kwargs = dict(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            max_connections=settings.REDIS_POOL_MAX,
            socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            decode_responses=False,   # We handle bytes manually for flexibility
        )
        if settings.REDIS_PASSWORD:
            pool_kwargs["password"] = settings.REDIS_PASSWORD
        if settings.REDIS_TLS:
            pool_kwargs["ssl"] = True
            pool_kwargs["ssl_cert_reqs"] = "required" if settings.REDIS_TLS_VERIFY else "none"

        self._pool = aioredis.ConnectionPool(**pool_kwargs)
        self._client = aioredis.Redis(connection_pool=self._pool)

        # Connectivity check
        try:
            await self._client.ping()
            logger.info(
                "Redis IOC store connected: %s:%d db=%d",
                settings.REDIS_HOST, settings.REDIS_PORT, settings.REDIS_DB,
            )
        except RedisError as exc:
            logger.error("Redis connection failed: %s", exc)
            raise

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
        if self._pool:
            await self._pool.disconnect()
        logger.info("Redis IOC store disconnected")

    def _r(self) -> aioredis.Redis:
        if not self._client:
            raise RuntimeError("RedisIOCStore.connect() must be called before use")
        return self._client

    # ── Write operations ──────────────────────────────────────────────────────

    async def upsert(self, ioc: IOCRecord) -> None:
        key = _ioc_redis_key(_norm(ioc.ioc_value))
        r = self._r()
        async with r.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=_ioc_to_hash(ioc))
            pipe.expire(key, settings.IOC_TTL_SECONDS)
            pipe.sadd(_INDEX_KEY, _norm(ioc.ioc_value))
            await pipe.execute()

    async def bulk_upsert(self, iocs: List[IOCRecord]) -> int:
        """
        Chunked pipeline upsert.
        Each chunk is sent as a single pipeline to avoid one giant transaction.
        Chunk size is controlled by REDIS_PIPELINE_CHUNK (default 500).
        """
        if not iocs:
            return 0

        r = self._r()
        total = 0
        chunk_size = settings.REDIS_PIPELINE_CHUNK

        for i in range(0, len(iocs), chunk_size):
            chunk = iocs[i: i + chunk_size]
            async with r.pipeline(transaction=False) as pipe:
                for ioc in chunk:
                    norm_val = _norm(ioc.ioc_value)
                    key = _ioc_redis_key(norm_val)
                    pipe.hset(key, mapping=_ioc_to_hash(ioc))
                    pipe.expire(key, settings.IOC_TTL_SECONDS)
                    pipe.sadd(_INDEX_KEY, norm_val)
                await pipe.execute()
            total += len(chunk)
            logger.debug("Redis bulk upsert chunk %d/%d: %d IOCs", i // chunk_size + 1,
                         (len(iocs) + chunk_size - 1) // chunk_size, len(chunk))

        # Keep index set TTL alive (refresh to max IOC TTL)
        await r.expire(_INDEX_KEY, settings.IOC_TTL_SECONDS)
        logger.info("Redis bulk upsert complete: %d IOCs", total)
        return total

    # ── Read operations ───────────────────────────────────────────────────────

    async def lookup(self, value: str) -> Optional[IOCRecord]:
        key = _ioc_redis_key(_norm(value))
        try:
            raw = await self._r().hgetall(key)
            return _hash_to_ioc(raw) if raw else None
        except RedisError as exc:
            logger.error("Redis lookup error for %s: %s", value, exc)
            return None

    async def lookup_multi(self, values: List[str]) -> List[Tuple[str, Optional[IOCRecord]]]:
        """Parallel pipeline GET for multiple observables."""
        r = self._r()
        keys = [_ioc_redis_key(_norm(v)) for v in values]
        try:
            async with r.pipeline(transaction=False) as pipe:
                for k in keys:
                    pipe.hgetall(k)
                results = await pipe.execute()
            return [(v, _hash_to_ioc(raw) if raw else None)
                    for v, raw in zip(values, results)]
        except RedisError as exc:
            logger.error("Redis lookup_multi error: %s", exc)
            return [(v, None) for v in values]

    # ── Stats & maintenance ───────────────────────────────────────────────────

    async def stats(self) -> Dict:
        r = self._r()
        try:
            total = await r.scard(_INDEX_KEY)
            info = await r.info("stats")
            return {
                "backend": "redis",
                "total_iocs": total,
                "redis_host": settings.REDIS_HOST,
                "redis_db": settings.REDIS_DB,
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
            }
        except RedisError as exc:
            logger.error("Redis stats error: %s", exc)
            return {"backend": "redis", "error": str(exc)}

    async def clear(self) -> None:
        """Delete all IOC keys and the index. Use with caution."""
        r = self._r()
        members = await r.smembers(_INDEX_KEY)
        keys_to_del = [_ioc_redis_key(m.decode()) for m in members] + [_INDEX_KEY]
        if keys_to_del:
            await r.delete(*keys_to_del)
        logger.warning("Redis IOC store cleared: %d keys deleted", len(keys_to_del))

    # evict_expired → no-op: Redis handles TTL natively
    async def evict_expired(self) -> int:
        logger.debug("Redis TTL eviction is automatic — no manual eviction needed")
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# Factory — returns the configured backend
# ══════════════════════════════════════════════════════════════════════════════

def create_ioc_store() -> BaseIOCStore:
    backend = settings.IOC_BACKEND.strip().lower()
    if backend == "redis":
        logger.info("IOC backend: Redis (%s:%d)", settings.REDIS_HOST, settings.REDIS_PORT)
        return RedisIOCStore()
    else:
        logger.info("IOC backend: in-memory (TTL=%ds)", settings.IOC_TTL_SECONDS)
        return InMemoryIOCStore()


# Module-level singleton — initialised in app lifespan
ioc_store: BaseIOCStore = create_ioc_store()
