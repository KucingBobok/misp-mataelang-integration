"""
Configuration management — v1.1
Adds: Redis backend settings, inter-service API key auth, OpenSearch dedicated user.
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List, Optional
import secrets


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "MISP-MataElang Integration Service"
    APP_VERSION: str = "1.1.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── Inter-Service Authentication ───────────────────────────────────────────
    # API keys that are allowed to call this service's REST endpoints.
    # Comma-separated list — generate with: python -c "import secrets; print(secrets.token_hex(32))"
    # Example: "key-abc123,key-def456"
    SERVICE_API_KEYS: str = ""

    # Single convenience key — used when SERVICE_API_KEYS is empty.
    # If both are empty the service will REFUSE to start (security requirement v1.1).
    SERVICE_API_KEY: str = ""

    # Header name clients must send
    API_KEY_HEADER: str = "X-API-Key"

    # Paths that bypass API key auth (comma-separated)
    AUTH_EXEMPT_PATHS: str = "/health,/docs,/redoc,/openapi.json,/"

    # ── MISP ───────────────────────────────────────────────────────────────────
    MISP_URL: str = "https://misp.example.com"
    MISP_API_KEY: str = ""
    MISP_VERIFY_TLS: bool = True
    MISP_TIMEOUT: int = 30

    MISP_IOC_TYPES: List[str] = [
        "ip-src", "ip-dst", "domain", "hostname", "url"
    ]
    MISP_PUBLISH_TIMESTAMP: str = "24h"
    MISP_PAGE_SIZE: int = 200
    MISP_ENFORCE_WARNINGLIST: bool = True

    # ── Sync Scheduler ─────────────────────────────────────────────────────────
    SYNC_INTERVAL_SECONDS: int = 600
    SYNC_ENABLED: bool = True

    # ── Kafka ─────────────────────────────────────────────────────────────────
    KAFKA_BROKERS: str = "broker:19094"
    KAFKA_SECURITY_PROTOCOL: str = "SSL"
    KAFKA_SSL_CA_LOCATION: str = "/certs/ca.pem"
    KAFKA_SSL_CERT_LOCATION: str = "/certs/client.pem"
    KAFKA_SSL_KEY_LOCATION: str = "/certs/client.key"
    KAFKA_SSL_KEY_PASSWORD: str = ""

    KAFKA_INPUT_TOPIC: str = "snort_alerts"
    KAFKA_OUTPUT_TOPIC: str = "misp_enriched_alerts"
    KAFKA_CONSUMER_GROUP_ID: str = "misp-integration-service"
    KAFKA_AUTO_OFFSET_RESET: str = "latest"

    # ── OpenSearch ─────────────────────────────────────────────────────────────
    OPENSEARCH_HOST: str = "https://opensearch-node1:9200"
    OPENSEARCH_USERNAME: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_VERIFY_CERTS: bool = False
    OPENSEARCH_INDEX_ENRICHED: str = "misp-enriched-alerts"
    OPENSEARCH_INDEX_IOC: str = "misp-ioc-store"

    # ── Redis IOC Store (v1.1) ─────────────────────────────────────────────────
    # IOC_BACKEND controls which store implementation is used.
    # "redis"  → RedisIOCStore  (v1.1 default)
    # "memory" → InMemoryIOCStore (v1.0 fallback)
    IOC_BACKEND: str = "redis"

    REDIS_HOST: str = "misp-redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""          # Set a strong password in production
    REDIS_TLS: bool = False
    REDIS_TLS_VERIFY: bool = True
    REDIS_POOL_MIN: int = 2
    REDIS_POOL_MAX: int = 20
    REDIS_CONNECT_TIMEOUT: int = 5    # seconds
    REDIS_SOCKET_TIMEOUT: int = 5     # seconds

    # Redis key namespace prefix — change if sharing a Redis instance
    REDIS_KEY_PREFIX: str = "mataelang:ioc"

    # IOC TTL in seconds (86400 = 24 h).  Also applied as Redis EXPIRE.
    IOC_TTL_SECONDS: int = 86400

    # Bulk pipeline chunk size — avoids sending one huge MULTI/EXEC per sync
    REDIS_PIPELINE_CHUNK: int = 500

    # ── Sighting Feedback ──────────────────────────────────────────────────────
    SIGHTING_ENABLED: bool = True
    SIGHTING_SOURCE: str = "Mata Elang NIDS"

    # ── Derived helpers ────────────────────────────────────────────────────────
    @property
    def allowed_api_keys(self) -> List[str]:
        """Return merged set of allowed keys from both env vars."""
        keys = []
        if self.SERVICE_API_KEYS:
            keys.extend([k.strip() for k in self.SERVICE_API_KEYS.split(",") if k.strip()])
        if self.SERVICE_API_KEY:
            keys.append(self.SERVICE_API_KEY.strip())
        return list(set(keys))

    @property
    def exempt_paths(self) -> List[str]:
        return [p.strip() for p in self.AUTH_EXEMPT_PATHS.split(",") if p.strip()]

    @property
    def redis_url(self) -> str:
        scheme = "rediss" if self.REDIS_TLS else "redis"
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"{scheme}://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    model_config = {"env_file": ".env", "case_sensitive": True}


settings = Settings()
