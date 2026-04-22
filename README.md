# MISP ↔ Mata Elang NIDS Integration Service — v1.1

Upgrade dari v1.0 dengan dua fitur utama:
- **Redis-backed IOC persistence** — IOC tetap tersimpan saat service restart, bulk-upsert via pipeline, TTL dikelola native oleh Redis
- **Inter-service authentication** — semua endpoint (kecuali `/health`) wajib menyertakan `X-API-Key` header; service menolak start jika tidak ada key yang dikonfigurasi

---

## Perubahan v1.0 → v1.1

| Aspek | v1.0 | v1.1 |
|-------|------|------|
| IOC Storage | In-memory (hilang saat restart) | Redis Hash + EXPIRE (persisten) |
| IOC Bulk Upsert | asyncio.Lock | Redis Pipeline (chunked, non-blocking) |
| IOC TTL Eviction | Background thread | Native Redis EXPIRE — otomatis |
| Auth REST API | Tidak ada | `X-API-Key` header (wajib, constant-time compare) |
| Auth Redis | Tidak ada | `--requirepass` + password env |
| Auth OpenSearch | Admin user | Dedicated role `misp_integration_role` |
| MISP Health Check | Tidak ada | `GET /users/view/me` saat startup |
| MISP Retry | Tidak ada | Exponential back-off (max 3x) |
| Kafka Error Handling | Basic | Dead-letter log + max 10 consecutive error bail-out |
| Container User | root | Non-root (`mataelang` user) |
| API Route Guard | Tidak ada | `APIKeyMiddleware` (Starlette-level, sebelum routing) |

---

## Arsitektur

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Mata Elang Stack                               │
│                                                                        │
│  Snort3 Sensor ──gRPC──► sensor-api ──Kafka──► event-stream-aggr       │
│                                                       │                │
│                                               snort_alerts topic       │
│                                                       │                │
│  ┌────────────────────────────────────────────────────▼─────────────┐  │
│  │               MISP Integration Service  v1.1                     │  │
│  │                                                                  │  │
│  │  ┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐ │  │
│  │  │ APIKey       │    │  Scheduler      │    │  Kafka Consumer │ │  │
│  │  │ Middleware   │    │  (APScheduler)  │    │  (mTLS SSL)     │ │  │
│  │  └──────┬───────┘    └────────┬────────┘    └────────┬────────┘ │  │
│  │         │                    │                        │          │  │
│  │         ▼                    ▼                        ▼          │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │                  FastAPI REST API                           │ │  │
│  │  │  /health /sync/misp /ioc/search /enrich/alert /sighting    │ │  │
│  │  └──────────────┬──────────────────────────┬──────────────────┘ │  │
│  │                 │                          │                     │  │
│  │  ┌──────────────▼────────────┐   ┌────────▼────────────────┐   │  │
│  │  │  Redis IOC Store  (v1.1)  │   │  Enrichment Engine      │   │  │
│  │  │  Hash per IOC             │   │  IOC lookup → context   │   │  │
│  │  │  Native TTL (EXPIRE)      │   │  → Sighting feedback    │   │  │
│  │  │  Pipeline bulk-upsert     │   └────────┬────────────────┘   │  │
│  │  └───────────────────────────┘            │                     │  │
│  │                                           ▼                     │  │
│  │                                  ┌─────────────────────────┐   │  │
│  │  MISP Server ◄──── /sightings ── │  OpenSearch             │   │  │
│  │      │                           │  misp-enriched-alerts   │   │  │
│  │      └── /attributes/restSearch →│  misp-ioc-store         │   │  │
│  │                                  └─────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Setup v1.1

### 1. Generate API Key

```bash
python scripts/generate_api_key.py
# Output: Key 1: aBcDeFgHiJkL...
```

### 2. Konfigurasi `.env`

```bash
cp .env.example .env
nano .env
```

Wajib diisi:
```env
SERVICE_API_KEY=<hasil generate_api_key.py>
MISP_URL=https://misp.contoh.com
MISP_API_KEY=<dari MISP Administration > Auth Keys>
REDIS_PASSWORD=<password kuat untuk Redis>
OPENSEARCH_USERNAME=misp_integration_user
OPENSEARCH_PASSWORD=<dari opensearch_setup.sh>
KAFKA_SSL_KEY_PASSWORD=<SSL_PASSWORD dari Mata Elang .env>
```

### 3. Setup OpenSearch User (sekali saja)

```bash
OPENSEARCH_URL=https://opensearch-node1:9200 \
ADMIN_PASSWORD=SecurePassword@123 \
MISP_USER_PASSWORD=MispIntegration@2026 \
bash scripts/opensearch_setup.sh
```

Script ini membuat:
- Role `misp_integration_role` — hanya izin write ke `misp-*` index
- User `misp_integration_user` — service account dedicated
- Role mapping user → role

### 4. Deploy

```bash
# Mata Elang harus sudah berjalan
cd defense_center && docker compose up -d

# Jalankan integration service
cd ../misp-mataelang-integration-v1.1
docker compose -f compose.misp.yml --env-file .env up -d
```

### 5. Verifikasi

```bash
# Health (public — tidak perlu key)
curl http://localhost:8090/health

# Sync IOC (memerlukan key)
curl -X POST http://localhost:8090/sync/misp \
     -H "X-API-Key: YOUR_KEY"

# IOC stats
curl http://localhost:8090/ioc/stats \
     -H "X-API-Key: YOUR_KEY"
```

### 6. Test collection

```bash
chmod +x tests/test_collection.sh
BASE_URL=http://localhost:8090 \
API_KEY=YOUR_KEY \
bash tests/test_collection.sh
```

---

## Redis Storage Model

```
Redis Key Pattern:  mataelang:ioc:<normalised_value>
Redis Type:         Hash (field per IOCRecord attribute)
Redis TTL:          IOC_TTL_SECONDS (default 86400 = 24 jam)
Index Key:          mataelang:ioc:__index__  (Redis Set of all active keys)

Contoh:
  HGETALL mataelang:ioc:185.220.101.45
  → {
      "ioc_id": "uuid-...",
      "ioc_value": "185.220.101.45",
      "ioc_type": "ip-src",
      "detectable": "True",
      "event_uuid": "...",
      "event_info": "Tor Exit Nodes",
      "threat_level": "High",
      "tags": "[\"tlp:white\",\"misp-galaxy:threat-actor=Tor\"]",
      ...
    }
```

---

## API Reference

| Method | Endpoint | Auth | Deskripsi |
|--------|----------|------|-----------|
| `GET` | `/health` | Tidak | Status, IOC stats, last sync |
| `POST` | `/sync/misp` | Ya | Trigger manual IOC sync |
| `GET` | `/ioc/stats` | Ya | Statistik IOC store (Redis keyspace hits/miss) |
| `GET` | `/ioc/search?value=X` | Ya | Lookup observable tunggal |
| `DELETE` | `/ioc/store` | Ya | Hapus semua IOC (admin) |
| `POST` | `/enrich/alert` | Ya | Enrich alert Mata Elang |
| `POST` | `/sighting` | Ya | Kirim sighting ke MISP |
| `GET` | `/rules/{fmt}` | Ya | Download rule Snort/Suricata |

Semua protected endpoint mengembalikan HTTP 401 jika `X-API-Key` tidak ada atau salah.

---

## File Baru di v1.1

| File | Fungsi |
|------|--------|
| `app/core/security.py` | `validate_api_key()`, `require_api_key()` dependency, `check_keys_configured()` |
| `app/core/auth_middleware.py` | Starlette middleware — enforces auth sebelum routing |
| `scripts/generate_api_key.py` | Generate cryptographically secure API key |
| `scripts/opensearch_setup.sh` | Buat dedicated OpenSearch user + role |

---

## Roadmap

| Versi | Fitur |
|-------|-------|
| v1.0 | In-memory IOC store, REST enrichment ✅ |
| v1.1 | Redis persistence, API key auth ✅ |
| v1.2 | ZMQ pub-sub MISP (real-time, gantikan polling) |
| v1.3 | Rule feed auto-update untuk Snort3 |
| v2.0 | SOAR playbook trigger berdasarkan threat_level MISP |
