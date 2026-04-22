#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# MISP ↔ Mata Elang Integration Service v1.1 — curl Test Collection
# ══════════════════════════════════════════════════════════════════════════════
# Usage:
#   BASE_URL=http://localhost:8090 \
#   API_KEY=your_service_api_key \
#   bash tests/test_collection.sh
# ══════════════════════════════════════════════════════════════════════════════

BASE_URL="${BASE_URL:-http://localhost:8090}"
API_KEY="${API_KEY:-}"
PASS=0; FAIL=0

section() { echo; echo "══════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════"; }
ok()      { echo "  ✔ PASS: $1"; ((PASS++)); }
fail()    { echo "  ✘ FAIL: $1"; ((FAIL++)); }
check()   {
    local label="$1" expected="$2" actual="$3"
    [[ "$actual" == "$expected" ]] && ok "$label (HTTP $actual)" || fail "$label — expected $expected, got $actual"
}

AUTH_HEADER=""
if [[ -n "$API_KEY" ]]; then
    AUTH_HEADER="-H X-API-Key:${API_KEY}"
    echo "Using API key: ${API_KEY:0:8}..."
else
    echo "WARNING: API_KEY is not set. Protected endpoints will return HTTP 401."
fi

# ── 1. Health (public — no auth required) ─────────────────────────────────────
section "1. Health Check (public)"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
check "GET /health" "200" "$HTTP"
curl -s "$BASE_URL/health" | python3 -m json.tool 2>/dev/null

# ── 2. Auth rejection test ────────────────────────────────────────────────────
section "2. Auth Rejection (no key → expect 401)"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/sync/misp" -X POST)
check "POST /sync/misp (no key)" "401" "$HTTP"

# ── 3. Auth rejection — wrong key ────────────────────────────────────────────
section "3. Auth Rejection (wrong key → expect 401)"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/sync/misp" -X POST \
    -H "X-API-Key: wrongkey")
check "POST /sync/misp (wrong key)" "401" "$HTTP"

# ── 4. MISP Sync (requires auth) ──────────────────────────────────────────────
section "4. MISP IOC Sync"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST $AUTH_HEADER "$BASE_URL/sync/misp")
check "POST /sync/misp" "200" "$HTTP"
curl -s -X POST $AUTH_HEADER "$BASE_URL/sync/misp" | python3 -m json.tool 2>/dev/null

# ── 5. IOC Store Stats ────────────────────────────────────────────────────────
section "5. IOC Store Stats"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" $AUTH_HEADER "$BASE_URL/ioc/stats")
check "GET /ioc/stats" "200" "$HTTP"
curl -s $AUTH_HEADER "$BASE_URL/ioc/stats" | python3 -m json.tool 2>/dev/null

# ── 6. IOC Lookup — clean IP ─────────────────────────────────────────────────
section "6. IOC Lookup — clean IP"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" $AUTH_HEADER "$BASE_URL/ioc/search?value=8.8.8.8")
check "GET /ioc/search?value=8.8.8.8" "200" "$HTTP"
curl -s $AUTH_HEADER "$BASE_URL/ioc/search?value=8.8.8.8" | python3 -m json.tool 2>/dev/null

# ── 7. IOC Lookup — Tor exit node ────────────────────────────────────────────
section "7. IOC Lookup — Tor exit node"
curl -s $AUTH_HEADER "$BASE_URL/ioc/search?value=185.220.101.45" | python3 -m json.tool 2>/dev/null

# ── 8. Enrich Alert — clean IP ───────────────────────────────────────────────
section "8. Alert Enrichment — clean IP (miss expected)"
PAYLOAD='{"alert_id":"v11-clean-001","sensor_id":"sensor1","src_ip":"8.8.8.8","dst_ip":"10.10.10.5","signature":"DNS Query","timestamp":"2026-04-22T05:00:00"}'
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST $AUTH_HEADER \
    -H "Content-Type: application/json" -d "$PAYLOAD" "$BASE_URL/enrich/alert")
check "POST /enrich/alert (clean)" "200" "$HTTP"
curl -s -X POST $AUTH_HEADER -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$BASE_URL/enrich/alert" | python3 -m json.tool 2>/dev/null

# ── 9. Enrich Alert — Tor exit node ──────────────────────────────────────────
section "9. Alert Enrichment — Tor exit node"
PAYLOAD='{"alert_id":"v11-tor-001","sensor_id":"sensor1","src_ip":"185.220.101.45","dst_ip":"192.168.1.100","signature":"ET TOR Known Tor Exit Node","priority":1,"timestamp":"2026-04-22T05:00:00"}'
curl -s -X POST $AUTH_HEADER -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$BASE_URL/enrich/alert" | python3 -m json.tool 2>/dev/null

# ── 10. Enrich Alert — domain ────────────────────────────────────────────────
section "10. Alert Enrichment — domain"
PAYLOAD='{"alert_id":"v11-domain-001","sensor_id":"sensor1","src_ip":"192.168.1.50","domain":"malware-c2.example.com","signature":"DNS Query to Malicious Domain","timestamp":"2026-04-22T05:00:00"}'
curl -s -X POST $AUTH_HEADER -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$BASE_URL/enrich/alert" | python3 -m json.tool 2>/dev/null

# ── 11. Sighting feedback ────────────────────────────────────────────────────
section "11. Sighting Feedback"
PAYLOAD='{"ioc_value":"185.220.101.45","timestamp":"2026-04-22T05:00:00"}'
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST $AUTH_HEADER \
    -H "Content-Type: application/json" -d "$PAYLOAD" "$BASE_URL/sighting")
echo "  HTTP $HTTP (200=ok, 502=MISP unreachable)"
curl -s -X POST $AUTH_HEADER -H "Content-Type: application/json" \
    -d "$PAYLOAD" "$BASE_URL/sighting" | python3 -m json.tool 2>/dev/null

# ── 12. NIDS Rule Export ──────────────────────────────────────────────────────
section "12. NIDS Rules — Snort"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" $AUTH_HEADER "$BASE_URL/rules/snort")
echo "  HTTP $HTTP"
curl -s $AUTH_HEADER "$BASE_URL/rules/snort" | head -3

section "12b. NIDS Rules — Suricata"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" $AUTH_HEADER "$BASE_URL/rules/suricata")
echo "  HTTP $HTTP"
curl -s $AUTH_HEADER "$BASE_URL/rules/suricata" | head -3

# ── 13. Clear IOC store ───────────────────────────────────────────────────────
section "13. Clear IOC Store (admin)"
echo "  Skipped — uncomment to test (destructive)"
# HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE $AUTH_HEADER "$BASE_URL/ioc/store")
# check "DELETE /ioc/store" "200" "$HTTP"

# ── Summary ───────────────────────────────────────────────────────────────────
section "Test Summary"
TOTAL=$((PASS + FAIL))
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL / $TOTAL"
[[ $FAIL -eq 0 ]] && echo "  Status: ALL TESTS PASSED" || echo "  Status: SOME TESTS FAILED"
