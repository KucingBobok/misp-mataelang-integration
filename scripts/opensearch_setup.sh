#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# OpenSearch Dedicated User & Role Setup — v1.1
# ══════════════════════════════════════════════════════════════════════════════
# Creates a dedicated OpenSearch role 'misp_integration_role' with minimal
# write permissions for the two integration indices, then assigns it to
# a dedicated user 'misp_integration_user'.
#
# Run ONCE against your running OpenSearch instance:
#   OPENSEARCH_URL=https://localhost:9200 \
#   ADMIN_PASSWORD=SecurePassword@123 \
#   MISP_USER_PASSWORD=MispIntegration@2026 \
#   bash scripts/opensearch_setup.sh
#
# After running, update your .env:
#   OPENSEARCH_USERNAME=misp_integration_user
#   OPENSEARCH_PASSWORD=MispIntegration@2026
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-https://localhost:9200}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-SecurePassword@123}"
MISP_USERNAME="${MISP_USERNAME:-misp_integration_user}"
MISP_USER_PASSWORD="${MISP_USER_PASSWORD:-MispIntegration@2026}"
CURL_OPTS=(-sk -u "${ADMIN_USER}:${ADMIN_PASSWORD}" -H "Content-Type: application/json")

echo "OpenSearch Security Setup for MISP Integration Service"
echo "  URL:  ${OPENSEARCH_URL}"
echo "  User: ${MISP_USERNAME}"
echo ""

# ── 1. Create role ────────────────────────────────────────────────────────────
echo "[1/3] Creating role: misp_integration_role"
curl "${CURL_OPTS[@]}" -X PUT \
    "${OPENSEARCH_URL}/_plugins/_security/api/roles/misp_integration_role" \
    -d '{
  "description": "Minimal write access for MISP-MataElang integration service",
  "cluster_permissions": [
    "cluster:monitor/health",
    "cluster:monitor/state",
    "cluster:monitor/nodes/info",
    "cluster:monitor/stats"
  ],
  "index_permissions": [
    {
      "index_patterns": ["misp-enriched-alerts*", "misp-ioc-store*"],
      "allowed_actions": [
        "indices:admin/create",
        "indices:admin/exists",
        "indices:admin/mapping/put",
        "indices:data/write/index",
        "indices:data/write/bulk*",
        "indices:data/read/search",
        "indices:data/read/get"
      ]
    }
  ]
}'
echo ""

# ── 2. Create user ────────────────────────────────────────────────────────────
echo "[2/3] Creating user: ${MISP_USERNAME}"
curl "${CURL_OPTS[@]}" -X PUT \
    "${OPENSEARCH_URL}/_plugins/_security/api/internalusers/${MISP_USERNAME}" \
    -d "{
  \"password\": \"${MISP_USER_PASSWORD}\",
  \"description\": \"Service account for MISP-MataElang integration\",
  \"backend_roles\": [],
  \"attributes\": {
    \"service\": \"misp-integration\",
    \"version\": \"1.1\"
  }
}"
echo ""

# ── 3. Map user to role ───────────────────────────────────────────────────────
echo "[3/3] Mapping user to role"
curl "${CURL_OPTS[@]}" -X PUT \
    "${OPENSEARCH_URL}/_plugins/_security/api/rolesmapping/misp_integration_role" \
    -d "{
  \"users\": [\"${MISP_USERNAME}\"],
  \"description\": \"MISP integration service account mapping\"
}"
echo ""

echo "Setup complete."
echo ""
echo "Update your .env:"
echo "  OPENSEARCH_USERNAME=${MISP_USERNAME}"
echo "  OPENSEARCH_PASSWORD=${MISP_USER_PASSWORD}"
