#!/usr/bin/env bash
# ==============================================================================
# SentinelAI End-to-End Health & Network Isolation Validation Script
# ==============================================================================
set -euo pipefail

HOST="${1:-localhost}"
WEB_PORT="${2:-8080}"

echo "========================================================"
echo " SentinelAI Platform Deployment Healthcheck"
echo " Target: http://${HOST}:${WEB_PORT}"
echo "========================================================"

FAILED=0

# 1. Frontend Web Ingress
echo -n "[*] Checking Frontend Ingress (HTTP 8080)... "
STATUS_WEB=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${WEB_PORT}/" || echo "000")
if [ "$STATUS_WEB" -eq 200 ]; then
    echo "OK (HTTP $STATUS_WEB)"
else
    echo "FAILED (HTTP $STATUS_WEB)"
    FAILED=$((FAILED + 1))
fi

# 2. Reverse Proxied API Health
echo -n "[*] Checking Reverse Proxied API Health (/health)... "
STATUS_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${WEB_PORT}/health" || echo "000")
if [ "$STATUS_HEALTH" -eq 200 ]; then
    echo "OK (HTTP $STATUS_HEALTH)"
else
    echo "FAILED (HTTP $STATUS_HEALTH)"
    FAILED=$((FAILED + 1))
fi

# 3. Reverse Proxied API Readiness
echo -n "[*] Checking Reverse Proxied API Readiness (/api/v1/readiness)... "
STATUS_READY=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${WEB_PORT}/api/v1/readiness" || echo "000")
if [ "$STATUS_READY" -eq 200 ]; then
    echo "OK (HTTP $STATUS_READY)"
else
    echo "FAILED (HTTP $STATUS_READY)"
    FAILED=$((FAILED + 1))
fi

# 4. Reverse Proxied Prometheus Metrics
echo -n "[*] Checking Prometheus Metrics (/metrics)... "
STATUS_METRICS=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${WEB_PORT}/metrics" || echo "000")
if [ "$STATUS_METRICS" -eq 200 ]; then
    echo "OK (HTTP $STATUS_METRICS)"
else
    echo "FAILED (HTTP $STATUS_METRICS)"
    FAILED=$((FAILED + 1))
fi

# 5. Internal Network Isolation Check
echo "[*] Verifying Host Isolation of Internal Services:"

echo -n "    - Direct API Port 8000: "
if curl -s -m 2 "http://${HOST}:8000/health" > /dev/null 2>&1; then
    echo "EXPOSED (SECURITY VIOLATION - port 8000 should be internal)"
    FAILED=$((FAILED + 1))
else
    echo "PROTECTED (Closed / Filtered on Host)"
fi

echo -n "    - Direct PostgreSQL Port 5432: "
if nc -z -w 2 "${HOST}" 5432 > /dev/null 2>&1 || (echo > "/dev/tcp/${HOST}/5432") > /dev/null 2>&1; then
    echo "EXPOSED (SECURITY VIOLATION - port 5432 should be internal)"
    FAILED=$((FAILED + 1))
else
    echo "PROTECTED (Closed / Filtered on Host)"
fi

echo -n "    - Direct Kafka Port 9092: "
if nc -z -w 2 "${HOST}" 9092 > /dev/null 2>&1 || (echo > "/dev/tcp/${HOST}/9092") > /dev/null 2>&1; then
    echo "EXPOSED (SECURITY VIOLATION - port 9092 should be internal)"
    FAILED=$((FAILED + 1))
else
    echo "PROTECTED (Closed / Filtered on Host)"
fi

echo "========================================================"
if [ "$FAILED" -eq 0 ]; then
    echo "ALL HEALTH & NETWORK ISOLATION CHECKS PASSED!"
    exit 0
else
    echo "HEALTHCHECK COMPLETED WITH $FAILED FAILURES"
    exit 1
fi
