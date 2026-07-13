#!/usr/bin/env bash
# Optional smoke: admin plane health + list gateways.
set -euo pipefail
: "${GATE_ADMIN_URL:?}"
: "${GATE_ADMIN_TOKEN:?}"
curl -sf "${GATE_ADMIN_URL%/}/readyz" >/dev/null
echo "readyz OK"
curl -sf -H "Authorization: Bearer ${GATE_ADMIN_TOKEN}" \
  "${GATE_ADMIN_URL%/}/v1/gateways" >/dev/null
echo "list gateways OK"
