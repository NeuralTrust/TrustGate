#!/usr/bin/env bash
# TrustGate: First request example
# Sets up a gateway, registry, consumer, and makes a chat completion.
#
# Prerequisites:
#   - TrustGate running (make up)
#   - OPENAI_API_KEY environment variable set
#
# Usage:
#   export OPENAI_API_KEY="sk-..."
#   ./first-request.sh

set -euo pipefail

ADMIN="${ADMIN_URL:-http://localhost:8080}"
PROXY="${PROXY_URL:-http://localhost:8081}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}==>${NC} $*"; }
ok() { echo -e "${GREEN}✓${NC} $*"; }
error() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# Check prerequisites
command -v curl >/dev/null 2>&1 || error "curl is required"
command -v jq >/dev/null 2>&1 || error "jq is required"
[[ -n "${OPENAI_API_KEY:-}" ]] || error "OPENAI_API_KEY environment variable is required"

# Check TrustGate is running
curl -sf "$ADMIN/healthz" >/dev/null 2>&1 || error "Admin plane not reachable at $ADMIN"
curl -sf "$PROXY/healthz" >/dev/null 2>&1 || error "Proxy plane not reachable at $PROXY"
ok "TrustGate is running"

# Generate admin token (requires SERVER_SECRET_KEY in .env)
info "Generating admin token..."
if [[ -z "${ADMIN_TOKEN:-}" ]]; then
    if [[ -f "../../.env" ]]; then
        export SERVER_SECRET_KEY="$(grep ^SERVER_SECRET_KEY ../../.env | cut -d= -f2-)"
    elif [[ -f ".env" ]]; then
        export SERVER_SECRET_KEY="$(grep ^SERVER_SECRET_KEY .env | cut -d= -f2-)"
    fi
    
    if [[ -z "${SERVER_SECRET_KEY:-}" ]]; then
        error "SERVER_SECRET_KEY not found. Set ADMIN_TOKEN or ensure .env exists."
    fi
    
    ADMIN_TOKEN=$(python3 - <<'PY'
import jwt, os, time
secret = os.environ["SERVER_SECRET_KEY"]
print(jwt.encode({"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}, secret, algorithm="HS256"))
PY
)
fi
ok "Admin token ready"

# 1. Create gateway
info "Creating gateway 'demo'..."
GW=$(curl -sf -X POST "$ADMIN/v1/gateways" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"Demo Gateway","slug":"demo"}') || error "Failed to create gateway"
GW_ID=$(echo "$GW" | jq -r .id)
GW_SLUG=$(echo "$GW" | jq -r .slug)
ok "Gateway created: $GW_SLUG (ID: $GW_ID)"

# 2. Register OpenAI as upstream provider
info "Registering OpenAI provider..."
REG=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/registries" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "openai-primary",
        "provider": "openai",
        "auth": {
            "type": "api_key",
            "api_key": {"api_key": "'"$OPENAI_API_KEY"'"}
        }
    }') || error "Failed to create registry"
REG_ID=$(echo "$REG" | jq -r .id)
ok "Registry created: openai-primary (ID: $REG_ID)"

# 3. Create consumer bound to that registry
info "Creating consumer 'my-app'..."
CON=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/consumers" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "my-app",
        "registries": [{"id": "'"$REG_ID"'"}]
    }') || error "Failed to create consumer"
CON_ID=$(echo "$CON" | jq -r .id)
CON_SLUG=$(echo "$CON" | jq -r .slug)
ok "Consumer created: $CON_SLUG (ID: $CON_ID)"

# 4. Mint consumer API key
info "Creating API key..."
AUTH=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/auths" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"my-app-key","type":"api_key"}') || error "Failed to create auth"
AUTH_ID=$(echo "$AUTH" | jq -r .id)
API_KEY=$(echo "$AUTH" | jq -r .api_key)
ok "API key created (ID: $AUTH_ID)"

# 5. Attach key to consumer
info "Attaching key to consumer..."
curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/consumers/$CON_ID/auths/$AUTH_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" >/dev/null || error "Failed to attach auth"
ok "Key attached to consumer"

# 6. Make chat completion through proxy
info "Making chat completion request..."
echo ""
RESPONSE=$(curl -sf -X POST "$PROXY/$CON_SLUG/v1/chat/completions" \
    -H "X-AG-Gateway-Slug: $GW_SLUG" \
    -H "X-AG-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Say hello in one sentence."}]
    }') || error "Chat completion failed"

echo "$RESPONSE" | jq -r '.choices[0].message.content'
echo ""
ok "Request successful!"

# Summary
echo ""
echo "======================================"
echo "Setup complete! Here are your values:"
echo "======================================"
echo "Gateway Slug:    $GW_SLUG"
echo "Consumer Slug:   $CON_SLUG"
echo "API Key:         $API_KEY"
echo ""
echo "Make requests with:"
echo "  curl -X POST \"$PROXY/$CON_SLUG/v1/chat/completions\" \\"
echo "    -H \"X-AG-Gateway-Slug: $GW_SLUG\" \\"
echo "    -H \"X-AG-API-Key: $API_KEY\" \\"
echo "    -H \"Content-Type: application/json\" \\"
echo "    -d '{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello!\"}]}'"
