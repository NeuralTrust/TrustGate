#!/usr/bin/env bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default environment variables
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
STREAM_SUBDOMAIN="openai-stream-$(date +%s)"
MODEL=${MODEL:-"gpt-4o-mini"}
API_KEY=${API_KEY:-""}

echo -e "${GREEN}1. Creating gateway for streaming test...${NC}"

# Create a new gateway
CREATE_GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "streaming-gateway-'$(date +%s)'",
        "subdomain": "'"$STREAM_SUBDOMAIN"'"
    }')

GATEWAY_ID=$(echo "$CREATE_GATEWAY_RESPONSE" | jq -r '.id')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to create gateway. Response: $CREATE_GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway ID: $GATEWAY_ID"

# 2. Create an API key for this gateway
echo -e "\n${GREEN}2. Creating API key for the streaming gateway...${NC}"
KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Streaming Key",
    "expires_at": "2026-01-01T00:00:00Z"
}')

API_KEY=$(echo "$KEY_RESPONSE" | jq -r '.key')

if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
    echo -e "${RED}Failed to create API key. Response: $KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key: $API_KEY"

# 4. Create an upstream and link it to the new service
echo -e "\n${GREEN}4. Creating upstream with OpenAI target...${NC}"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
      "name": "openai-stream-upstream-'$(date +%s)'",
      "algorithm": "round-robin",
      "targets": [
        {
          "path": "/v1/chat/completions",
          "provider": "openai",
          "weight": 100,
          "models": ["gpt-3.5-turbo","gpt-4","gpt-4o-mini"],
          "default_model": "gpt-4o-mini",
          "credentials": {
            "header_name": "Authorization",
            "header_value": "Bearer '"$OPENAI_API_KEY"'"
          }
        }
      ]
  }')

# 5. Link service to upstream
UPSTREAM_ID=$(echo "$UPSTREAM_RESPONSE" | jq -r '.id')
if [ -z "$UPSTREAM_ID" ] || [ "$UPSTREAM_ID" = "null" ]; then
    echo -e "${RED}Failed to create upstream. Response: $UPSTREAM_RESPONSE${NC}"
    exit 1
fi
echo "Upstream created with ID: $UPSTREAM_ID"

# 3. Create a new service (handler for upstream requests)
echo -e "\n${GREEN}3. Creating OpenAI service...${NC}"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
      "name": "openai-stream-service-'$(date +%s)'",
      "type": "upstream",
      "upstream_id": "'"$UPSTREAM_ID"'"
  }')

SERVICE_ID=$(echo "$SERVICE_RESPONSE" | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi
echo "Service created with ID: $SERVICE_ID"

# 6. Create a rule linking the service with path /v1
echo -e "\n${GREEN}5. Creating rule for the streaming gateway...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
      "path": "/v1",
      "service_id": "'"$SERVICE_ID"'",
      "methods": ["POST"],
      "strip_path": false,
      "active": true
  }')

RULE_ID=$(echo "$RULE_RESPONSE" | jq -r '.id')
if [ -z "$RULE_ID" ] || [ "$RULE_ID" = "null" ]; then
    echo -e "${RED}Failed to create rule. Response: $RULE_RESPONSE${NC}"
    exit 1
fi
echo "Rule created with ID: $RULE_ID"

# Wait briefly for config propagation
sleep 2

# 7. Test streaming request
echo -e "\n${GREEN}6. Testing OpenAI streaming with gateway...${NC}"
echo "Using subdomain: $STREAM_SUBDOMAIN.$BASE_DOMAIN"
echo "Using model: $MODEL"

# Direct streaming output without JSON parsing
curl -N -X POST "$PROXY_URL/v1" \
    -H "Content-Type: application/json" \
    -H "Host: $STREAM_SUBDOMAIN.$BASE_DOMAIN" \
    -H "X-TG-API-Key: $API_KEY" \
    -d '{
        "model": "'"$MODEL"'",
        "stream": true,
        "stream_options": {
            "include_usage": true
        },
        "messages": [{"role": "user", "content": "Hello, streaming test."}]
    }'

echo -e "\n${GREEN}Streaming test complete${NC}"
