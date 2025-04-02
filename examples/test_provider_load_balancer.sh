#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test configuration
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="multi-provider-$(date +%s)"
GATEWAY_ID=""
API_KEY=""

# Initialize counters for providers
openai_count=0
anthropic_count=0
total_requests=5

echo -e "${GREEN}1. Creating test gateway with multiple providers...${NC}"

GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "multi-provider-gateway-'$(date +%s)'",
        "subdomain": "'"$SUBDOMAIN"'"
    }')

# Extract gateway ID and API key
GATEWAY_ID=$(echo "$GATEWAY_RESPONSE" | jq -r '.id')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway ID: $GATEWAY_ID"

# 2. Create API key
echo -e "\n${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2026-01-01T00:00:00Z"
}')

API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"
# Wait for configuration to propagate

# Create an upstream
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ai-providers-upstream-'$(date +%s)'",
        "algorithm": "round-robin",
        "targets": [
            {
                "path": "/v1/chat/completions",
                "provider": "openai",
                "weight": 50,
                "priority": 1,
                "default_model": "gpt-4o-mini",
                "models": ["gpt-3.5-turbo", "gpt-4", "gpt-4o-mini"],
                "credentials": {
                    "header_name": "Authorization",
                    "header_value": "Bearer '"$OPENAI_API_KEY"'"
                }
            },
            {
                "path": "/v1/messages",
                "provider": "anthropic",
                "weight": 50,
                "priority": 1,
                "default_model": "claude-3-5-sonnet-20241022",
                "models": ["claude-3-5-sonnet-20241022"],
                "headers": {
                    "anthropic-version": "2023-06-01"
                },
                "credentials": {
                    "header_name": "x-api-key",
                    "header_value": "'"$ANTHROPIC_API_KEY"'"
                }
            }
        ],
        "health_checks": {
            "passive": true,
            "threshold": 3,
            "interval": 60
        }
    }')

UPSTREAM_ID=$(echo "$UPSTREAM_RESPONSE" | jq -r '.id')

if [ "$UPSTREAM_ID" == "null" ] || [ -z "$UPSTREAM_ID" ]; then
    echo -e "${RED}Failed to create upstream. Response: $UPSTREAM_RESPONSE${NC}"
    exit 1
fi

echo "Upstream created with ID: $UPSTREAM_ID"
# Then create a service that uses this upstream
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ai-chat-service-'$(date +%s)'",
        "description": "Load balanced AI chat completion service",
        "upstream_id": "'"$UPSTREAM_ID"'",
        "type": "upstream",
        "tags": ["ai", "chat"]
    }')

SERVICE_ID=$(echo "$SERVICE_RESPONSE" | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# Create rule
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1",
    "service_id": "'$SERVICE_ID'",
    "methods": ["POST"],
    "strip_path": false,
    "active": true
}')

RULE_ID=$(echo "$RULE_RESPONSE" | jq -r '.id')

if [ "$RULE_ID" == "null" ] || [ -z "$RULE_ID" ]; then
    echo -e "${RED}Failed to create rule. Response: $RULE_RESPONSE${NC}"
    exit 1
fi

echo "Rule created with ID: $RULE_ID"

echo -e "\n${GREEN}2. Testing provider load balancing...${NC}"
for i in $(seq 1 $total_requests); do
    # Alternate between models to test both providers
    MODEL="gpt-4o-mini"
    
    # Make request and capture response headers
    RESPONSE_HEADERS=$(curl -s -D - -X POST "$PROXY_URL/v1" \
        -H "Content-Type: application/json" \
        -H "Host: $SUBDOMAIN.$BASE_DOMAIN" \
        -H "X-TG-API-Key: $API_KEY" \
        -d '{
            "model": "'"$MODEL"'",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1024,
            "stream": true,
            "system": "You are a helpful assistant."
        }' 2>&1)
    
    echo "$RESPONSE_HEADERS"
    # Extract the selected provider from response headers
    SELECTED_PROVIDER=$(echo "$RESPONSE_HEADERS" | grep -i "X-Selected-Provider" | cut -d' ' -f2 | tr -d '\r')
    
    # Update counters
    case $SELECTED_PROVIDER in
        "openai")
            ((openai_count++))
            echo -n "O"
            ;;
        "anthropic")
            ((anthropic_count++))
            echo -n "A"
            ;;
        *)
            echo -n "?"
            ;;
    esac
    
    # Add newline every 10 requests for readability
    if [ $((i % 10)) -eq 0 ]; then
        echo ""
    fi
done

echo -e "\n\n${GREEN}3. Results:${NC}"
echo "Total requests: $total_requests"
echo "OpenAI requests: $openai_count ($(echo "scale=1; $openai_count * 100 / $total_requests" | bc)%)"
echo "Anthropic requests: $anthropic_count ($(echo "scale=1; $anthropic_count * 100 / $total_requests" | bc)%)"

# Clean up
echo -e "\n${GREEN}4. Cleaning up...${NC}"
curl -s -X DELETE "$ADMIN_URL/gateways/$GATEWAY_ID" > /dev/null
echo "Gateway deleted" 