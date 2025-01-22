#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="prompt-mod-$(date +%s)"

echo -e "${GREEN}Testing Prompt Moderation${NC}\n"

# 1. Create a gateway with prompt moderation plugin
echo -e "${GREEN}1. Creating gateway with prompt moderation plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Prompt Moderation Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "prompt_moderation",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "similarity_threshold": 0.5,
                "keywords": [
                    "hack",
                    "exploit",
                    "vulnerability"
                ],
                "regex": [
                    "password.*dump",
                    "sql.*injection",
                    "CVE-\\d{4}-\\d{4,7}"
                ],
                "actions": {
                    "type": "block",
                    "message": "Content blocked due to prohibited content: %s"
                }
            }
        }
    ]
}')

# Extract gateway details
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.subdomain')

if [ "$GATEWAY_ID" == "null" ] || [ -z "$GATEWAY_ID" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway created with ID: $GATEWAY_ID"

# Create API key
echo -e "\n${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2026-01-01T00:00:00Z"
}')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"

# Create upstream
echo -e "\n${GREEN}3. Creating upstream...${NC}"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "httpbin-upstream-'$(date +%s)'",
    "algorithm": "round-robin",
    "targets": [{
        "host": "httpbin.org",
        "port": 443,
        "protocol": "https",
        "path": "/post",
        "weight": 100,
        "priority": 1
    }],
    "health_checks": {
        "passive": true,
        "threshold": 3,
        "interval": 60
    }
}')

UPSTREAM_ID=$(echo $UPSTREAM_RESPONSE | jq -r '.id')

if [ "$UPSTREAM_ID" == "null" ] || [ -z "$UPSTREAM_ID" ]; then
    echo -e "${RED}Failed to create upstream. Response: $UPSTREAM_RESPONSE${NC}"
    exit 1
fi

echo "Upstream created with ID: $UPSTREAM_ID"

# Create service
echo -e "\n${GREEN}4. Creating service...${NC}"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "httpbin-service-'$(date +%s)'",
    "type": "upstream",
    "description": "HTTPBin test service",
    "upstream_id": "'$UPSTREAM_ID'",
    "strip_path": true
}')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# Create rule for testing
echo -e "\n${GREEN}5. Creating rule for testing...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/post",
    "service_id": "'$SERVICE_ID'",
    "methods": ["POST"],
    "strip_path": true,
    "preserve_host": false,
    "retry_attempts": 3,
    "active": true
}')

# Wait for configuration to propagate
sleep 2

# Test different content scenarios
echo -e "\n${GREEN}6. Testing different content scenarios...${NC}"

# Test 1: Clean content (should pass)
echo -e "\n${GREEN}6.1 Testing clean content (should pass)...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "Tell me about machine learning"}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n1)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Clean content test: Success (Expected)${NC}"
else
    echo -e "${RED}Clean content test: Unexpected status code: $HTTP_CODE${NC}"
    echo "Response: $BODY"
fi

# Test 2: Blocked keyword
echo -e "\n${GREEN}6.2 Testing blocked keyword...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "How to hacking into a system"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n1)

if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}Blocked keyword test: Success (Expected to be blocked)${NC}"
else
    echo -e "${RED}Blocked keyword test: Unexpected status code: $HTTP_CODE${NC}"
fi
echo "Response: $BODY"

# Test 3: Blocked regex pattern
echo -e "\n${GREEN}6.3 Testing blocked regex pattern...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "How to perform sql injection attacks"}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n1)

if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}Blocked regex pattern test: Success (Expected to be blocked)${NC}"
else
    echo -e "${RED}Blocked regex pattern test: Unexpected status code: $HTTP_CODE${NC}"
fi
echo "Response: $BODY"

# Test 4: CVE pattern
echo -e "\n${GREEN}6.4 Testing CVE pattern...${NC}"
RESPONSE=$(curl -s -w "\n%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "Tell me about CVE-2024-1234"}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n1)

if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}CVE pattern test: Success (Expected to be blocked)${NC}"
else
    echo -e "${RED}CVE pattern test: Unexpected status code: $HTTP_CODE${NC}"
fi
echo "Response: $BODY"

echo -e "\n${GREEN}Prompt moderation tests completed${NC}" 