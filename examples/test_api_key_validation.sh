#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}

echo -e "${GREEN}Testing API Key Validation${NC}\n"

# 1. Create a gateway
echo -e "${GREEN}1. Creating gateway...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Key Test Gateway",
    "subdomain": "apikey-test-'$(date +%s)'"
  }')

# Extract fields from response
GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.ID // .id')
SUBDOMAIN=$(echo $GATEWAY_RESPONSE | jq -r '.Subdomain // .subdomain')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" = "null" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

# 2. Create API key
echo -e "${GREEN}2. Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "expires_at": "2026-01-22T18:55:12+01:00"
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ -z "$API_KEY" ] || [ "$API_KEY" = "null" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

# 3. Create upstream
echo -e "${GREEN}3. Creating upstream...${NC}"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "httpbin-upstream-'$(date +%s)'",
    "algorithm": "round-robin",
    "targets": [{
        "host": "httpbin.org",
        "port": 443,
        "protocol": "https",
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

# 4. Create service
echo -e "${GREEN}4. Creating service...${NC}"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "httpbin-service-'$(date +%s)'",
    "type": "upstream",
    "description": "HTTPBin test service",
    "upstream_id": "'$UPSTREAM_ID'"
  }')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# 5. Create a forwarding rule
echo -e "${GREEN}5. Creating forwarding rule...${NC}"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/test",
    "service_id": "'$SERVICE_ID'",
    "methods": ["GET"],
    "strip_path": true,
    "active": true
  }')

# Wait for configuration to propagate
sleep 2

# 6. Test with valid API key
echo -e "\n${GREEN}6. Testing with valid API key...${NC}"
VALID_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "Authorization: Bearer ${API_KEY}" \
    "${PROXY_URL}/test/get")

VALID_STATUS=$(echo "$VALID_RESPONSE" | tail -n1)
echo -e "Valid key status code: ${VALID_STATUS}"

# 7. Test with invalid API key
echo -e "\n${GREEN}7. Testing with invalid API key...${NC}"
INVALID_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "Authorization: Bearer invalid_key" \
    "${PROXY_URL}/test/get")

INVALID_STATUS=$(echo "$INVALID_RESPONSE" | tail -n1)
echo -e "Invalid key status code: ${INVALID_STATUS}"

# 8. Test with no API key
echo -e "\n${GREEN}8. Testing with no API key...${NC}"
NO_KEY_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    "${PROXY_URL}/test/get")

NO_KEY_STATUS=$(echo "$NO_KEY_RESPONSE" | tail -n1)
echo -e "No key status code: ${NO_KEY_STATUS}"

# Check results
echo -e "\n${GREEN}Results:${NC}"
if [ "$VALID_STATUS" = "200" ]; then
    echo -e "✅ Valid API key test passed"
else
    echo -e "❌ Valid API key test failed (got $VALID_STATUS, expected 200)"
fi

if [ "$INVALID_STATUS" = "401" ]; then
    echo -e "✅ Invalid API key test passed"
else
    echo -e "❌ Invalid API key test failed (got $INVALID_STATUS, expected 401)"
fi

if [ "$NO_KEY_STATUS" = "401" ]; then
    echo -e "✅ No API key test passed"
else
    echo -e "❌ No API key test failed (got $NO_KEY_STATUS, expected 401)"
fi 