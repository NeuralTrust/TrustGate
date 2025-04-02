#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="sizelimit-$(date +%s)"

echo -e "${GREEN}Testing Request Size Limiter Plugin${NC}\n"

# 1. Create a gateway with request size limiter plugin
echo -e "${GREEN}1. Creating gateway with request size limiter plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Request Size Limiter Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "request_size_limiter",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "allowed_payload_size": 10,
                "size_unit": "kilobytes",
                "max_chars_per_request": 1000,
                "require_content_length": false
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
    "name": "echo-upstream-'$(date +%s)'",
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
    "name": "echo-service-'$(date +%s)'",
    "type": "upstream",
    "description": "Echo test service",
    "upstream_id": "'$UPSTREAM_ID'"
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
    "strip_path": false,
    "active": true
}')

# Wait for configuration to propagate
sleep 2

# Test request size limiter
echo -e "\n${GREEN}6. Testing request size limiter...${NC}"

# Test with small request (should be allowed)
echo -e "\n${GREEN}6.1 Testing with small request (should be allowed)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "This is a small request with few characters."
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Small request was correctly allowed.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Small request was incorrectly blocked.${NC}"
fi

# Test with request exceeding byte size limit
echo -e "\n${GREEN}6.2 Testing with request exceeding byte size limit (should be blocked)...${NC}"

# Generate a large binary payload (over 10KB)
LARGE_BINARY=$(dd if=/dev/urandom bs=1024 count=12 2>/dev/null | base64)

RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "binary_data": "'"$LARGE_BINARY"'"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "413" ]; then
    echo -e "${GREEN}Success! Request exceeding byte size limit was correctly blocked.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Large request was incorrectly allowed.${NC}"
fi

# Test with request exceeding character limit
echo -e "\n${GREEN}6.3 Testing with request exceeding character limit (should be blocked)...${NC}"

# Generate a string with more than 1000 characters
LARGE_TEXT=$(printf '%.0s-' {1..1100})

RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "'"$LARGE_TEXT"'"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "413" ]; then
    echo -e "${GREEN}Success! Request exceeding character limit was correctly blocked.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Large request was incorrectly allowed.${NC}"
fi

# Test with Content-Length header
echo -e "\n${GREEN}6.4 Testing with explicit Content-Length header...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 30" \
    -d '{
        "message": "With length"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Request with Content-Length was correctly allowed.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# Add a test for default size unit
echo -e "\n${GREEN}6.5 Testing with default size unit (megabytes)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "Testing default size unit"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Request with default size unit was correctly allowed.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

echo -e "\n${GREEN}Request size limiter tests completed${NC}" 