#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="injection-$(date +%s)"

echo -e "${GREEN}Testing Injection Protection Plugin${NC}\n"

# 1. Create a gateway with injection protection plugin
echo -e "${GREEN}1. Creating gateway with injection protection plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Injection Protection Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "injection_protection",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "predefined_injections": [
                    {
                        "type": "sql",
                        "enabled": true
                    },
                    {
                        "type": "javascript",
                        "enabled": true
                    },
                    {
                        "type": "server_side_include",
                        "enabled": true
                    }
                ],
                "custom_injections": [
                    {
                        "name": "custom_sql",
                        "pattern": "(?i)\\b(select|union|having)\\b",
                        "content_to_check": "all"
                    }
                ],
                "content_to_check": ["headers", "path_and_query", "body"],
                "action": "block",
                "status_code": 400,
                "error_message": "Potential security threat detected"
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

# Test injection protection
echo -e "\n${GREEN}6. Testing injection protection...${NC}"

# Test SQL injection
echo -e "\n${GREEN}6.1 Testing SQL injection (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "query": "DROP TABLE users"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! SQL injection was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}SQL injection was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

# Test XSS injection
echo -e "\n${GREEN}6.2 Testing XSS injection (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "comment": "<script>alert(\"XSS\")</script>"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! XSS injection was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}XSS injection was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

# Test custom SQL injection pattern
echo -e "\n${GREEN}6.3 Testing custom SQL injection pattern (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "query": "SELECT * FROM users"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! Custom SQL pattern was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Custom SQL pattern was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

# Test safe content
echo -e "\n${GREEN}6.4 Testing safe content (should be allowed)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "This is a safe message with no injections",
        "data": {
            "id": 123,
            "name": "Test User"
        }
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Safe content was correctly allowed.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Safe content was incorrectly blocked.${NC}"
    echo -e "Response: $BODY"
fi

# Add tests for header injection
echo -e "\n${GREEN}6.5 Testing header injection (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -H "X-Custom-Header: <script>alert('XSS')</script>" \
    -d '{
        "message": "This is a safe message"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! Header injection was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Header injection was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

# Add tests for query parameter injection
echo -e "\n${GREEN}6.6 Testing query parameter injection (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post?query=DROP%20TABLE%20users" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "This is a safe message"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! Query parameter injection was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Query parameter injection was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

# Add test for path injection
echo -e "\n${GREEN}6.7 Testing path injection (should be blocked)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post/exec/something" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -H "X-Original-URL: /post/exec/something" \
    -d '{
        "message": "This is a safe message"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "400" ]; then
    echo -e "${GREEN}Success! Path injection was correctly blocked.${NC}"
    echo -e "Response: $BODY"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Path injection was not blocked as expected.${NC}"
    echo -e "Response: $BODY"
fi

echo -e "\n${GREEN}Injection protection tests completed${NC}" 