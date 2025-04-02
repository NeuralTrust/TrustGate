#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="bedrock-$(date +%s)"

# Check if GUARDRAIL_ID is set
if [ -z "${GUARDRAIL_ID}" ]; then
    echo -e "${RED}Error: You didn't export the GUARDRAIL_ID environment variable${NC}"
    exit 1
fi

# Check if GUARDRAIL_VERSION is set
if [ -z "${GUARDRAIL_VERSION}" ]; then
    echo -e "${RED}Error: You didn't export the GUARDRAIL_VERSION environment variable${NC}"
    exit 1
fi

# Check if AWS credentials are set
if [ -z "${AWS_ACCESS_KEY}" ]; then
    echo -e "${RED}Error: You didn't export the AWS_ACCESS_KEY environment variable${NC}"
    exit 1
fi

if [ -z "${AWS_SECRET_KEY}" ]; then
    echo -e "${RED}Error: You didn't export the AWS_SECRET_KEY environment variable${NC}"
    exit 1
fi

# Check if AWS region is set
if [ -z "${AWS_REGION}" ]; then
    echo -e "${RED}Error: You didn't export the AWS_REGION environment variable${NC}"
    exit 1
fi

echo -e "${GREEN}Testing Bedrock Guardrail Plugin${NC}\n"


# 1. Create a gateway with bedrock guardrail plugin
echo -e "${GREEN}1. Creating gateway with bedrock guardrail plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Bedrock Guardrail Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "bedrock_guardrail",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "guardrail_id": "'$GUARDRAIL_ID'",
                "version": "'$GUARDRAIL_VERSION'",
                "credentials": {
                    "aws_access_key": "'$AWS_ACCESS_KEY'",
                    "aws_secret_key": "'$AWS_SECRET_KEY'",
                    "aws_region": "'$AWS_REGION'"
                },
                "actions": {
                    "message": "%s"
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

# Test bedrock guardrail
echo -e "\n${GREEN}6. Testing content moderation...${NC}"

# Test 1: Safe content
echo -e "\n${GREEN}Testing safe content...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: text/plain" \
    -d "The latest deployment includes performance improvements and bug fixes.")

BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}✓ Safe content test passed${NC}"
else
    echo -e "${RED}✗ Safe content test failed (Status: $HTTP_CODE)${NC}"
    echo "Response: $BODY"
fi

# Test 2: Content policy violation
echo -e "\n${GREEN}Testing content policy violation...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: text/plain" \
    -d "I dont like obama")

BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
ERROR_MSG=$(echo "$BODY" | jq -r '.error')

if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}✓ Content policy violation test passed${NC}"
    echo "Error: $ERROR_MSG"
else
    echo -e "${RED}✗ Content policy violation test failed (Status: $HTTP_CODE)${NC}"
    echo "Error: $ERROR_MSG"
fi


echo -e "\n${GREEN}Bedrock Guardrail tests completed${NC}"

