#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check for required environment variables
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}Error: OPENAI_API_KEY must be set${NC}"
    echo "Please set the following environment variable:"
    echo "export OPENAI_API_KEY='your-api-key'"
    exit 1
fi

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="toxicity-openai-$(date +%s)"

echo -e "${GREEN}Testing OpenAI Toxicity Detection Plugin${NC}\n"

# Create gateway configuration
echo -e "${GREEN}1. Creating gateway configuration...${NC}"

GATEWAY_CONFIG='{
    "name": "OpenAI Toxicity Detection Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "toxicity_openai",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "openai_key": "'$OPENAI_API_KEY'",
                "actions": {
                    "type": "block",
                    "message": "Content contains violence or hate speech"
                },
                "categories": [
                    "hate", "hate/threatening",
                    "violence", "violence/graphic"
                ],
                "thresholds": {
                    "hate": 0.15,
                    "hate/threatening": 0.15,
                    "violence": 0.15,
                    "violence/graphic": 0.15
                }
            }
        }
    ]
}'

GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d "$GATEWAY_CONFIG")

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

# Create rule
echo -e "\n${GREEN}5. Creating rule...${NC}"
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

# Test cases
echo -e "\n${GREEN}6. Running test cases...${NC}"

# Test 1: Test with safe text content
echo -e "\n${GREEN}6.1 Testing safe text content...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Hello! How are you today? I hope you are having a great day!"
                    }
                ]
            }
        ]
    }')

HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

echo -e "Response Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Safe text test passed (as expected)${NC}"
else
    echo -e "${RED}Safe text test failed (unexpected block)${NC}"
fi

# Test 2: Test with hate speech content
echo -e "\n${GREEN}6.2 Testing hate speech content...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "I hate all people from that country and want them gone!"
                    }
                ]
            }
        ]
    }')

HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

echo -e "Response Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}Hate speech test passed (blocked as expected)${NC}"
    echo -e "${RED}Response: $BODY${NC}"
else
    echo -e "${RED}Hate speech test failed (not blocked)${NC}"
fi


# Test 3: Test with violent content
echo -e "\n${GREEN}6.3 Testing violent content...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "I will violently attack and hurt everyone!"
                    }
                ]
            }
        ]
    }')

HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

echo -e "Response Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}Violence test passed (blocked as expected)${NC}"
    echo -e "${RED}Response: $BODY${NC}"
else
    echo -e "${RED}Violence test failed (not blocked)${NC}"
fi

# Test 4: Test with violent image
echo -e "\n${GREEN}6.4 Testing violent image...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "https://www.shutterstock.com/image-photo/violent-young-man-threatening-his-260nw-790887175.jpg"
                        }
                    }
                ]
            }
        ]
    }')

HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

echo -e "Response Status Code: $HTTP_CODE"
if [ "$HTTP_CODE" == "403" ]; then
    echo -e "${GREEN}Violent image test passed (blocked as expected)${NC}"
    echo -e "${RED}Response: $BODY${NC}"
else
    echo -e "${RED}Violent image test failed (not blocked)${NC}"
fi


echo -e "\n${GREEN}OpenAI toxicity detection tests completed${NC}"