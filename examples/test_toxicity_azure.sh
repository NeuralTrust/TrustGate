#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check for required environment variables
if [ -z "$AZURE_API_KEY" ] || [ -z "$AZURE_TEXT_ENDPOINT" ] || [ -z "$AZURE_IMAGE_ENDPOINT" ]; then
    echo -e "${RED}Error: AZURE_API_KEY, AZURE_TEXT_ENDPOINT, and AZURE_IMAGE_ENDPOINT must be set${NC}"
    echo "Please set the following environment variables:"
    echo "export AZURE_API_KEY='your-api-key'"
    echo "export AZURE_TEXT_ENDPOINT='https://YOUR_REGION.api.cognitive.microsoft.com/contentsafety/text/analyze'"
    echo "export AZURE_IMAGE_ENDPOINT='https://YOUR_REGION.api.cognitive.microsoft.com/contentsafety/image/analyze'"
    exit 1
fi

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="toxicity-azure-image-$(date +%s)"

echo -e "${GREEN}Testing Azure Content Safety Image Plugin${NC}\n"

# Create gateway with image field configuration
echo -e "${GREEN}1. Creating gateway with image field configuration...${NC}"

# Create the gateway configuration JSON
GATEWAY_CONFIG='{
    "name": "Azure Content Safety Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "toxicity_azure",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "api_key": "'$AZURE_API_KEY'",
                "endpoints": {
                    "text": "'$AZURE_TEXT_ENDPOINT'",
                    "image": "'$AZURE_IMAGE_ENDPOINT'"
                },
                "output_type": "FourSeverityLevels",
                "content_types": [{
                    "type": "text",
                    "path": "text"
                },
                {
                    "type": "image",
                    "path": "image_data"
                }],
                "actions": {
                    "type": "block",
                    "message": "Content violates safety guidelines"
                },
                "category_severity": {
                    "Hate": 0,
                    "Violence": 0,
                    "SelfHarm": 2,
                    "Sexual": 2
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

# Test cases
echo -e "\n${GREEN}6. Testing different content types...${NC}"

# Test 1: Test image content
echo -e "\n${GREEN}6.1 Testing image content...${NC}"
TEST_IMAGE="./assets/test_imgs/test-violent-image.jpg"
if [ ! -f "$TEST_IMAGE" ]; then
    echo -e "${RED}Image file not found: $TEST_IMAGE${NC}"
else
    IMAGE_BASE64=$(base64 -i "$TEST_IMAGE" | tr -d '\n')
    JSON_PAYLOAD=$(jq -n --arg img "$IMAGE_BASE64" '{"image_data": $img}')
    
    RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "X-TG-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD")
    # Extract status code
    HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
    # Extract body (everything before STATUS_CODE line)
    BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

    echo -e "\n${GREEN}Response Status Code: $HTTP_CODE${NC}"
    
    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}Image passed moderation${NC}"
    elif [ "$HTTP_CODE" == "400" ]; then
        echo -e "${RED}Image blocked by moderation${NC}"
        ERROR_MSG=$(echo "$BODY" | jq -r '.error')
        echo -e "${RED}$ERROR_MSG${NC}"
    else
        echo -e "${RED}Unexpected status code: $HTTP_CODE${NC}"
    fi
    
    echo -e "\n----------------------------------------"
fi

# Test 2: Test text content
echo -e "\n${GREEN}6.2 Testing text content...${NC}"
TEXT_PAYLOAD='{
    "text": "This is a test message containing potentially harmful content: I hate everyone and want to cause violence."
}'

echo -e "\n${GREEN}Sending text content for moderation...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$TEXT_PAYLOAD")

# Extract status code
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
# Extract body (everything before STATUS_CODE line)
BODY=$(echo "$RESPONSE" | sed -n '1,/STATUS_CODE/p' | sed '$d')

echo -e "\n${GREEN}Response Status Code: $HTTP_CODE${NC}"

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Text passed moderation${NC}"
elif [ "$HTTP_CODE" == "400" ]; then
    echo -e "${RED}Text blocked by moderation${NC}"
    #ERROR_MSG=$(echo "$BODY" | jq -r '.error')
    echo -e "${RED}$ERROR_MSG${NC}"
else
    echo -e "${RED}Unexpected status code: $HTTP_CODE${NC}"
fi

echo -e "\n----------------------------------------"
echo -e "\n${GREEN}Content safety tests completed${NC}"