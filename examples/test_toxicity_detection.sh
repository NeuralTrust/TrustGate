#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="toxicity-$(date +%s)"

echo -e "${GREEN}Testing Toxicity Detection Plugin${NC}\n"

# 1. Create a gateway with toxicity detection plugin
echo -e "${GREEN}1. Creating gateway with toxicity detection plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Toxicity Detection Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "toxicity_detection",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "openai_key": "'${OPENAI_API_KEY}'",
                "actions": {
                    "type": "block",
                    "message": "Content contains inappropriate content."
                },
                "categories": [
                    "sexual",
                    "violence",
                    "hate"
                ],
                "thresholds": {
                    "sexual": 0.3,
                    "violence": 0.5,
                    "hate": 0.4
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

# Test toxicity detection
echo -e "\n${GREEN}6. Testing toxicity detection...${NC}"

# Test cases with different toxicity categories
TEST_CASES=(
    '{"messages":[{"role":"user","content":"Let us discuss dating and relationships in a respectful way"}]}'
    '{"messages":[{"role":"user","content":"I will brutally murder you and your entire family in the most gruesome way possible"}]}'
    '{"messages":[{"role":"user","content":"I hate all people from that country, they are subhuman and deserve to die"}]}'
)

TEST_NAMES=(
    "sexual content test"
    "violence test"
    "hate speech test"
)

TEST_CATEGORIES=(
    "sexual"
    "violence"
    "hate"
)

TEST_THRESHOLDS=(
    "0.3"
    "0.5"
    "0.4"
)

for i in "${!TEST_CASES[@]}"; do
    echo -e "\n${GREEN}Testing ${TEST_NAMES[$i]}:${NC}"
    CONTENT=$(echo "${TEST_CASES[$i]}" | jq -r '.messages[0].content')
    echo "Content: $CONTENT"

    # Make direct call to OpenAI Moderation API
    echo -e "\n${GREEN}OpenAI Moderation API Direct Response:${NC}"
    MODERATION_RESPONSE=$(curl -s "https://api.openai.com/v1/moderations" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${OPENAI_API_KEY}" \
        -d "{\"input\": \"$CONTENT\"}")
    
    # Extract and display only the relevant score
    CATEGORY=${TEST_CATEGORIES[$i]}
    THRESHOLD=${TEST_THRESHOLDS[$i]}
    SCORE=$(echo $MODERATION_RESPONSE | jq ".results[0].category_scores.$CATEGORY")
    echo -e "$CATEGORY Score: $SCORE (Threshold: $THRESHOLD)"
    
    echo -e "\n${GREEN}Testing Gateway Response:${NC}"
    RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "X-API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "${TEST_CASES[$i]}")

    # Extract body and status code from response
    BODY=$(echo "$RESPONSE" | sed '$d')
    HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

    echo "Gateway Status Code: $HTTP_CODE"
    if [ "$HTTP_CODE" == "403" ]; then
        echo -e "${RED}Content Blocked${NC}"
        ERROR_MESSAGE=$(echo $BODY | jq -r '.error')
        echo -e "${RED}$ERROR_MESSAGE${NC}"
    else
        echo -e "${GREEN}Content Allowed${NC}"
    fi

    # Compare with threshold
    if (( $(echo "$SCORE > $THRESHOLD" | bc -l) )); then
        echo -e "${RED}$CATEGORY score ($SCORE) exceeds threshold ($THRESHOLD)${NC}"
    else
        echo -e "${GREEN}$CATEGORY score ($SCORE) below threshold ($THRESHOLD)${NC}"
    fi
    echo "----------------------------------------"
done

echo -e "\n${GREEN}Toxicity detection tests completed${NC}" 