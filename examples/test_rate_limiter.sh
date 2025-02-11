#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="gateway-rate-limiter-$(date +%s)"

echo -e "${GREEN}Testing Rate Limiter${NC}\n"

# 1. Create a gateway with rate limiting plugin
echo -e "${GREEN}1. Creating gateway with rate limiting plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Multi Rate Limited Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "rate_limiter",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "limits": {
                    "global": {
                        "limit": 15,
                        "window": "1m"
                    },
                    "per_ip": {
                        "limit": 5,
                        "window": "1m"
                    },
                    "per_user": {
                        "limit": 5,
                        "window": "1m"
                    }
                },
                "actions": {
                    "type": "reject",
                    "retry_after": "60"
                }
            }
        }
    ]
}')
echo $GATEWAY_RESPONSE | jq
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
    "upstream_id": "'$UPSTREAM_ID'"
}')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# Create rules for different paths
echo -e "\n${GREEN}5. Creating rules for different paths...${NC}"
RULE1_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path1",
    "service_id": "'$SERVICE_ID'",
    "methods": ["GET"],
    "strip_path": true,
    "active": true
}')

RULE2_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path2",
    "service_id": "'$SERVICE_ID'",
    "methods": ["GET"],
    "strip_path": true,
    "active": true
}')

# Wait for configuration to propagate
sleep 2

# Test different rate limit types
echo -e "\n${GREEN}6. Testing different rate limit types...${NC}"

# Test IP-based rate limit
echo -e "\n${GREEN}6.1 Testing IP-based rate limit (limit: 5/min)...${NC}"
for i in {1..10}; do
    start_time=$(date +%s.%N)
    
    RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" "$PROXY_URL/path2" \
        -H "Host: $SUBDOMAIN.$BASE_DOMAIN" \
        -H "X-API-Key: $API_KEY")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n2 | head -n1)
    BODY=$(echo "$RESPONSE" | head -n1)
    
    
    if [ "$HTTP_CODE" == "200" ]; then
        echo -e "${GREEN}IP-based Request $i: Success${NC}"
    elif [ "$HTTP_CODE" == "429" ]; then
        echo -e "${RED}IP-based Request $i: Rate Limited (Expected after 5 requests)${NC}"
        echo "Response: $BODY"
    else
        echo -e "${RED}IP-based Request $i: Unexpected status code: $HTTP_CODE${NC}"
        echo "Response: $BODY"
    fi
    sleep 0.1
done

echo -e "\n${GREEN}Rate limiter tests completed${NC}" 