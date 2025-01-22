#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if hey is installed
if ! command -v hey &> /dev/null; then
    echo -e "${RED}Error: 'hey' is not installed${NC}"
    echo "Installing hey..."
    export PATH=$PATH:$(go env GOPATH)/bin
    go install github.com/rakyll/hey@latest
    if ! command -v hey &> /dev/null; then
        echo -e "${RED}Failed to install hey. Please install it manually:${NC}"
        echo "go install github.com/rakyll/hey@latest"
        echo "And make sure your GOPATH/bin is in your PATH"
        exit 1
    fi
fi

# Configuration
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="benchmark"
CONCURRENT_USERS=50
DURATION="30s"

echo -e "${BLUE}TrustGate Benchmark Tool${NC}\n"

# Test 1: System endpoint (ping)
echo -e "${GREEN}Testing system ping endpoint...${NC}"
echo -e "\n${BLUE}Starting system benchmark with ${CONCURRENT_USERS} concurrent users for ${DURATION}...${NC}"
hey -z ${DURATION} \
    -c ${CONCURRENT_USERS} \
    -disable-keepalive \
    -cpus 2 \
    "${PROXY_URL}/__/ping"

# Create test gateway
echo -e "${GREEN}Creating test gateway...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Benchmark Gateway",
    "subdomain": "benchmark"
  }')

GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')

if [ "$GATEWAY_ID" == "null" ] || [ -z "$GATEWAY_ID" ]; then
    echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
    exit 1
fi

echo "Gateway created with ID: $GATEWAY_ID"

# Create API key
echo -e "\n${GREEN}Creating API key...${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Benchmark Key",
    "expires_at": "2026-01-01T00:00:00Z"
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
    echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
    exit 1
fi

echo "API Key created: $API_KEY"

# Create upstream
echo -e "\n${GREEN}Creating upstream...${NC}"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ping-upstream-'$(date +%s)'",
    "algorithm": "round-robin",
    "targets": [{
        "host": "localhost",
        "port": 8081,
        "protocol": "http",
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
echo -e "\n${GREEN}Creating service...${NC}"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ping-service-'$(date +%s)'",
    "type": "upstream",
    "description": "Ping test service",
    "upstream_id": "'$UPSTREAM_ID'"
}')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ "$SERVICE_ID" == "null" ] || [ -z "$SERVICE_ID" ]; then
    echo -e "${RED}Failed to create service. Response: $SERVICE_RESPONSE${NC}"
    exit 1
fi

echo "Service created with ID: $SERVICE_ID"

# Create rule
echo -e "\n${GREEN}Creating rule...${NC}"
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

# Test 2: Forwarded ping endpoint
echo -e "${GREEN}Testing forwarded ping endpoint...${NC}"
echo -e "\n${BLUE}Starting forwarded benchmark with ${CONCURRENT_USERS} concurrent users for ${DURATION}...${NC}"
hey -z ${DURATION} \
    -c ${CONCURRENT_USERS} \
    -disable-keepalive \
    -cpus 2 \
    -H "X-API-Key: ${API_KEY}" \
    -H "Host: benchmark.example.com" \
    -host "benchmark.example.com" \
    "${PROXY_URL}/test"