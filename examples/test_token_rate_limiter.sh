#!/bin/bash

# Configuration
ADMIN_URL="http://localhost:8080/api/v1"
PROXY_URL="http://localhost:8081"
TIMESTAMP=$(date +%s)
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="tokentest-$TIMESTAMP"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to print section header
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to print rate limit info from response headers
print_rate_limits() {
    local response_headers=$1
    echo "$response_headers"
    echo -e "${GREEN}Rate Limit Info:${NC}"
    echo "Requests Limit: $(echo "$response_headers" | grep -i "x-ratelimit-limit-requests" | cut -d' ' -f2)"
    echo "Requests Remaining: $(echo "$response_headers" | grep -i "x-ratelimit-remaining-requests" | cut -d' ' -f2)"
    echo "Requests Reset: $(echo "$response_headers" | grep -i "x-ratelimit-reset-requests" | cut -d' ' -f2)"
    echo "Tokens Limit: $(echo "$response_headers" | grep -i "x-ratelimit-limit-tokens" | cut -d' ' -f2)"
    echo "Tokens Remaining: $(echo "$response_headers" | grep -i "x-ratelimit-remaining-tokens" | cut -d' ' -f2)"
    echo "Tokens Reset: $(echo "$response_headers" | grep -i "x-ratelimit-reset-tokens" | cut -d' ' -f2)"
    echo "Tokens Consumed: $(echo "$response_headers" | grep -i "x-tokens-consumed" | cut -d' ' -f2)"
}

# Check if OPENAI_API_KEY is set
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}Error: OPENAI_API_KEY environment variable is not set${NC}"
    echo "Please set your OpenAI API key first:"
    echo "export OPENAI_API_KEY=your_api_key"
    exit 1
fi

print_header "Creating Gateway with Token Rate Limiter"

# Create gateway with token rate limiter plugin
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Token Rate Limiter Example",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
      {
        "name": "token_rate_limiter",
        "enabled": true,
        "settings": {
          "tokens_per_request": 20,
          "tokens_per_minute": 100,
          "bucket_size": 1000,
          "requests_per_minute": 60
        }
      }
    ]
  }')

GATEWAY_ID=$(echo $GATEWAY_RESPONSE | jq -r '.id')

if [ -z "$GATEWAY_ID" ] || [ "$GATEWAY_ID" == "null" ]; then
    echo -e "${RED}Failed to create gateway${NC}"
    echo $GATEWAY_RESPONSE
    exit 1
fi

echo -e "${GREEN}Gateway created with ID: $GATEWAY_ID${NC}"

# Create upstream for OpenAI
print_header "Creating Upstream"
UPSTREAM_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openai-upstream-'$(date +%s)'",
    "algorithm": "round-robin",
    "targets": [{
          "path": "/v1/chat/completions",
          "provider": "openai",
          "weight": 100,
          "models": ["gpt-3.5-turbo","gpt-4","gpt-4o-mini"],
          "default_model": "gpt-4o-mini",
          "credentials": {
            "header_name": "Authorization",
            "header_value": "Bearer '"$OPENAI_API_KEY"'"
        }
    }],
    "health_checks": {
        "passive": true,
        "threshold": 3,
        "interval": 60
    }
}')

UPSTREAM_ID=$(echo $UPSTREAM_RESPONSE | jq -r '.id')

if [ -z "$UPSTREAM_ID" ] || [ "$UPSTREAM_ID" == "null" ]; then
    echo -e "${RED}Failed to create upstream${NC}"
    echo $UPSTREAM_RESPONSE
    exit 1
fi

echo -e "${GREEN}Upstream created with ID: $UPSTREAM_ID${NC}"

# Create service
print_header "Creating Service"
SERVICE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openai-service-'$(date +%s)'",
    "type": "upstream",
    "description": "OpenAI API Service",
    "upstream_id": "'$UPSTREAM_ID'",
    "retries": 3
}')

SERVICE_ID=$(echo $SERVICE_RESPONSE | jq -r '.id')

if [ -z "$SERVICE_ID" ] || [ "$SERVICE_ID" == "null" ]; then
    echo -e "${RED}Failed to create service${NC}"
    echo $SERVICE_RESPONSE
    exit 1
fi

echo -e "${GREEN}Service created with ID: $SERVICE_ID${NC}"

# Create API key
print_header "Creating API Key"
API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-key",
    "expires_at": "2026-01-01T00:00:00Z"
  }')

API_KEY=$(echo $API_KEY_RESPONSE | jq -r '.key')

if [ -z "$API_KEY" ] || [ "$API_KEY" == "null" ]; then
    echo -e "${RED}Failed to create API key${NC}"
    echo $API_KEY_RESPONSE
    exit 1
fi

echo -e "${GREEN}API key created: $API_KEY${NC}"

# Create rule
print_header "Creating Rule"
RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/v1",
    "service_id": "'$SERVICE_ID'",
    "methods": ["POST"],
    "strip_path": false,
    "active": true
}')

# Wait for gateway to be ready
echo "Waiting for gateway to be ready..."
sleep 2

# Function to make a chat completion request
make_chat_request() {
    local prompt=$1
    local description=$2
    
    print_header "$description"
    echo "Prompt: $prompt"
    
    # Make the request and capture both headers and body
    local response=$(curl -v -s -i -X POST "${PROXY_URL}/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "X-TG-API-Key: $API_KEY" \
        -d '{
            "model": "gpt-4o-mini",
            "stream": true,
            "stream_options": {
                "include_usage": true
            },
            "messages": [
                {
                    "role": "user",
                    "content": "'"$prompt"'"
                }
            ]
        }')
    
    # Split headers and body
    local headers=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"}NR==1')
    local body=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"}NR==2')
    
    # Print rate limit and token consumption info
    print_rate_limits "$headers"
    
    # Check if response is valid JSON and print preview
    if echo "$body" | jq -e . >/dev/null 2>&1; then
        # Check if response contains an error
        if echo "$body" | jq -e '.error' >/dev/null 2>&1; then
            echo -e "\n${RED}Error Response:${NC}"
            echo "$body" | jq -r '.error'
        else
            echo -e "\n${GREEN}Response Preview:${NC}"
            echo "$body" | jq -r '.choices[0].message.content' | head -n 3
        fi
    else
        echo -e "${RED}Error: Invalid response${NC}"
        echo "$body"
    fi
    
    echo "----------------------------------------"
    # Add small delay between requests
    sleep 1
}

# Test Sequence
# Request 1: Short message
make_chat_request "Hello, how are you?" "Request 1: Short Message"

# Request 2: Medium length request
make_chat_request "Write me a paragraph about AI" "Request 2: Medium Length Request"

# Wait for token refill
print_header "Waiting for token refill (60 seconds)"
sleep 60

# Request 3: Large completion
make_chat_request "Write a detailed essay about the future of technology, including AI, quantum computing, and space exploration. Include specific examples and potential timeline predictions." "Request 3: Large Completion"

# Request 4: Should fail due to insufficient tokens
make_chat_request "Write a comprehensive technical specification for a new programming language, including syntax, features, standard library, and comparison with existing languages." "Request 4: Should Fail - Insufficient Tokens" 