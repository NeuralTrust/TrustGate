#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="datamask-$(date +%s)"

echo -e "${GREEN}Testing Data Masking Plugin${NC}\n"

# 1. Create a gateway with data masking plugin
echo -e "${GREEN}1. Creating gateway with data masking plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Data Masking Gateway",
    "subdomain": "'$SUBDOMAIN'",
    "required_plugins": [
        {
            "name": "data_masking",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "similarity_threshold": 0.8,
                "predefined_entities": [
                    {
                        "entity": "credit_card",
                        "enabled": true,
                        "mask_with": "[MASKED_CC]",
                        "preserve_len": false
                    },
                    {
                        "entity": "email",
                        "enabled": true,
                        "mask_with": "[MASKED_EMAIL]",
                        "preserve_len": false
                    },
                    {
                        "entity": "iban",
                        "enabled": true,
                        "mask_with": "[MASKED_IBAN]",
                        "preserve_len": false
                    },
                    {
                        "entity": "swift_bic",
                        "enabled": true,
                        "mask_with": "[MASKED_BIC]",
                        "preserve_len": false
                    },
                    {
                        "entity": "crypto_wallet",
                        "enabled": true,
                        "mask_with": "[MASKED_WALLET]",
                        "preserve_len": false
                    },
                    {
                        "entity": "tax_id",
                        "enabled": true,
                        "mask_with": "[MASKED_TAX_ID]",
                        "preserve_len": true
                    },
                    {
                        "entity": "key_pattern",
                        "enabled": true,
                        "mask_with": "[MASKED_KEY]",
                        "preserve_len": false
                    },
                    {
                        "entity": "mask_pattern",
                        "enabled": true,
                        "mask_with": "[MASKED_VALUE]",
                        "preserve_len": false
                    }
                ],
                "rules": [
                    {
                        "pattern": "secret_key",
                        "type": "keyword",
                        "mask_with": "****",
                        "preserve_len": true
                    }
                ]
            }
        },
        {
            "name": "data_masking",
            "enabled": true,
            "stage": "pre_response",
            "priority": 1,
            "settings": {
                "similarity_threshold": 0.8,
                "predefined_entities": [
                    {
                        "entity": "credit_card",
                        "enabled": true,
                        "mask_with": "[MASKED_CC]",
                        "preserve_len": false
                    },
                    {
                        "entity": "email",
                        "enabled": true,
                        "mask_with": "[MASKED_EMAIL]",
                        "preserve_len": false
                    },
                    {
                        "entity": "iban",
                        "enabled": true,
                        "mask_with": "[MASKED_IBAN]",
                        "preserve_len": false
                    },
                    {
                        "entity": "swift_bic",
                        "enabled": true,
                        "mask_with": "[MASKED_BIC]",
                        "preserve_len": false
                    },
                    {
                        "entity": "crypto_wallet",
                        "enabled": true,
                        "mask_with": "[MASKED_WALLET]",
                        "preserve_len": false
                    },
                    {
                        "entity": "tax_id",
                        "enabled": true,
                        "mask_with": "[MASKED_TAX_ID]",
                        "preserve_len": true
                    },
                    {
                        "entity": "key_pattern",
                        "enabled": true,
                        "mask_with": "[MASKED_KEY]",
                        "preserve_len": false
                    },
                    {
                        "entity": "mask_pattern",
                        "enabled": true,
                        "mask_with": "[MASKED_VALUE]",
                        "preserve_len": false
                    }
                ],
                "rules": [
                    {
                        "pattern": "secret_key",
                        "type": "keyword",
                        "mask_with": "****",
                        "preserve_len": true
                    },
                    {
                        "pattern": "INT-[0-9]{10}",
                        "type": "regex",
                        "mask_with": "[MASKED_TICKET_ID]",
                        "preserve_len": true
                    }
                ]
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

# Test data masking
echo -e "\n${GREEN}6. Testing data masking...${NC}"

# Test all masking patterns
echo -e "\n${GREEN}6.1 Testing all masking patterns...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "credit_card": "4111-2222-3333-4444",
        "email": "test@example.com",
        "iban": "DE89370400440532013000",
        "swift_bic": "DEUTDEFF500",
        "crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "tax_id": "12-3456789",
        "similar_secrets": "secret_keys_here",
        "ticket_id": "INT-1234567890",
        "reference": "This is a reference with INT-1234567890 in the middle"
    }')
echo "$RESPONSE"
# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Request successful${NC}"
    
    # Check each pattern
    PATTERNS=(
        "4111-2222-3333-4444"
        "test@example.com"
        "DE89370400440532013000"
        "DEUTDEFF500"
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        "12-3456789"
        "secret_keys_here"
        "INT-1234567890"
    )
  
    for pattern in "${PATTERNS[@]}"; do
        if echo "$BODY" | grep -q "$pattern"; then
            echo -e "${RED}WARNING: Pattern '$pattern' was not masked${NC}"
        else
            echo -e "${GREEN}Successfully masked: $pattern${NC}"
        fi
    done

    # Verify masked values are present
    MASKS=(
        "[MASKED_CC]"
        "[MASKED_EMAIL]"
        "[MASKED_IBAN]"
        "[MASKED_BIC]"
        "[MASKED_WALLET]"
        "[MASKED_TAX_ID]"
        "[MASKED_KEY]"
        "[MASKED_VALUE]"
        "[MASKED_TICKET_ID]"
    )
    
    for mask in "${MASKS[@]}"; do
        if echo "$BODY" | grep -q "$mask"; then
            echo -e "${GREEN}Found expected mask: $mask${NC}"
        else
            echo -e "${RED}WARNING: Expected mask '$mask' not found${NC}"
        fi
    done
else
    echo -e "${RED}Request failed with status code: $HTTP_CODE${NC}"
fi

# Test fuzzy matching
echo -e "\n${GREEN}6.2 Testing fuzzy matching...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/post" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-TG-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "message": "my sekret_key and secret-key should be masked",
        "notes": "Testing fuzzy matching"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')


HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Request successful${NC}"
    
    # Check fuzzy matches
    FUZZY_TERMS=("sekret_key" "secret-key")
    for term in "${FUZZY_TERMS[@]}"; do
        if echo "$BODY" | grep -q "$term"; then
            echo -e "${RED}WARNING: Similar term '$term' was not masked${NC}"
        else
            echo -e "${GREEN}Fuzzy masking successful for '$term'${NC}"
        fi
    done
else
    echo -e "${RED}Request failed with status code: $HTTP_CODE${NC}"
fi

echo -e "\n${GREEN}Data masking tests completed${NC}" 