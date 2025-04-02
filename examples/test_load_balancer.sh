#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'

# Test configuration
ADMIN_URL=${ADMIN_URL:-"http://localhost:8080/api/v1"}
PROXY_URL=${PROXY_URL:-"http://localhost:8081"}
BASE_DOMAIN=${BASE_DOMAIN:-"example.com"}
SUBDOMAIN="balancer-$(date +%s)"
GATEWAY_ID=""
API_KEY=""

# Use temporary files to store responses
RESPONSE_FILE=$(mktemp)

# Cleanup temporary files on exit
cleanup_files() {
    rm -f "$RESPONSE_FILE"
}
trap cleanup_files EXIT

# Function to create a test gateway with load balancing rules
create_test_gateway() {
    echo -e "${BLUE}Creating test gateway with load balancing rules...${NC}"
    
    echo "1. Creating gateway..."
    GATEWAY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Multi Rate Limited Gateway",
    "subdomain": "'$SUBDOMAIN'"
    }')


    # Extract fields from response
    GATEWAY_ID=$(echo "$GATEWAY_RESPONSE" | jq -r '.id')
    if [ "$GATEWAY_ID" == "null" ] || [ -z "$GATEWAY_ID" ]; then
        echo -e "${RED}Failed to create gateway. Response: $GATEWAY_RESPONSE${NC}"
        exit 1
    fi

    echo -e "Gateway ID: $GATEWAY_ID"

    # 2. Create API key
    echo -e "\n${GREEN}2. Creating API key...${NC}"
    API_KEY_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/keys" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Test Key",
        "expires_at": "2026-01-01T00:00:00Z"
    }')

    API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.key')

    if [ "$API_KEY" == "null" ] || [ -z "$API_KEY" ]; then
        echo -e "${RED}Failed to create API key. Response: $API_KEY_RESPONSE${NC}"
        exit 1
    fi

    echo "API Key created: $API_KEY"
    
    echo -e "\n${GREEN}3. Creating upstream...${NC}"
    # Create upstream with round-robin strategy
    UPSTREAM_RR_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "round-robin-upstream-'$(date +%s)'",
            "algorithm": "round-robin",
            "targets": [
                {
                    "host": "localhost",
                    "port": 9001,
                    "protocol": "http",
                    "weight": 100,
                    "priority": 1
                },
                {
                    "host": "localhost",
                    "port": 9002,
                    "protocol": "http",
                    "weight": 100,
                    "priority": 1
                },
                {
                    "host": "localhost",
                    "port": 9003,
                    "protocol": "http",
                    "weight": 100,
                    "priority": 1
                }
            ],
            "health_checks": {
                "passive": true,
                "threshold": 3,
                "interval": 60
            }
        }')

    UPSTREAM_RR_ID=$(echo "$UPSTREAM_RR_RESPONSE" | jq -r '.id')
    if [ "$UPSTREAM_RR_ID" == "null" ] || [ -z "$UPSTREAM_RR_ID" ]; then
        echo -e "${RED}Failed to create round-robin upstream. Response: $UPSTREAM_RR_RESPONSE${NC}"
        exit 1
    fi

    # Create upstream with weighted strategy
    UPSTREAM_W_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/upstreams" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "weighted-upstream-'$(date +%s)'",
            "algorithm": "weighted-round-robin",
            "targets": [
                {
                    "host": "localhost",
                    "port": 9001,
                    "protocol": "http",
                    "weight": 60,
                    "priority": 1
                },
                {
                    "host": "localhost",
                    "port": 9002,
                    "protocol": "http",
                    "weight": 30,
                    "priority": 1
                },
                {
                    "host": "localhost",
                    "port": 9003,
                    "protocol": "http",
                    "weight": 10,
                    "priority": 1
                }
            ],
            "health_checks": {
                "passive": true,
                "threshold": 3,
                "interval": 60
            }
        }')

    UPSTREAM_W_ID=$(echo "$UPSTREAM_W_RESPONSE" | jq -r '.id')
    if [ "$UPSTREAM_W_ID" == "null" ] || [ -z "$UPSTREAM_W_ID" ]; then
        echo -e "${RED}Failed to create weighted upstream. Response: $UPSTREAM_W_RESPONSE${NC}"
        exit 1
    fi

    echo -e "\n${GREEN}4. Creating services...${NC}"
    # Create service for round-robin
    SERVICE_RR_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "round-robin-service-'$(date +%s)'",
            "type": "upstream",
            "description": "Round-robin test service",
            "upstream_id": "'$UPSTREAM_RR_ID'"
        }')

    SERVICE_RR_ID=$(echo "$SERVICE_RR_RESPONSE" | jq -r '.id')
    if [ "$SERVICE_RR_ID" == "null" ] || [ -z "$SERVICE_RR_ID" ]; then
        echo -e "${RED}Failed to create round-robin service. Response: $SERVICE_RR_RESPONSE${NC}"
        exit 1
    fi

    # Create service for weighted
    SERVICE_W_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/services" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "weighted-service-'$(date +%s)'",
            "type": "upstream",
            "description": "Weighted test service",
            "upstream_id": "'$UPSTREAM_W_ID'"
        }')

    SERVICE_W_ID=$(echo "$SERVICE_W_RESPONSE" | jq -r '.id')
    if [ "$SERVICE_W_ID" == "null" ] || [ -z "$SERVICE_W_ID" ]; then
        echo -e "${RED}Failed to create weighted service. Response: $SERVICE_W_RESPONSE${NC}"
        exit 1
    fi
    
    echo -e "\n${GREEN}5. Creating rules...${NC}"
    # Create round-robin rule
    RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
        -H "Content-Type: application/json" \
        -d '{
            "path": "/round-robin",
            "service_id": "'$SERVICE_RR_ID'",
            "methods": ["GET"],
            "strip_path": true,
            "active": true
        }')

    if ! echo "$RULE_RESPONSE" | jq -e '.id' > /dev/null; then
        echo -e "${RED}Failed to create round-robin rule. Response: $RULE_RESPONSE${NC}"
        exit 1
    fi

    # Create weighted rule
    RULE_RESPONSE=$(curl -s -X POST "$ADMIN_URL/gateways/$GATEWAY_ID/rules" \
        -H "Content-Type: application/json" \
        -d '{
            "path": "/weighted",
            "service_id": "'$SERVICE_W_ID'",
            "methods": ["GET"],
            "strip_path": true,
            "active": true
        }')

    if ! echo "$RULE_RESPONSE" | jq -e '.id' > /dev/null; then
        echo -e "${RED}Failed to create weighted rule. Response: $RULE_RESPONSE${NC}"
        exit 1
    fi

    echo -e "${GREEN}Gateway, upstreams, services, and rules created successfully${NC}"
}

# Function to check if required tools are installed
check_requirements() {
    echo -e "${BLUE}Checking requirements...${NC}"
    for cmd in nc jq curl; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}Error: $cmd is required but not installed.${NC}"
            echo "Please install $cmd and try again."
            exit 1
        fi
    done
    echo -e "${GREEN}All requirements satisfied.${NC}"
}

# Function to start a Python-based mock server
create_mock_server() {
    local port=$1
    cat > "/tmp/mock_server_${port}.py" << 'EOF'
import sys
import http.server
import json
import datetime
import socket
import time

port = int(sys.argv[1])

def wait_for_port(port, timeout=5):
    start_time = time.time()
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', port))
                return True
        except socket.error:
            if time.time() - start_time > timeout:
                return False
            time.sleep(0.1)

class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            "server": f"localhost:{port}",
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        return  # Suppress logging

try:
    server = http.server.HTTPServer(('localhost', port), MockHandler)
    print(f"Server started on port {port}")
    if not wait_for_port(port):
        print(f"Server failed to start on port {port}")
        sys.exit(1)
    server.serve_forever()
except Exception as e:
    print(f"Error starting server on port {port}: {e}")
    sys.exit(1)
EOF

    python3 "/tmp/mock_server_${port}.py" $port &
    echo $! > "/tmp/mock_server_${port}.pid"
    
    # Wait for server to start
    sleep 1
}

# Function to start mock backend servers
start_mock_servers() {
    echo -e "${BLUE}Starting mock backend servers...${NC}"
    
    # Create a temporary directory for server files
    TEMP_DIR=$(mktemp -d)
    echo "Using temporary directory: $TEMP_DIR"
    
    # Check if Python 3 is available
    if command -v python3 &> /dev/null; then
        # Use Python-based mock servers
        for port in 9001 9002 9003; do
            echo "Starting server on port $port"
            create_mock_server $port
            
            # Verify server started successfully
            if ! curl -s "http://localhost:${port}" > /dev/null; then
                echo -e "${RED}Error: Server on port $port failed to start${NC}"
                cat "/tmp/mock_server_${port}.py"  # Print server script for debugging
                stop_mock_servers
                exit 1
            fi
        done
    else
        # Fallback to nc-based servers with OS-specific syntax
        for port in 9001 9002 9003; do
            echo "Starting server on port $port"
            (while true; do 
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"server\":\"localhost:$port\", \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" | nc -l $port
                else
                    echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"server\":\"localhost:$port\", \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" | nc -l -p $port
                fi
            done) &
            echo $! > "/tmp/mock_server_${port}.pid"
        done
    fi
    
    # Verify servers are running
    for port in 9001 9002 9003; do
        echo "Verifying server on port $port..."
        if ! curl -s "http://localhost:${port}" > /dev/null; then
            echo -e "${RED}Error: Server on port $port failed to start${NC}"
            stop_mock_servers
            exit 1
        fi
        echo -e "${GREEN}Server on port $port is running${NC}"
    done
    
    sleep 2
}

# Function to stop mock servers
stop_mock_servers() {
    echo -e "${BLUE}Stopping mock servers...${NC}"
    for port in 9001 9002 9003; do
        pid_file="/tmp/mock_server_${port}.pid"
        py_file="/tmp/mock_server_${port}.py"
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            pkill -P $pid 2>/dev/null  # Kill child processes
            kill $pid 2>/dev/null || kill -9 $pid 2>/dev/null  # Kill main process
            rm "$pid_file"
            [ -f "$py_file" ] && rm "$py_file"
        fi
    done
    
    # Clean up temporary directory
    [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}

# Function to test round-robin load balancing
test_round_robin() {
    echo -e "${BLUE}Testing round-robin load balancing...${NC}"
    
    # Clear the response file
    > "$RESPONSE_FILE"
    total_requests=9
    
    for i in $(seq 1 $total_requests); do
        response=$(curl -s \
            -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
            -H "X-TG-API-Key: ${API_KEY}" \
            "$PROXY_URL/round-robin")
        
        server=$(echo "$response" | jq -r '.server')
        if [ "$server" != "null" ] && [ ! -z "$server" ]; then
            echo "$server" >> "$RESPONSE_FILE"
        else
            echo -e "${RED}Error: Received null response from server${NC}"
            echo "Full response: $response"
            echo "API Key: $API_KEY"
            echo "Host: ${SUBDOMAIN}.${BASE_DOMAIN}"
            return 1
        fi
        echo "Request $i: $server"
    done
    
    # Verify distribution
    echo -e "\nDistribution:"
    sort "$RESPONSE_FILE" | uniq -c | while read count server; do
        echo "$server: $count requests"
    done
    
    # Check if each server got approximately equal requests
    expected=$((total_requests / 3))
    success=true
    while read count server; do
        if [ $count -lt $((expected - 1)) ] || [ $count -gt $((expected + 1)) ]; then
            success=false
            break
        fi
    done < <(sort "$RESPONSE_FILE" | uniq -c)
    
    if [ "$success" = true ]; then
        echo -e "${GREEN}Round-robin test passed!${NC}"
    else
        echo -e "${RED}Round-robin test failed - uneven distribution${NC}"
    fi
}

# Function to test weighted load balancing
test_weighted() {
    echo -e "${BLUE}Testing weighted load balancing...${NC}"
    total_requests=100  # Use larger sample size for better statistics
    success=true
    
    # Track consecutive failures
    failures=0
    max_failures=3
    
    echo "Expected distribution:"
    echo "localhost:9001: 60%"
    echo "localhost:9002: 30%"
    echo "localhost:9003: 10%"
    echo ""
    
    # Warmup phase
    echo "Performing warmup requests..."
    for i in $(seq 1 20); do
        curl -s -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
            -H "X-TG-API-Key: $API_KEY" \
            "$PROXY_URL/weighted" > /dev/null
    done
    echo "Warmup complete"
    echo ""
    
    for i in $(seq 1 $total_requests); do
        response=$(curl -s -H "Host: ${SUBDOMAIN}.${BASE_DOMAIN}" \
        -H "X-TG-API-Key: $API_KEY" \
        "$PROXY_URL/weighted")
        server=$(echo "$response" | jq -r '.server')
        if [ "$server" != "null" ] && [ ! -z "$server" ]; then
            echo "$server" >> "$RESPONSE_FILE"
            failures=0
        else
            echo -e "${RED}Error: Received null response from server${NC}"
            echo "Full response: $response"
            failures=$((failures + 1))
            if [ $failures -ge $max_failures ]; then
                echo -e "${RED}Too many consecutive failures${NC}"
                return 1
            fi
            return 1
        fi
        echo -n "."
        # Print progress every 50 requests
        if [ $((i % 50)) -eq 0 ]; then
            echo " $i/$total_requests"
        fi
    done
    echo ""
    
    # Verify distribution
    echo -e "\nActual distribution:"
    while read count server; do
        percentage=$((count * 100 / total_requests))
        echo "$server: $count requests ($percentage%)"
        
        # Check if distribution matches weights (with 10% tolerance)
        case "$server" in
            "localhost:9001") expected=60 ;;
            "localhost:9002") expected=30 ;;
            "localhost:9003") expected=10 ;;
            *) continue ;;
        esac
        
        if [ $percentage -lt $((expected - 10)) ] || [ $percentage -gt $((expected + 10)) ]; then
            success=false
            echo -e "${RED}  Expected: $expected% (±10%), Got: $percentage%${NC}"
        fi
    done < <(sort "$RESPONSE_FILE" | uniq -c)
    
    if [ "$success" = true ]; then
        echo -e "${GREEN}Weighted distribution test passed!${NC}"
    else
        echo -e "${RED}Weighted distribution test failed - distribution outside tolerance${NC}"
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}Cleaning up...${NC}"
    stop_mock_servers
    exit $1
}

# Main test execution
main() {
    # Cleanup any existing mock servers
    stop_mock_servers
    
    # Start fresh mock servers
    start_mock_servers
    
    # Create test gateway and rules
    create_test_gateway
    
    # Wait for gateway and rules to be ready
    sleep 2
    
    # Run tests
    test_round_robin || {
        echo -e "${RED}Round-robin test failed${NC}"
        cleanup 1
    }
    
    echo ""
    
    test_weighted || {
        echo -e "${RED}Weighted test failed${NC}"
        cleanup 1
    }
    
    # Cleanup
    stop_mock_servers
}

# Set up trap for cleanup on script exit
trap 'cleanup $?' EXIT INT TERM

# Run main function
main 