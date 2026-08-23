# MCP + Cursor Example

Configure Cursor IDE to use TrustGate's MCP plane as an aggregated tool gateway.

## What is the MCP Plane?

TrustGate's MCP plane (`:8082`) implements the [Model Context Protocol](https://modelcontextprotocol.io), letting AI agents like Cursor and Claude connect to multiple upstream MCP tool servers through a single gateway.

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  Cursor / Agent │ ───▶ │ TrustGate MCP    │ ───▶ │ Upstream MCP    │
│                 │      │ :8082            │      │ servers         │
└─────────────────┘      └──────────────────┘      └─────────────────┘
```

Benefits:
- **Single endpoint** — Agents connect to TrustGate instead of individual tools
- **Access control** — Per-consumer toolkits, rate limiting, audit
- **Aggregation** — Combine tools from multiple MCP servers

## Prerequisites

- TrustGate running with the MCP plane (`make up`)
- An MCP consumer configured (see [Setup](#setup))

## Setup

### 1. Start TrustGate

```bash
make up
curl localhost:8082/healthz  # verify MCP plane is running
```

### 2. Configure an MCP consumer via Admin API

```bash
# Set your admin token (see examples/README.md)
ADMIN="http://localhost:8080"
MCP="http://localhost:8082"

# Create a gateway
GW=$(curl -s -X POST "$ADMIN/v1/gateways" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"MCP Demo","slug":"mcp-demo"}')
GW_ID=$(echo "$GW" | jq -r .id)

# Register an upstream MCP server (example: a local MCP server on port 9100)
REG=$(curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/registries" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "local-mcp",
    "type": "mcp",
    "mcp_target": { "url": "http://127.0.0.1:9100/mcp" }
  }')
REG_ID=$(echo "$REG" | jq -r .id)

# Create an MCP consumer
CON=$(curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/consumers" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "agent-client",
    "type": "mcp",
    "registries": [{"id": "'"$REG_ID"'"}]
  }')
CON_SLUG=$(echo "$CON" | jq -r .slug)
CON_ID=$(echo "$CON" | jq -r .id)

# Create and attach an API key
AUTH=$(curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/auths" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"cursor-key","type":"api_key"}')
AUTH_ID=$(echo "$AUTH" | jq -r .id)
API_KEY=$(echo "$AUTH" | jq -r .api_key)

curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/consumers/$CON_ID/auths/$AUTH_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

echo "Consumer slug: $CON_SLUG"
echo "API key: $API_KEY"
```

### 3. Configure Cursor

Create or edit your Cursor MCP configuration (`mcp.json`):

```json
{
  "mcpServers": {
    "trustgate": {
      "url": "http://localhost:8082/agent-client/mcp",
      "headers": {
        "X-AG-API-Key": "<your consumer API key>"
      }
    }
  }
}
```

Replace:
- `agent-client` with your consumer slug
- `<your consumer API key>` with the API key from step 2

### 4. Test the connection

Cursor should now see tools from your upstream MCP servers. You can also test manually:

```bash
# List available tools
curl -X POST "http://localhost:8082/agent-client/mcp" \
  -H "Content-Type: application/json" \
  -H "X-AG-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}'
```

## Using the MCP Catalog

TrustGate includes a catalog of pre-configured MCP servers:

```bash
curl -s "$ADMIN/v1/mcp-servers-catalog" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.mcp_servers[0:5]'
```

Add one to your consumer's registries via the Admin API or UI.

## Further Reading

- [MCP Testing Guide](../../docs/mcp/testing-guide.md) — Full MCP plane documentation
- [Model Context Protocol](https://modelcontextprotocol.io) — MCP specification
