# Anthropic SDK Example

Use the standard Anthropic Python SDK through TrustGate — no client changes needed beyond the base URL and headers.

## Prerequisites

- TrustGate running locally (`make up` from repo root)
- A configured gateway, consumer, and an **Anthropic registry** attached to that consumer (see [Registry setup](#registry-setup) below, or adapt [curl-first-request](../curl-first-request/))
- Python 3.8+
- An Anthropic API key (from the [Anthropic Console](https://console.anthropic.com/settings/keys))

## Setup

```bash
pip install -r requirements.txt
```

## Usage

Set your consumer credentials and run:

```bash
export CONSUMER_API_KEY="your-consumer-api-key"
export CONSUMER_SLUG="my-app"
export GATEWAY_SLUG="demo"

python chat.py
```

## How it works

TrustGate's proxy plane speaks the Anthropic Messages API natively on `/v1/messages`. Point the Anthropic SDK at it like this:

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://localhost:8081/my-app",  # /{consumer_slug}
    api_key="unused",  # provider key lives in the gateway
    default_headers={
        "X-AG-Gateway-Slug": "demo",
        "X-AG-API-Key": "<consumer api key>",
    },
)

response = client.messages.create(
    model="claude-3-5-haiku-latest",
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello!"}],
)
```

The SDK's `api_key` parameter is ignored — your real Anthropic key is stored securely in the registry you configure via the Admin API, not on the client.

## Registry setup

The consumer used by this example needs a registry whose `provider` is `anthropic`, holding your real Anthropic API key. Using the same admin-token flow as [curl-first-request](../curl-first-request/first-request.sh):

```bash
ADMIN="http://localhost:8080"

# 1. Create (or reuse) a gateway
GW=$(curl -sf -X POST "$ADMIN/v1/gateways" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"Demo Gateway","slug":"demo"}')
GW_ID=$(echo "$GW" | jq -r .id)

# 2. Register Anthropic as an upstream provider
REG=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/registries" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "anthropic-primary",
        "provider": "anthropic",
        "auth": {
            "type": "api_key",
            "api_key": {"api_key": "'"$ANTHROPIC_API_KEY"'"}
        }
    }')
REG_ID=$(echo "$REG" | jq -r .id)

# 3. Create a consumer bound to that registry
CON=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/consumers" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "my-app",
        "registries": [{"id": "'"$REG_ID"'"}]
    }')
CON_ID=$(echo "$CON" | jq -r .id)
CON_SLUG=$(echo "$CON" | jq -r .slug)

# 4. Mint and attach a consumer API key
AUTH=$(curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/auths" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"my-app-key","type":"api_key"}')
AUTH_ID=$(echo "$AUTH" | jq -r .id)
API_KEY=$(echo "$AUTH" | jq -r .api_key)

curl -sf -X POST "$ADMIN/v1/gateways/$GW_ID/consumers/$CON_ID/auths/$AUTH_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
```

Use the resulting `$CON_SLUG` as `CONSUMER_SLUG` and `$API_KEY` as `CONSUMER_API_KEY` when running `chat.py`. A consumer can hold multiple registries (e.g. `openai-primary` and `anthropic-primary` together) — TrustGate routes each proxy path to a registry capable of serving it.

## Other endpoints

The same consumer slug works for all Anthropic-compatible surfaces:

- `/v1/messages` — Anthropic Messages format (this example)
- `/v1/chat/completions` — OpenAI Chat Completions format (also served against an Anthropic registry)
- `/v1/models` — SDK `client.models.list()` / `client.models.retrieve(id)` (gateway-owned discovery of models this consumer can call)
- `/v1/files` — SDK `client.files.*` (Anthropic's native Files API, forwarded as-is)