# curl First Request

A shell script that sets up a gateway, registry, consumer, and API key — then makes a chat completion through TrustGate.

## Prerequisites

- TrustGate running locally (`make up` from repo root)
- `curl` and `jq` installed
- `OPENAI_API_KEY` set in your environment

## Usage

```bash
# Set your OpenAI key
export OPENAI_API_KEY="sk-..."

# Run the example
./first-request.sh
```

## What it does

1. Generates an admin JWT token
2. Creates a gateway named "demo"
3. Registers OpenAI as an upstream provider
4. Creates a consumer "my-app" bound to that registry
5. Mints a consumer API key
6. Makes a chat completion request through the proxy

## Manual steps

If you prefer to run commands individually, see the [full Admin API setup](../../README.md#advanced-full-admin-api-setup) in the main README.
