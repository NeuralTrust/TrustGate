# OpenAI Node.js SDK Example (TypeScript)

Use the standard OpenAI Node.js SDK through TrustGate — no client changes needed beyond the base URL and headers.

## Prerequisites

- TrustGate running locally (`make up` from repo root)
- A configured gateway, registry, and consumer (see [curl-first-request](../curl-first-request/) to set these up)
- Node.js 18+

## Setup

```bash
npm install
```

## Usage

Set your consumer credentials and run:

```bash
export CONSUMER_API_KEY="your-consumer-api-key"
export CONSUMER_SLUG="my-app"
export GATEWAY_SLUG="demo"

npx tsx chat.ts
```

## How it works

TrustGate's proxy plane is OpenAI-compatible. Point any OpenAI SDK at it:

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8081/my-app", // /{consumer_slug}
  apiKey: "unused", // provider key lives in the gateway
  defaultHeaders: {
    "X-AG-Gateway-Slug": "demo",
    "X-AG-API-Key": "<consumer api key>",
  },
});
```

The SDK's `apiKey` option is ignored — your upstream provider key (OpenAI, Anthropic, etc.) is stored securely in the registry you configured via the Admin API.

The example uses `gpt-4o-mini` by default, matching the Python example. Change the model if your TrustGate registry is configured for a different provider.
