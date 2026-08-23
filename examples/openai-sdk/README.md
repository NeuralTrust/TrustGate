# OpenAI SDK Example

Use the standard OpenAI Python SDK through TrustGate — no client changes needed beyond the base URL and headers.

## Prerequisites

- TrustGate running locally (`make up` from repo root)
- A configured gateway, registry, and consumer (see [curl-first-request](../curl-first-request/) to set these up)
- Python 3.8+

## Setup

```bash
pip install openai
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

TrustGate's proxy plane is OpenAI-compatible. Point any OpenAI SDK at it:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8081/my-app",  # /{consumer_slug}
    api_key="unused",  # provider key lives in the gateway
    default_headers={
        "X-AG-Gateway-Slug": "demo",
        "X-AG-API-Key": "<consumer api key>",
    },
)
```

The SDK's `api_key` parameter is ignored — your upstream provider key (OpenAI, Anthropic, etc.) is stored securely in the registry you configured via the Admin API.

## Other endpoints

The same consumer slug works for all OpenAI-compatible endpoints:

- `/v1/chat/completions` — Chat completions
- `/v1/messages` — Anthropic Messages format
- `/v1/responses` — OpenAI Responses format
- `/v1/models` — SDK `client.models.list()` / `client.models.retrieve(id)` (gateway-owned discovery of models this consumer can call)
- `/v1/audio/speech` — SDK `client.audio.speech.create()` (raw audio bytes)
- `/v1/audio/transcriptions` — SDK `client.audio.transcriptions.create()` (multipart file)
- `/v1/images/generations` — SDK `client.images.generate()` (OpenAI, Azure, openai_compatible, OpenRouter)
- `/v1/images/edits` — SDK `client.images.edit()` (multipart; same providers)
- `/v1/images/variations` — SDK `client.images.create_variation()` (multipart; same providers)
