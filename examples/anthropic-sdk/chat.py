#!/usr/bin/env python3
"""
TrustGate + Anthropic SDK example.

Point the standard Anthropic SDK at TrustGate's proxy plane. TrustGate
speaks the Anthropic Messages API on /v1/messages, so no request/response
translation is needed as long as an Anthropic-capable registry is attached
to the consumer (an "anthropic" registry, or any provider whose adapter
supports the Messages format).

Prerequisites:
    - TrustGate running (make up)
    - Gateway, registry, and consumer configured
    - Environment variables set:
        CONSUMER_API_KEY - your consumer API key
        CONSUMER_SLUG - consumer slug (default: my-app)
        GATEWAY_SLUG - gateway slug (default: demo)
        PROXY_URL - proxy URL (default: http://localhost:8081)

Usage:
    pip install -r requirements.txt
    export CONSUMER_API_KEY="..."
    python chat.py
"""

import os
from anthropic import Anthropic

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8081")
CONSUMER_SLUG = os.environ.get("CONSUMER_SLUG", "my-app")
GATEWAY_SLUG = os.environ.get("GATEWAY_SLUG", "demo")
CONSUMER_API_KEY = os.environ.get("CONSUMER_API_KEY")

if not CONSUMER_API_KEY:
    raise ValueError(
        "CONSUMER_API_KEY environment variable is required.\n"
        "Run examples/curl-first-request/first-request.sh to create one "
        "(swap the registry provider to 'anthropic' as described in this "
        "example's README)."
    )

client = Anthropic(
    base_url=f"{PROXY_URL}/{CONSUMER_SLUG}",
    api_key="unused",  # the real provider key lives in the TrustGate registry
    default_headers={
        "X-AG-Gateway-Slug": GATEWAY_SLUG,
        "X-AG-API-Key": CONSUMER_API_KEY,
    },
)

response = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=256,
    messages=[
        {"role": "user", "content": "What is TrustGate in one sentence?"},
    ],
)

print(response.content[0].text)