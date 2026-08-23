#!/usr/bin/env python3
"""
TrustGate + OpenAI SDK example.

Point the standard OpenAI SDK at TrustGate's proxy plane.

Prerequisites:
    - TrustGate running (make up)
    - Gateway, registry, and consumer configured
    - Environment variables set:
        CONSUMER_API_KEY - your consumer API key
        CONSUMER_SLUG - consumer slug (default: my-app)
        GATEWAY_SLUG - gateway slug (default: demo)
        PROXY_URL - proxy URL (default: http://localhost:8081)

Usage:
    pip install openai
    export CONSUMER_API_KEY="..."
    python chat.py
"""

import os
from openai import OpenAI

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8081")
CONSUMER_SLUG = os.environ.get("CONSUMER_SLUG", "my-app")
GATEWAY_SLUG = os.environ.get("GATEWAY_SLUG", "demo")
CONSUMER_API_KEY = os.environ.get("CONSUMER_API_KEY")

if not CONSUMER_API_KEY:
    raise ValueError(
        "CONSUMER_API_KEY environment variable is required.\n"
        "Run examples/curl-first-request/first-request.sh to create one."
    )

client = OpenAI(
    base_url=f"{PROXY_URL}/{CONSUMER_SLUG}",
    api_key="unused",
    default_headers={
        "X-AG-Gateway-Slug": GATEWAY_SLUG,
        "X-AG-API-Key": CONSUMER_API_KEY,
    },
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is TrustGate in one sentence?"},
    ],
)

print(response.choices[0].message.content)
