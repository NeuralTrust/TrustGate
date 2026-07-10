---
linear: RUN-259
type: feat
changelog: "Add Cerebras as an OpenAI-compatible LLM provider with catalog sync and connection probe."
---

# Proposal: Cerebras LLM provider (RUN-251 / RUN-259)

## Why

Cerebras Inference exposes an OpenAI-compatible Chat Completions API. TrustGate needs
first-class routing, catalog seeding from models.dev, and connection testing so registries
can target Cerebras like Groq or DeepSeek.

## What

- `provider: cerebras` client at `https://api.cerebras.ai/v1`
- GET `/v1/models` connection probe
- Catalog seed + models.dev mapping (`cerebras` key)
- FormatOpenAI wire passthrough (no dedicated adapter format)
- httptest smoke tests for sync, stream, and rate-limit handling

## Out of scope

- App v2 registry UI (RUN-920, separate PR)
- multi-agent matrix tests (RUN-260 canceled)
