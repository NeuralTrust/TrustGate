---
linear: RUN-946
type: fix
changelog: "Inject default tools[].function.parameters on OpenAI-wire requests when Gemini cross-format adaptation omits them."
---

# Proposal: Default tool parameters for strict OpenAI upstreams

## Why

Gemini agent requests adapted to OpenAI wire format can omit `tools[].function.parameters`.
Strict upstreams (Cerebras gpt-oss chat template) reject those tools with HTTP 400.

## What

- Extend `NormalizeOpenAIRequest` to inject `{"type":"object","properties":{}}` when parameters are missing, null, or `{}`.
- Unit tests for missing parameters and Cerebras provider normalization path.

## QA

- `ag-matrix -u cerebras -a google` passes
- `go test ./pkg/infra/providers/adapter/...`
