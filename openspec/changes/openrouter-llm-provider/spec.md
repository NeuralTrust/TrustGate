# OpenRouter LLM Provider Specification

**Linear:** RUN-252 · RUN-922 · RUN-261 · RUN-924 · **Change:** `openrouter-llm-provider`

## Purpose

Add OpenRouter as a first-class OpenAI-wire-compatible LLM provider. Catalog seeds the provider only (no models.dev import). `@openrouter/vendor/model` routing intent already exists and MUST remain unchanged.

## ADDED Requirements

### Requirement: Provider registration

TrustGate MUST register `openrouter` in `SupportedProviders`, `IsValidProvider`, the factory locator, `FormatOpenRouter`, and catalog auth (`api_key`). Completions MUST use `https://openrouter.ai/api/v1/chat/completions`. Connection test MUST probe `GET https://openrouter.ai/api/v1/models` with Bearer auth.

#### Scenario: Registry and locator accept openrouter

- GIVEN `provider: openrouter` with valid API key
- WHEN an operator creates a registry target or runs test-connection
- THEN validation succeeds, the locator returns an OpenRouter client, and the models probe succeeds

### Requirement: Sync and stream completions

The client MUST proxy sync and stream chat completions with `vendor/model` slugs (e.g. `anthropic/claude-sonnet-4`) unchanged, using `Bearer {api_key}`. Missing credentials MUST fail before upstream call.

#### Scenario: Sync and stream with vendor/model slug

- GIVEN an openrouter target and model `anthropic/claude-sonnet-4`
- WHEN sync or streaming completion is proxied
- THEN the upstream body retains the model slug and responses complete (sync body or SSE chunks)

### Requirement: Catalog provider seed without models.dev models

Catalog sync MUST seed an `openrouter` provider row (wire format `openai`). OpenRouter MUST NOT appear in `modelsDevProviderToCode`; no OpenRouter model rows MAY be imported from models.dev.

#### Scenario: Provider seeded, models not imported

- GIVEN catalog sync runs
- WHEN providers seed and models.dev import complete
- THEN an `openrouter` provider with `api_key` auth exists and zero catalog models reference `openrouter`

### Requirement: Routing intent compatibility (unchanged)

`ParseModelRef` / `applyIntentToBody` for `@openrouter/...` MUST NOT change. Nested slashes MUST be preserved. This change only enables `IsValidProvider("openrouter")` for registry CRUD and candidate resolution.

#### Scenario: Intent parses and rewrites model

- GIVEN ref `@openrouter/meta-llama/llama-3-70b` or `@openrouter/anthropic/claude-sonnet-4`
- WHEN intent is parsed and applied to an openrouter request
- THEN provider is `openrouter`, nested slug is preserved, and body `model` is the vendor/model suffix

### Requirement: Extension field preservation

`FormatOpenRouter` MUST register in the adapter registry. Same-format round-trips MUST preserve request fields `provider`, `models`, `transforms`, `route` and response metadata via `ProviderExtensions`. Cross-format adaptation MUST strip OpenRouter-only extensions.

#### Scenario: Same-format extension round-trip

- GIVEN openrouter sync or stream payloads with routing extensions and response metadata
- WHEN encode → decode → encode on the same format
- THEN all extension fields and metadata survive

#### Scenario: Cross-format strips extensions

- GIVEN an openrouter request with `provider`, `models`, `transforms`, `route`
- WHEN adapted to a non-openrouter format (e.g. anthropic)
- THEN those fields are absent from encoded output

### Requirement: SSE keep-alive comment filtering

Stream handling MUST ignore SSE comment lines (`: ping`, `: OPENROUTER PROCESSING`) before JSON decode; `data:` lines MUST still parse.

#### Scenario: Comment lines do not break stream decode

- GIVEN an SSE stream with `: ping` or `: OPENROUTER PROCESSING` between `data:` events
- WHEN chunks are decoded
- THEN comments are skipped and subsequent JSON chunks parse without error

## Out of scope

models.dev OpenRouter models; OpenRouter catalog API; attribution headers; App v2 UI; changes to `intent.go`.
