---
linear: RUN-252
type: feat
changelog: "Add OpenRouter as a first-class LLM provider with groq-style client, extension adapter, and smoke tests."
---

# Proposal: OpenRouter LLM provider (RUN-252)

## Intent

TrustGate must route LLM traffic to OpenRouter as a first-class provider. Routing intent (`@openrouter/vendor/model`) and body rewrite already exist in `pkg/domain/routing/intent.go`, but registry CRUD, catalog listing, connection probe, and proxy upstream calls fail because `openrouter` is not registered — no client, factory entry, format adapter, or catalog seed.

## Scope

### In Scope
- **RUN-922 (core):** `ProviderOpenRouter`; `pkg/infra/providers/openrouter/` client + connection probe; factory locator; `FormatOpenRouter` in `format.go`; catalog seed row + API-key auth; sync/stream to `https://openrouter.ai/api/v1/chat/completions`
- **RUN-261 (adapter):** `OpenRouterAdapter` preserving request fields (`provider`, `models`, `transforms`, `route`) and response metadata; SSE comment-line filtering; registry passthrough for openrouter↔openai
- **RUN-924 (tests):** httptest client/connection tests; adapter round-trip; functional smoke for `@openrouter/vendor/model`

### Out of Scope
- models.dev catalog sync (seed provider only; prior OpenRouter catalog purged)
- OpenRouter catalog API; optional `HTTP-Referer` / `X-Title` headers
- `openai_compatible` base-URL alias (no registry provider match, no extensions)

## Capabilities

### New Capabilities
- `openrouter-llm-provider`: first-class OpenRouter integration — registry validation, proxy sync/stream, extension preservation, qualified routing intent

### Modified Capabilities
- None (routing intent already implemented; no existing provider spec in `openspec/specs/`)

## Approach

**Approach A** — dedicated `openrouter` package + `FormatOpenRouter`, mirroring **groq**: thin wrapper over `openai.ChatCompletionsClient` with fixed endpoint; `RunBearerGETProbe` on `GET /api/v1/models`; dedicated adapter wrapping `OpenAIAdapter` (Mistral/groq pattern) for OpenRouter-specific fields and `ProviderExtensions` / request extension maps.

**Delivery:** three chained PRs aligned to Linear sub-issues, ~400-line budget each: **RUN-922 → RUN-261 → RUN-924**.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/providers/openrouter/` | New | Client, connection, tests |
| `pkg/infra/providers/client.go` | Modified | Constant, `SupportedProviders`, `IsValidProvider` |
| `pkg/infra/providers/factory/locator.go` | Modified | Wire `NewOpenRouterClient()` |
| `pkg/infra/providers/adapter/` | Modified/New | `FormatOpenRouter`, `OpenRouterAdapter`, registry |
| `pkg/app/catalog/sync.go` | Modified | Seed row; no `modelsDevProviderToCode` entry |
| `pkg/app/catalog/provider_auth.go` | Modified | API key auth catalog entry |
| `tests/functional/` | New | Routing smoke with fake upstream |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| OpenRouter extensions differ from groq `x_groq` | Med | Flexible extension maps on canonical model |
| SSE `: ping` lines break stream JSON decode | Med | Filter comment lines before `DecodeStreamChunk` (RUN-261) |
| Allowlisted consumers reject free-form `vendor/model` | Med | Document nil-allowlist behavior; no models.dev rows |
| Single PR exceeds 400-line budget | High | Three chained PRs per sub-issue |

## Rollback Plan

Additive change. Revert by removing the `openrouter` package, factory locator entry, adapter registration, `FormatOpenRouter`, catalog seed, and provider constant. No migrations or schema changes. Existing providers unaffected.

## Dependencies

- OpenRouter Chat Completions API (OpenAI-compatible wire format)
- Existing `openai.ChatCompletionsClient` and HTTP client pool

## Success Criteria

- [ ] Registry CRUD and connection probe accept `provider=openrouter`
- [ ] `@openrouter/vendor/model` proxies sync + stream to OpenRouter
- [ ] OpenRouter request/response extensions round-trip same-wire; stripped cross-format
- [ ] SSE keep-alive comments do not break streaming
- [ ] Catalog lists OpenRouter with API key auth; no models.dev sync rows
- [ ] `-race`-clean unit and functional tests per RUN-922 / RUN-261 / RUN-924
