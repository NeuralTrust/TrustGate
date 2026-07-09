# Design: OpenRouter LLM provider (RUN-252)

## Technical Approach

Add a first-class `openrouter` provider by mirroring the **groq** infra pattern: thin `pkg/infra/providers/openrouter/` client over `openai.ChatCompletionsClient`, factory locator wiring, `FormatOpenRouter` in the adapter layer, and catalog **seed-only** registration (no models.dev import). `@openrouter/vendor/model` routing already exists in `pkg/domain/routing/intent.go` and `pkg/app/proxy/routing.go`; this change completes registry CRUD, connection probe, proxy forwarding, and extension-aware adaptation.

Hexagonal binding: **infra** owns HTTP client + format adapters; **app/catalog** owns provider seed + auth catalog; **domain** gains no new types (validates via `IsValidProvider`); wiring stays in `pkg/infra/providers/factory/locator.go`.

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Client shape | Dedicated `openrouter` package (groq clone) | `openai_compatible` + `base_url` | Registry needs `provider: "openrouter"`; intent `@openrouter/...` must match; separate telemetry pool |
| Adapter shape | `OpenRouterAdapter` wraps `OpenAIAdapter` (Mistral pattern) | Register bare `OpenAIAdapter` like groq | OpenRouter has request fields (`provider`, `models`, `transforms`, `route`), response metadata, and SSE comment keep-alives groq does not |
| Request extensions | `RequestExtensions map[string]json.RawMessage` on `CanonicalRequest` | Typed fields only in `openaiRequest` | Four optional keys; map matches existing `ProviderExtensions` response pattern |
| Wire passthrough | `normalizeFormat` → `openai`; `ShouldPassthroughSameWireFormat` forces adapter for openrouter↔openai | Always passthrough | Same lesson as groq/`x_groq`: wire-similar ≠ byte-identical |
| Catalog models | Seed row only (`wire_format: openai`) | models.dev mapping | Prior OpenRouter catalog purged; free-form `vendor/model` slugs are runtime-only |
| Optional headers | Defer `HTTP-Referer` / `X-Title` | v1 attribution headers | Not in codebase; `ChatCompletionsClient` custom headers can follow later |
| Delivery | Three chained PRs: core → adapter → tests | Single PR | ~400-line review budget; slices align RUN-922 / RUN-261 / RUN-924 |

## Data Flow

### Sync completion

```
Client ──► Proxy forwarder ──► ResolveAgentFormat("openrouter") → FormatOpenRouter
                │                        │
                │              Registry.AdaptRequest(source → openrouter)
                ▼                        ▼
         applyIntentToBody          OpenRouterAdapter.EncodeRequest
         (model = vendor/slug)              │
                │                           ▼
                └──────────► factory.Get("openrouter") ──► openrouter.client
                                              │
                                              ▼
                              POST https://openrouter.ai/api/v1/chat/completions
                                              │
                ◄─────────────────────────────┘
         Registry.AdaptResponse(openrouter → source) ──► Client
```

### Connection probe

```
Admin API ──► GetTester("openrouter") ──► RunBearerGETProbe
                              GET https://openrouter.ai/api/v1/models
```

### Streaming (adapter slice)

```
openrouter SSE line ──► OpenRouterAdapter.DecodeStreamChunk
         │                      │ skip lines starting with ":" (ping / processing)
         │                      ▼
         └────► OpenAIAdapter decode/encode ──► Registry.AdaptStreamChunk → client
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `pkg/infra/providers/openrouter/client.go` | Create | `NewOpenRouterClient()`; `ChatCompletionsClient` → `https://openrouter.ai/api/v1/chat/completions` |
| `pkg/infra/providers/openrouter/connection.go` | Create | `TestConnection` via `GET …/api/v1/models` + `RunBearerGETProbe` |
| `pkg/infra/providers/openrouter/client_test.go` | Create | httptest sync/stream (copy `groq/client_test.go` + `openRouterClientAt`) |
| `pkg/infra/providers/openrouter/connection_test.go` | Create | httptest probe success/failure |
| `pkg/infra/providers/client.go` | Modify | `ProviderOpenRouter`; extend `SupportedProviders` / `IsValidProvider` |
| `pkg/infra/providers/factory/locator.go` | Modify | Map `ProviderOpenRouter` → `openrouter.NewOpenRouterClient()` |
| `pkg/infra/providers/factory/locator_test.go` | Modify | Assert openrouter in locator table |
| `pkg/infra/providers/adapter/format.go` | Modify | `FormatOpenRouter`; `resolveProviderWireFormat`, `ResolveAgentFormat`, `SupportedSourceFormat`, `normalizeFormat` |
| `pkg/infra/providers/adapter/openrouter_adapter.go` | Create | Wrap `OpenAIAdapter`; peel/merge request + response extensions; filter SSE comments |
| `pkg/infra/providers/adapter/openrouter_adapter_test.go` | Create | Round-trip extensions; cross-format strip (mirror `groq_adapter_test.go`) |
| `pkg/infra/providers/adapter/registry.go` | Modify | `Register(FormatOpenRouter, &OpenRouterAdapter{})`; extend `ShouldPassthroughSameWireFormat` |
| `pkg/infra/providers/adapter/canonical.go` | Modify | Add `RequestExtensions` on `CanonicalRequest` |
| `pkg/app/catalog/sync.go` | Modify | Seed `{ProviderOpenRouter, "OpenRouter", "openai"}`; **no** `modelsDevProviderToCode` entry |
| `pkg/app/catalog/provider_auth.go` | Modify | `providerAuthCatalog[ProviderOpenRouter] = {apiKeyAuthOption}` |
| `pkg/app/catalog/sync_test.go` | Modify | Seed count follows `len(seedProviders)` automatically |

**Out of scope:** `pkg/domain/routing/intent.go`, models.dev sync, OpenRouter catalog API, attribution headers.

## Interfaces / Contracts

```go
// pkg/infra/providers/client.go
const ProviderOpenRouter = "openrouter"

// pkg/infra/providers/adapter/format.go
const FormatOpenRouter Format = "openrouter"

// pkg/infra/providers/adapter/canonical.go
type CanonicalRequest struct {
    // ...existing fields...
    RequestExtensions map[string]json.RawMessage `json:"request_extensions,omitempty"`
}
```

OpenRouter request extension keys (preserve on openrouter round-trip, strip on cross-format): `provider`, `models`, `transforms`, `route`. Response keys land in `ProviderExtensions` (e.g. OpenRouter usage/provider metadata).

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | Client, probe, adapter | httptest; table-driven; `-race` |
| Adapter | Extension round-trip + cross-format strip | Copy `groq_adapter_test.go` patterns |
| Functional | `@openrouter/vendor/model` routing | Fake upstream; existing intent tests + new smoke |

## Migration / Rollout

No migration required. Catalog sync adds one provider row on next sync. Existing purged `source='openrouter'` model rows stay absent.

## Open Questions

- [ ] Exact OpenRouter response extension keys to preserve beyond usage (confirm against live API during RUN-261)
- [ ] Whether SSE comment filtering belongs only in `OpenRouterAdapter.DecodeStreamChunk` or also in shared stream reader (default: adapter-only)
