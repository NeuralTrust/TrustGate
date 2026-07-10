## Exploration: OpenRouter LLM provider (RUN-252)

### Current State

TrustGate routes LLM traffic through provider packages under `pkg/infra/providers/`, a factory locator, and format adapters. OpenAI-compatible providers (**groq**, **deepseek**) are the closest siblings: thin wrappers over `openai.ChatCompletionsClient` with a fixed endpoint, `RunBearerGETProbe` connection test, and a dedicated `Format*` in `adapter/format.go` registered in `adapter/registry.go`.

**OpenRouter does not exist yet** — no `pkg/infra/providers/openrouter/`, no `ProviderOpenRouter` constant, no catalog seed row.

**Routing intent for `@openrouter` is already implemented** in `pkg/domain/routing/intent.go`:
- `@openrouter/anthropic/claude-sonnet-4` → `{Provider: "openrouter", Model: "anthropic/claude-sonnet-4"}`
- Nested slashes preserved (test at `intent_test.go:36`)
- `applyIntentToBody` in `pkg/app/proxy/routing.go` rewrites qualified intents to native `vendor/model` before upstream call
- `CandidateSet.resolveQualified` filters by registry provider + allowlist

**Catalog policy:** models sync from **models.dev only** (`pkg/app/catalog/sync.go`). A prior OpenRouter catalog was purged (`migrations/20260617000000_purge_openrouter_catalog.go`). OpenRouter gets a **provider seed row only** — no `modelsDevProviderToCode` entry.

**Extension pattern (groq):** `x_groq` preserved via typed fields + `ProviderExtensions` in `openai_completions_adapter.go`; `ShouldPassthroughSameWireFormat` forces openai↔groq through adapter; cross-format strips extensions in `registry.go`.

### Affected Areas

#### RUN-922 — Core integration

| File | Why |
|------|-----|
| `pkg/infra/providers/client.go` | Add `ProviderOpenRouter`, `SupportedProviders()`, `IsValidProvider()` |
| `pkg/infra/providers/openrouter/client.go` | **New** — groq pattern: `ChatCompletionsClient` → `https://openrouter.ai/api/v1/chat/completions` |
| `pkg/infra/providers/openrouter/connection.go` | **New** — `GET https://openrouter.ai/api/v1/models` probe |
| `pkg/infra/providers/factory/locator.go` | Wire `openrouter.NewOpenRouterClient()` |
| `pkg/infra/providers/factory/locator_test.go` | Assert openrouter in locator map |
| `pkg/infra/providers/adapter/format.go` | `FormatOpenRouter`, `ResolveAgentFormat`, `SupportedSourceFormat`, `normalizeFormat` |
| `pkg/app/catalog/sync.go` | Add to `seedProviders` (wire_format `openai`); **do not** add to `modelsDevProviderToCode` |
| `pkg/app/catalog/provider_auth.go` | `providerAuthCatalog[ProviderOpenRouter] = {apiKeyAuthOption}` |
| `pkg/app/catalog/sync_test.go` | Update expected seed count |
| `pkg/domain/registry/llm_target.go` | Auto-validates via `IsValidProvider` (no direct edit if constant added) |

**Not needed for RUN-922:** changes to `pkg/domain/routing/intent.go` (already supports `@openrouter/vendor/model`).

#### RUN-261 — Adapter extensions

| File | Why |
|------|-----|
| `pkg/infra/providers/adapter/openrouter_adapter.go` | **New** — wrap `OpenAIAdapter`; preserve OpenRouter request fields (`provider`, `models`, `transforms`, `route`) and response metadata |
| `pkg/infra/providers/adapter/openrouter_adapter_test.go` | **New** — round-trip + cross-format strip (mirror `groq_adapter_test.go`) |
| `pkg/infra/providers/adapter/registry.go` | `Register(FormatOpenRouter, &OpenRouterAdapter{})`; extend `ShouldPassthroughSameWireFormat` for openrouter↔openai |
| `pkg/infra/providers/adapter/openai_completions_adapter.go` | Likely extend decode/encode for OpenRouter extension fields OR handle in dedicated adapter |
| `pkg/infra/providers/adapter/canonical.go` | Possibly `RequestExtensions map[string]json.RawMessage` on `CanonicalRequest` if passthrough cannot use typed fields |
| `pkg/infra/providers/stream.go` or adapter | Filter SSE comment lines (`: ping`, `: OPENROUTER PROCESSING`) before JSON decode |

#### RUN-924 — Functional smoke tests

| File | Why |
|------|-----|
| `pkg/infra/providers/openrouter/client_test.go` | httptest sync+stream (copy `groq/client_test.go` + `groqClientAt` pattern) |
| `pkg/infra/providers/openrouter/connection_test.go` | httptest `TestConnection` |
| `pkg/infra/providers/adapter/openrouter_adapter_test.go` | Extension round-trip, cross-format strip |
| `tests/functional/routing_intent_test.go` or new `openrouter_*_test.go` | E2E `@openrouter/vendor/model` with fake upstream |

#### Cross-cutting (verify after each slice)

| File | Why |
|------|-----|
| `pkg/infra/providers/validate.go` | No options validation needed (like groq/mistral) unless optional headers added later |
| `pkg/api/handler/http/catalog/response/catalog_response.go` | Picks up auth via `ProviderAuthOptions` automatically |

### Approaches

| Approach | Pros | Cons | Effort |
|----------|------|------|--------|
| **A. Dedicated `openrouter` package + `FormatOpenRouter` adapter (groq model)** | First-class provider; extension preservation; matches epic + sub-issue split; catalog seed without models.dev pollution | More files than alias | **Medium** |
| **B. Reuse `openai_compatible` with `base_url: https://openrouter.ai/api/v1`** | Zero new client code | No `provider:openrouter` in catalog/API; no extension adapter; routing intent `@openrouter/...` won't match registry provider; fails acceptance | Low |
| **C. Extend `openai` client with OpenRouter endpoint flag** | Single client | Conflates providers; breaks locator/factory pattern; poor telemetry separation | Medium–High |

### Recommendation

**Approach A** — mirror **groq** for the HTTP client (`ChatCompletionsClient` + fixed URL) and **groq adapter tests** for extension round-trip / cross-format stripping. Use a dedicated `OpenRouterAdapter` (like `MistralAdapter` wraps `OpenAIAdapter`) for OpenRouter-specific request/response fields and SSE keep-alive filtering.

**Implementation order:**
1. **RUN-922** — unblocks registry creation, catalog listing, connection probe, basic sync/stream to OpenRouter
2. **RUN-261** — required for extension field preservation and SSE keep-alive (acceptance criteria)
3. **RUN-924** — httptest + functional smoke; can start unit tests in parallel with 261

**PR strategy:** Three chained PRs aligned to RUN-922 → RUN-261 → RUN-924 (~400-line budget each). Total forecast **Medium–High** risk of exceeding single-PR budget.

### Open Questions

| Question | Resolution from code |
|----------|---------------------|
| Is `@openrouter/vendor/model` routing implemented? | **Yes** — `ParseModelRef` + `applyIntentToBody`; only missing `IsValidProvider("openrouter")` for registry CRUD |
| Catalog models for OpenRouter? | **No** — seed provider only; no `modelsDevProviderToCode`; migration already purged old `source='openrouter'` rows |
| Free-form `vendor/model` strings (app v2)? | Works when consumer has **no allowlist** (`Candidate.Allowed == nil` → `AllowsModel` returns true); qualified intent passes full slug via `OverrideModel` |
| OpenRouter optional headers (`HTTP-Referer`, `X-Title`)? | **Not in codebase** — defer unless epic requires; could add via `ChatCompletionsClient` `customHeaders` later |
| SSE `: ping` keep-alives? | **Not filtered today** — `StreamSSE` yields all lines; implement skip in `OpenRouterAdapter.DecodeStreamChunk` or proxy stream handler |
| Request fields `provider`/`models`/`transforms`/`route`? | **Not in codebase** — RUN-261 must add (groq's `x_groq` / `ProviderExtensions` is the response-side pattern) |
| Closest sibling? | **groq** (client) + **groq_adapter_test** (extensions); mistral only if tool-call ID normalization needed (unlikely for OpenRouter) |

### Risks

- OpenRouter response extensions may differ from groq's `x_groq` — adapter design must use flexible `ProviderExtensions` / `RequestExtensions` maps
- SSE comment lines may break stream JSON parsing if not filtered before `DecodeStreamChunk`
- Allowlisted consumers will reject unknown `vendor/model` slugs unless UI uses free-form (nil allowlist) or catalog picks models.dev slugs only
- No openspec change folder existed before this explore artifact — proposal/spec phases should create full SDD tree

### Ready for Proposal

**Yes** — recommend `sdd-propose` with Approach A, three PR slices (RUN-922 / RUN-261 / RUN-924), and explicit out-of-scope: models.dev sync, OpenRouter catalog API, optional attribution headers (unless product requires in v1).
