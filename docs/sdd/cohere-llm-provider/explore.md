## Exploration: Cohere LLM provider (RUN-925)

### Current State

TrustGate routes LLM traffic through a single catch-all proxy (`pkg/server/router/proxy_router.go` → `ForwardedHandler.Handle`). Supported **fixed chat routes** are resolved in `pkg/api/resolver/proxy_path_resolver.go`:

| Gateway path | Source format | Upstream pattern |
|---|---|---|
| `/{slug}/v1/chat/completions` | `openai` | Provider-specific chat URL |
| `/{slug}/v1/messages` | `anthropic` | Anthropic Messages API |
| `/{slug}/v1/responses` | `openai_responses` | OpenAI Responses API |
| `/{slug}/v1beta/models/{model}:generateContent` | `google` | Gemini |

**`/v1/embeddings` is not a supported proxy route** — functional test `TestProxyPaths_FixedRoutes` asserts it returns **404** (`tests/functional/payload_normalization_test.go`). **Rerank does not exist** anywhere in the codebase (no routes, adapters, or clients).

Provider wiring follows a consistent hexagonal pattern:

1. **Constants & validation** — `pkg/infra/providers/client.go` (`ProviderX`, `SupportedProviders`, `IsValidProvider`); registry validation in `pkg/domain/registry/llm_target.go`.
2. **HTTP client** — `pkg/infra/providers/{provider}/client.go` implementing `providers.Client` (`Completions`, `CompletionsStream`).
3. **Connection test** — `pkg/infra/providers/{provider}/connection.go` implementing `providers.ConnectionTester` via `RunBearerGETProbe` / `RunAPIKeyGETProbe`.
4. **Factory** — `pkg/infra/providers/factory/locator.go` maps provider name → client singleton.
5. **Format adapter** — `pkg/infra/providers/adapter/{provider}_adapter.go` registered in `adapter/registry.go`.
6. **Format resolution** — `adapter/format.go` (`ResolveTargetFormat`, `ResolveAgentFormat`, `SupportedSourceFormat`).
7. **Invocation** — `pkg/app/proxy/provider.go` (`providerInvoker.prepare`) adapts request/response/stream via canonical model.
8. **Catalog seed** — `pkg/app/catalog/sync.go` (`seedProviders`, `modelsDevProviderToCode`).
9. **DI** — `pkg/container/modules/providers.go`, `proxy.go`.

**Reference implementations for Cohere:**

| Pattern | Provider | Notes |
|---|---|---|
| Native non-OpenAI API | **Anthropic** | Raw POST to fixed URL; `AnthropicAdapter` (~800 LOC + tests); client mirrors mistral HTTP pool pattern |
| OpenAI-wire reuse | **Groq** | Delegates to `openai.ChatCompletionsClient`; `OpenAIAdapter` registered as `FormatGroq` |
| OpenAI-wire + tweaks | **Mistral** | Own HTTP client + `MistralAdapter` wrapping `OpenAIAdapter` |
| Embeddings (internal only) | **OpenAI** | `pkg/infra/embedding/openai/creator.go` — used by semantic-cache plugin, **not** exposed as gateway proxy |

There is **no Cohere code** in the worktree today. `normalize.go` mentions Cohere only in a comment about OpenAI SDK compatibility.

### Affected Areas

#### Chat (sync + stream) — required

| File / area | Why |
|---|---|
| `pkg/infra/providers/client.go` | Add `ProviderCohere = "cohere"` to constants, `SupportedProviders`, `IsValidProvider` |
| `pkg/infra/providers/cohere/client.go` | **New** — POST `https://api.cohere.com/v2/chat`; Bearer auth; sync + SSE stream via `providers.StreamResponse` |
| `pkg/infra/providers/cohere/connection.go` | **New** — probe (likely GET models or minimal POST); `RunBearerGETProbe` pattern like groq/mistral |
| `pkg/infra/providers/cohere/client_test.go` | **New** — httptest round-trips (follow `groq/client_test.go`, `anthropic/client_test.go`) |
| `pkg/infra/providers/cohere/connection_test.go` | **New** — probe classification tests |
| `pkg/infra/providers/factory/locator.go` | Register `cohere.NewCohereClient()` |
| `pkg/infra/providers/factory/locator_test.go` | Add `ProviderCohere` case |
| `pkg/infra/providers/adapter/format.go` | Add `FormatCohere`; extend `ResolveTargetFormat`, `ResolveAgentFormat`, `SupportedSourceFormat` |
| `pkg/infra/providers/adapter/cohere_adapter.go` | **New** — native v2 chat ↔ canonical (messages, tools, stream events) |
| `pkg/infra/providers/adapter/cohere_adapter_test.go` | **New** — roundtrip + cross-format tests (pattern: `anthropic_adapter_test.go`) |
| `pkg/infra/providers/adapter/registry.go` | `r.Register(FormatCohere, &CohereAdapter{})` |
| `pkg/app/proxy/provider.go` | Add `FormatCohere` to `injectStreamTrue` list in `InvokeStream` if Cohere uses `stream` boolean |
| `pkg/api/resolver/proxy_path_resolver.go` | Add fixed route for Cohere native client (proposed: `RouteChatV2 = "/v2/chat"` → `FormatCohere`) |
| `pkg/api/resolver/proxy_path_resolver_test.go` | Route + unknown-route cases |
| `pkg/app/catalog/sync.go` | Seed provider + optional `modelsDevProviderToCode` entry |
| `pkg/domain/registry/llm_target.go` | Automatic via `IsValidProvider` once constant added |
| `pkg/container/modules/providers.go` | No change if locator handles registration |

#### Embeddings proxy — new capability (not just provider client)

| File / area | Why |
|---|---|
| `pkg/api/resolver/proxy_path_resolver.go` | Add `RouteEmbeddings = "/v1/embeddings"` with source format (likely `openai_embeddings` or reuse `openai`) |
| `pkg/app/proxy/` | **New or extended forwarder** — current `providers.Client` only supports chat completions; embeddings need `Embed(ctx, cfg, body)` or a dedicated `EmbeddingInvoker` |
| `pkg/infra/providers/cohere/embed.go` (or `client_embed.go`) | POST `https://api.cohere.com/v2/embed` |
| `pkg/infra/providers/adapter/cohere_embed_adapter.go` | OpenAI `/v1/embeddings` ↔ Cohere v2 embed schema |
| `pkg/infra/embedding/cohere/creator.go` | Optional — for semantic-cache internal use mirroring openai embedding package |
| `pkg/container/modules/loadbalancer.go` | Register cohere embedding creator if semantic-cache should use Cohere backends |
| `tests/functional/` | **New** embed proxy e2e (currently only 404 test exists) |

#### Rerank proxy — greenfield

| File / area | Why |
|---|---|
| `pkg/api/resolver/proxy_path_resolver.go` | Add `RouteRerank = "/v1/rerank"` (or `/v2/rerank`) — **no prior art** |
| `pkg/infra/providers/cohere/rerank.go` | POST `https://api.cohere.com/v2/rerank` |
| `pkg/infra/providers/adapter/cohere_rerank_adapter.go` | Gateway request/response shape TBD |
| `pkg/app/proxy/` | Same capability-gap as embeddings — needs non-chat forward path |
| `tests/functional/` | **New** rerank e2e |

#### Catalog / admin / docs

| File / area | Why |
|---|---|
| `pkg/app/catalog/sync.go` | Manual seed for Cohere models + capabilities (`chat`, `embed`, `rerank`) when models.dev lacks Cohere |
| `pkg/infra/database/migrations/` | Possible migration to upsert Cohere catalog rows if not relying solely on sync |
| `docs/docs.go` / swagger | New proxy routes if OpenAPI is regenerated |
| `postman/TrustGate.postman_collection.json` | Example requests (optional) |

#### Out of scope (TrustGate worktree) but epic-linked

- **App v2 registry** — separate repo (`app`); TrustGate exposes `/v1/providers-catalog` consumed by App v2

### Provider Wiring Comparison (existing)

```
Client request → ResolveProxyPath (source format)
              → Forwarder (routing, plugins, model policy)
              → ProviderInvoker.prepare
                   ├─ locator.Get(provider)
                   ├─ AdaptRequest(source → target)  [if cross-format]
                   ├─ NormalizeRequestForProvider
                   └─ EnforceModel
              → client.Completions / CompletionsStream
              → AdaptResponse / AdaptStreamChunk (if cross-format)
```

- **Groq**: OpenAI wire end-to-end; `FormatGroq` uses `OpenAIAdapter` with Groq-specific normalization.
- **Mistral**: OpenAI wire; custom HTTP client + `MistralAdapter` ID/tool fixes.
- **Anthropic**: Native `/v1/messages` wire; dedicated client + large `AnthropicAdapter`; cross-format from `/v1/chat/completions` supported.

**Cohere (ticket constraint: native v2, not OpenAI-compatible)** aligns with **Anthropic**, not Groq.

### Approaches

#### 1. Full native stack (Anthropic-style) — **recommended**

Add `cohere` provider package + `CohereAdapter` + `/v2/chat` gateway route. Cross-format adaptation allows OpenAI clients on `/v1/chat/completions` to reach Cohere backends.

- **Pros**: Matches RUN-925 "native Chat API v2"; reuses proven adapter/invoker pipeline; supports `@cohere/model` routing intent; sync + stream in one flow.
- **Cons**: Largest adapter surface (Cohere v2 message/tool/stream semantics); ~800–1200 LOC for adapter + tests alone.
- **Effort**: High

#### 2. OpenAI-compatible shim (reject per ticket)

Point Cohere at an OpenAI-compat endpoint or treat as `openai_compatible`.

- **Pros**: Minimal code (groq-like).
- **Cons**: **Violates ticket** — Cohere v2 chat is not OpenAI-compatible; wrong tool/message/stream mapping.
- **Effort**: Low (but invalid)

#### 3. Embeddings/rerank as opaque pass-through proxy

Add routes that inject Bearer token and forward body to Cohere with **no** canonical adaptation (provider registry must be `cohere`).

- **Pros**: Fast to ship; smaller diff.
- **Cons**: Clients must speak Cohere-native JSON on gateway paths; breaks OpenAI SDK expectations for `/v1/embeddings`.
- **Effort**: Medium

#### 4. Embeddings/rerank with format adapters (recommended for acceptance criteria)

Extend proxy with capability-aware invoker: OpenAI-shaped `/v1/embeddings` ↔ Cohere `/v2/embed`; gateway `/v1/rerank` ↔ Cohere `/v2/rerank`.

- **Pros**: Matches "proxied through gateway" with usable client ergonomics; consistent with chat adaptation philosophy.
- **Cons**: Requires new abstractions beyond `providers.Client`; touches resolver, forwarder, invoker; no existing rerank pattern.
- **Effort**: High

#### 5. Chained PRs (delivery strategy)

Split given 400-line review budget:

| PR | Scope | Est. lines |
|---|---|---|
| PR-1 | Chat: provider client, adapter, locator, `/v2/chat`, connection test, unit tests | ~600–900 |
| PR-2 | Embeddings: route, embed client, adapter, functional test | ~350–500 |
| PR-3 | Rerank: route, client, adapter, catalog seed, functional test | ~300–450 |

- **Pros**: Reviewable slices; incremental merge risk.
- **Cons**: Integration testing spans PRs; catalog incomplete until PR-3.
- **Effort**: Medium (coordination)

### Recommendation

**Approach 1 + 4 + 5**: Implement Cohere as a first-class native provider (Anthropic pattern) for chat, add format adapters for embeddings and rerank proxy routes, and ship as **3 chained PRs**.

**Chat implementation sketch:**

1. `pkg/infra/providers/cohere/` — `client.go` (v2/chat), `connection.go` (Bearer probe to `GET https://api.cohere.com/v1/models` or v2-compatible endpoint — **verify at design time**).
2. `CohereAdapter` — map Cohere v2 `messages`/`tools`/`stream` events ↔ `CanonicalRequest`/`CanonicalResponse`/`CanonicalStreamChunk`.
3. Register `FormatCohere`; add proxy route `/v2/chat`.
4. Wire `ResolveAgentFormat("cohere", …) → FormatCohere`.
5. Allow cross-format: OpenAI `/v1/chat/completions` → Cohere backend (primary consumer path).

**Embeddings/rerank:**

1. Introduce `Capability` dimension on proxy routes (chat | embed | rerank) or separate handlers sharing auth/routing.
2. Add `/v1/embeddings` and `/v1/rerank` to `proxy_path_resolver.go`.
3. Implement Cohere embed/rerank HTTP calls + adapters (OpenAI embed shape in; Cohere native out).
4. Catalog: seed Cohere provider (`wire_format: cohere`) and models with `capabilities: {chat, embed, rerank}` — manual seed in `sync.go` if models.dev has no `cohere` key.

### Connection Testing

Follow existing pattern:

```go
// groq/connection.go — Bearer GET /models
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
    return providers.RunBearerGETProbe(ctx, providers.ProviderCohere, modelsURL, config.Credentials.ApiKey)
}
```

Admin path: `TestRegistryConnection` handler → `locator.GetTester(provider)` (`pkg/server/router/admin_router.go`). Cohere client must implement `ConnectionTester` on the same struct as `Client` (embedded pattern used by groq, anthropic, mistral).

### Test Patterns

| Layer | Pattern | Reference files |
|---|---|---|
| Unit — client | httptest server, assert headers/body/status | `groq/client_test.go`, `mistral/client_test.go` |
| Unit — connection | Mock HTTP status → `ProbeResult` stage | `openai/connection_test.go`, `connection_tester_test.go` |
| Unit — adapter | JSON fixtures, canonical roundtrip, cross-format | `anthropic_adapter_test.go`, `mistral_adapter_test.go` |
| Unit — invoker | Mock locator, assert adapt + enforce model | `provider_invoker_test.go` |
| Unit — locator | Table of provider names | `factory/locator_test.go` |
| Functional | `fakeUpstream` + admin API setup + `proxyPost` | `routing_intent_test.go`, `payload_normalization_test.go` |
| Functional — embed | **New** — assert `/v1/embeddings` returns 200 (today expects 404) | `payload_normalization_test.go` (invert case) |

Run tests: `go test ./pkg/infra/providers/cohere/...`, `go test ./pkg/infra/providers/adapter/...`, `go test -tags=functional ./tests/functional/...`

### Risks

- **Scope vs. 400-line PR budget** — chat adapter alone likely exceeds budget; chained PRs mandatory.
- **Embeddings/rerank require new proxy capability** — `providers.Client` is chat-only; forwarder/invoker must grow or split.
- **Cohere v2 stream format** — SSE event shapes differ from OpenAI; adapter complexity similar to Anthropic multi-line SSE.
- **Model catalog** — `models.dev` mapping has no `cohere` entry today; manual seed + capabilities metadata required for App v2 epic criterion.
- **Open questions block design** — client wire format for embed/rerank routes (see below).
- **Tool calling / message roles** — Cohere v2 semantics may not map 1:1 to canonical model; expect edge-case normalization.
- **App v2** — out of TrustGate worktree; catalog API must expose capabilities but UI work is separate.

### Open Questions

| # | Question | Code hint |
|---|---|---|
| 1 | Gateway chat route: `/v2/chat` only, or also require `/v1/chat/completions` cross-format? | Anthropic uses `/v1/messages` native + cross-format from OpenAI route |
| 2 | Connection probe URL — Cohere v1 `/models` vs v2 health endpoint? | groq uses `GET /openai/v1/models` |
| 3 | Embeddings gateway wire: OpenAI `/v1/embeddings` JSON in, OpenAI JSON out? | Acceptance says "proxied" — likely OpenAI-compatible facade |
| 4 | Rerank gateway path and wire format? | No existing route; propose `/v1/rerank` with Cohere-native or thin wrapper |
| 5 | Should semantic-cache plugin get `embedding/cohere` creator? | Only if Cohere registries used with semantic cache |
| 6 | models.dev sync for Cohere models or static seed only? | `modelsDevProviderToCode` has no `cohere` key |
| 7 | Catalog `capabilities` JSON schema for embed/rerank models? | `domain/catalog.Model.Capabilities map[string]any` — schema undefined in code |
| 8 | Epic "App v2 registry complete" — TrustGate-only seed sufficient? | Confirm with App v2 team |

### Ready for Proposal

**Yes** — exploration confirms feasibility via Anthropic-style native provider. Proposal should:

1. Lock gateway routes (`/v2/chat`, `/v1/embeddings`, `/v1/rerank`).
2. Decide embed/rerank wire formats (recommend OpenAI-shaped gateway facades).
3. Confirm chained PR split (chat → embed → rerank + catalog).
4. Resolve connection probe endpoint against Cohere docs.
5. Scope App v2 catalog as TrustGate seed + API vs. separate ticket.

**400-line budget forecast:** High — chained PRs recommended (`Decision needed before apply: Yes`, `Chained PRs recommended: Yes`, `400-line budget risk: High`).
