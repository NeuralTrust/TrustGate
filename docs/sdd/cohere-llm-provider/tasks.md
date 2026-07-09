# Tasks: Cohere LLM Provider (RUN-925)

**Linear:** RUN-925 · **Branch:** `feat/cohere-llm-provider` · **Worktree:** TrustGate-cohere-llm-provider

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines (total) | 1250–1850 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR-1 chat → PR-2 embeddings → PR-3 rerank+catalog |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Base branch | Est. lines |
|------|------|-----------|-------------|------------|
| 1 | Native v2 chat (sync+stream), connection test, cross-format from OpenAI | PR-1 | `main` | 600–900 |
| 2 | `/v1/embeddings` proxy + Cohere v2 embed adapter | PR-2 | `main` (after PR-1) | 350–500 |
| 3 | `/v1/rerank` proxy + catalog seed with capabilities | PR-3 | `main` (after PR-2) | 300–450 |

**Out of scope (TrustGate):** App v2 registry UI — separate `app` repo ticket after catalog API exposes Cohere.

**Artifact note:** Spec/design not in Engram; tasks derived from `explore.md` + RUN-925 acceptance criteria.

---

## Phase 1: PR-1 — Chat foundation (Work Unit 1)

**Review Workload Forecast:** 180–250 lines · budget risk Medium · PR-1 slice 1/3

**Files:** `pkg/infra/providers/client.go`, `pkg/infra/providers/cohere/client.go`, `pkg/infra/providers/cohere/connection.go`, `pkg/infra/providers/factory/locator.go`

- [ ] 1.1 Add `ProviderCohere = "cohere"` to `pkg/infra/providers/client.go` (`SupportedProviders`, `IsValidProvider`)
- [ ] 1.2 Create `pkg/infra/providers/cohere/client.go`: POST `https://api.cohere.com/v2/chat` sync + SSE stream (pattern: `anthropic/client.go`)
- [ ] 1.3 Create `pkg/infra/providers/cohere/connection.go`: `TestConnection` via `RunBearerGETProbe` to `GET https://api.cohere.com/v1/models`
- [ ] 1.4 Register `cohere.NewCohereClient()` in `pkg/infra/providers/factory/locator.go` (+ `ProviderCohere` alias)

---

## Phase 2: PR-1 — Chat adapter & routing (Work Unit 1)

**Review Workload Forecast:** 350–500 lines · budget risk High · PR-1 slice 2/3

**Files:** `pkg/infra/providers/adapter/format.go`, `cohere_adapter.go`, `registry.go`, `pkg/api/resolver/proxy_path_resolver.go`, `pkg/app/proxy/provider.go`, `pkg/app/catalog/sync.go`

- [ ] 2.1 Add `FormatCohere` to `adapter/format.go`; extend `ResolveTargetFormat`, `ResolveAgentFormat`, `SupportedSourceFormat` for `cohere`
- [ ] 2.2 Create `adapter/cohere_adapter.go`: Cohere v2 messages/tools/stream ↔ canonical (pattern: `anthropic_adapter.go`)
- [ ] 2.3 Register `FormatCohere` in `adapter/registry.go`
- [ ] 2.4 Add `RouteChatV2 = "/v2/chat"` → `FormatCohere` in `proxy_path_resolver.go` (+ resolver tests)
- [ ] 2.5 Add `FormatCohere` to `injectStreamTrue` branch in `pkg/app/proxy/provider.go` if v2 uses `stream` boolean
- [ ] 2.6 Seed Cohere provider row in `pkg/app/catalog/sync.go` (`wire_format: cohere`, `api_key` auth); no models.dev mapping

---

## Phase 3: PR-1 — Chat tests & ship (Work Unit 1)

**Review Workload Forecast:** 120–180 lines · budget risk Low · PR-1 slice 3/3

**Files:** `pkg/infra/providers/cohere/*_test.go`, `adapter/cohere_adapter_test.go`, `factory/locator_test.go`, `tests/functional/`, `openspec/changes/cohere-llm-provider-chat/`

- [ ] 3.1 Unit tests: `cohere/client_test.go`, `connection_test.go` (httptest headers, status, body)
- [ ] 3.2 Unit tests: `cohere_adapter_test.go` — same-format roundtrip, OpenAI→Cohere cross-format, stream chunks
- [ ] 3.3 Update `factory/locator_test.go` and `validate_test.go` for `ProviderCohere`
- [ ] 3.4 Functional: Cohere registry + sync+stream via `/{slug}/v2/chat`; cross-format via `/{slug}/v1/chat/completions`
- [ ] 3.5 Add `openspec/changes/cohere-llm-provider-chat/proposal.md` (frontmatter: `linear: RUN-925`, `type: feat`)
- [ ] 3.6 Verify: `go test -race ./pkg/infra/providers/cohere/... ./pkg/infra/providers/adapter/...`

---

## Phase 4: PR-2 — Embeddings capability (Work Unit 2)

**Review Workload Forecast:** 280–400 lines · budget risk Medium · PR-2

**Files:** `pkg/infra/providers/embed.go` (new interface), `cohere/embed.go`, `adapter/cohere_embed_adapter.go`, `proxy_path_resolver.go`, `pkg/app/proxy/embed_invoker.go`, `forwarder.go`, `factory/locator.go`

- [ ] 4.1 Introduce `providers.Embedder` interface (`Embed(ctx, cfg, body) ([]byte, error)`) in `pkg/infra/providers/` (or `embed.go`)
- [ ] 4.2 Create `cohere/embed.go`: POST `https://api.cohere.com/v2/embed` with Bearer auth
- [ ] 4.3 Create `adapter/cohere_embed_adapter.go`: OpenAI `/v1/embeddings` request/response ↔ Cohere v2 embed
- [ ] 4.4 Add `RouteEmbeddings = "/v1/embeddings"` → `FormatOpenAI` (embed source) in `proxy_path_resolver.go`
- [ ] 4.5 Create `pkg/app/proxy/embed_invoker.go`: adapt request, enforce model, call `Embedder`, adapt response
- [ ] 4.6 Wire embed path in `forwarder.go` (dispatch by route capability, not chat invoker)
- [ ] 4.7 Extend `factory/locator.go` with `GetEmbedder("cohere")` returning cohere client

---

## Phase 5: PR-2 — Embeddings tests & ship (Work Unit 2)

**Review Workload Forecast:** 80–120 lines · budget risk Low · PR-2

**Files:** `adapter/cohere_embed_adapter_test.go`, `proxy_path_resolver_test.go`, `tests/functional/payload_normalization_test.go`, `openspec/changes/cohere-llm-provider-embed/`

- [ ] 5.1 Unit tests: `cohere_embed_adapter_test.go` — model, input array, dimensions mapping
- [ ] 5.2 Resolver tests: `/{slug}/v1/embeddings` resolves (no longer `ErrUnknownProxyPath`)
- [ ] 5.3 Functional: Cohere target + `POST /{slug}/v1/embeddings` returns 200 with OpenAI-shaped response
- [ ] 5.4 Update `TestProxyPaths_FixedRoutes` — embeddings 404 only when route unsupported, not when Cohere wired
- [ ] 5.5 Add `openspec/changes/cohere-llm-provider-embed/proposal.md`
- [ ] 5.6 Verify: `go test -race ./pkg/...` + `go test -tags=functional ./tests/functional/... -run Embeddings`

---

## Phase 6: PR-3 — Rerank & catalog (Work Unit 3)

**Review Workload Forecast:** 220–320 lines · budget risk Medium · PR-3 slice 1/2

**Files:** `cohere/rerank.go`, `adapter/cohere_rerank_adapter.go`, `adapter/format.go`, `proxy_path_resolver.go`, `pkg/app/proxy/rerank_invoker.go`, `forwarder.go`, `pkg/app/catalog/sync.go`

- [ ] 6.1 Create `cohere/rerank.go`: POST `https://api.cohere.com/v2/rerank`
- [ ] 6.2 Add gateway wire format constant (e.g. `FormatCohereRerank` or `FormatRerank`) and `RouteRerank = "/v1/rerank"` in resolver
- [ ] 6.3 Create `adapter/cohere_rerank_adapter.go`: gateway rerank JSON ↔ Cohere v2 rerank
- [ ] 6.4 Create `pkg/app/proxy/rerank_invoker.go` + `forwarder.go` dispatch (mirror embed invoker)
- [ ] 6.5 Extend locator with `GetReranker("cohere")` or unified capability getter on cohere client
- [ ] 6.6 Manual catalog seed in `sync.go`: Cohere models (`command-r-plus`, `embed-english-v3.0`, etc.) with `capabilities: {chat, embed, rerank}`

---

## Phase 7: PR-3 — Verification & changelog (Work Unit 3)

**Review Workload Forecast:** 80–130 lines · budget risk Low · PR-3 slice 2/2

**Files:** `*_test.go`, `tests/functional/`, `openspec/changes/cohere-llm-provider-rerank/`

- [ ] 7.1 Unit tests: `cohere_rerank_adapter_test.go`, rerank client httptest
- [ ] 7.2 Functional: `POST /{slug}/v1/rerank` through Cohere registry returns ranked results
- [ ] 7.3 Catalog sync test: provider + model rows exist with expected capabilities
- [ ] 7.4 Add `openspec/changes/cohere-llm-provider-rerank/proposal.md` (changelog entry for merge)
- [ ] 7.5 Full verify: `go test -race ./...` and functional suite for chat+embed+rerank
- [ ] 7.6 Confirm `/v1/providers-catalog` exposes Cohere for App v2 (manual smoke); file App v2 follow-up ticket

---

## Phase 8: App v2 registry (out of scope — separate repo)

- [ ] 8.1 **Deferred:** App v2 provider picker + model capabilities UI in `app` repo (consumes TrustGate catalog API)
