# Tasks: Native Gemini and Vertex embeddings on gateway consumers (ENG-1624)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | core ~340 prod + ~790 test (~1,130); with the cuttable `:predict` phase ~450 prod + ~940 test (~1,390); generated `docs/` excluded |
| 400-line budget risk | High (total), Low on prod lines alone (~340 core, ~450 with `:predict`) |
| Chained PRs recommended | No |
| Suggested split | single PR with `size:exception` (majority tests); fallback chain below |
| Delivery strategy | single-pr |
| Chain strategy | size-exception |

Decision needed before apply: Yes
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

Recommendation: one PR to `develop`, label `size:exception`, PR body with the prod/test breakdown per phase (precedent: ENG-1618 S1c-3a). Prod code stays under 400 lines; the rest is tests. Each phase below is one commit, so the PR reads commit by commit. The phases are coupled (the routes are useless without the adapter, the adapter is dead code without the routes), which makes a chain mostly cost.

Fallback if Edu prefers chained PRs (feature-branch chain, tracker `feat/eng-1624-gemini-vertex-native-embeddings`):

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Phases 1-2: canonical fields, target encoders, provider gate, Gemini embed adapter (inert: no route reaches it) | PR 1 → tracker | ~260 prod / ~330 test; `/v1/embeddings` byte-identical |
| 2 | Phases 3-5: resolver, path model, app tests, functional, docs | PR 2 → PR 1 | ~80 prod / ~460 test; the feature goes live here |
| 3 | Phase 6: Vertex `:predict` (cuttable, closes ENG-3023) | PR 3 → PR 2 | ~110 prod / ~150 test |

### Phase-level forecast

| Phase | Commit | Prod | Test | Total |
|---|---|---:|---:|---:|
| 1 | Canonical fields + target encoders + provider gate | ~65 | ~100 | ~165 |
| 2 | Gemini embed adapter + format lists | ~195 | ~230 | ~425 |
| 3 | Resolver + path model + app wiring tests | ~40 | ~260 | ~300 |
| 4 | Functional QA coverage | — | ~160 | ~160 |
| 5a | Docs: README + godoc stub | ~40 | ~25 | ~65 |
| 5b | Docs: `make docs` (generated, own commit) | gen | — | gen |
| **Core** | | **~340** | **~775** | **~1,115** |
| 6 (cuttable) | Vertex `:predict` | ~110 | ~150 | ~260 |
| **With 6** | | **~450** | **~925** | **~1,375** |

---

## Phase 1: Canonical model and target encoders

Commit: `feat(adapter): carry embedding task type, titles and dimensions to capable targets`

- [x] 1.1 `pkg/infra/providers/adapter/cohere_embed_adapter.go`: add `TaskType string \`json:"task_type,omitempty"\``, `Titles []string \`json:"titles,omitempty"\``, `Dimensions int \`json:"dimensions,omitempty"\`` to `CanonicalEmbeddingRequest`.
- [x] 1.2 Same file: `CohereEmbedAdapter.EncodeRequest` derives `input_type` from `TaskType` when `InputType` is empty (RETRIEVAL_QUERY→search_query, RETRIEVAL_DOCUMENT→search_document, CLASSIFICATION→classification, CLUSTERING→clustering, else `search_document`). Titles and Dimensions dropped.
- [x] 1.3 Same file: `openAIEmbeddingRequest` gains `Dimensions int \`json:"dimensions,omitempty"\``; `OpenAIEmbeddingsAdapter.EncodeRequest` emits it from canonical. `DecodeRequest` unchanged (no `dimensions` decode on `/v1/embeddings`).
- [x] 1.4 Same file: `AdaptEmbeddingRequestForProvider(registry, body, source, target, providerName)`: decode, clear `Dimensions` unless `providerName` is `provider.OpenAI` or `provider.Azure` (rewrite `Metadata["embedding"]` via `embeddingFromCanonical`), encode. `AdaptEmbeddingRequest` delegates with `providerName == ""` and keeps its signature and the `source == target` passthrough.
- [x] 1.5 `pkg/infra/providers/adapter/vertex_embed_adapter.go`: `vertexEmbedRequest` gains `taskType`, `title`, `outputDimensionality` (omitempty); `EncodeRequest` sets them per request (title by index). Count-based single/batch choice untouched; `DecodeRequest` and `textsFromVertexContent` untouched.
- [x] 1.6 `pkg/infra/providers/adapter/bedrock_titan_embed_adapter.go`: no change (fields dropped by construction); covered by a test.
- [x] 1.7 `pkg/app/proxy/provider.go` (~L720): `adaptRequestBody` calls `AdaptEmbeddingRequestForProvider` with the provider name it already receives.
- [x] 1.8 Tests in `vertex_embed_adapter_test.go`, `cohere_embed_adapter_test.go` (or the existing embeddings test file), `bedrock_titan_embed_adapter_test.go`: carry-or-drop table per target; Cohere taskType mapping incl. unknown → `search_document`; provider gate keeps `dimensions` for openai/azure and drops it for mistral/openai_compatible/""; OpenAI→{Vertex, Cohere, Titan, OpenAI} bodies for existing `/v1/embeddings` inputs byte-identical to today (golden strings).

Verify: `go test -race ./pkg/infra/providers/adapter/ ./pkg/app/proxy/`

## Phase 2: Gemini embed adapter and format lists

Commit: `feat(adapter): decode and encode native Gemini embedContent and batchEmbedContents`

- [x] 2.1 `pkg/infra/providers/adapter/format.go`: `FormatGeminiEmbed = "gemini_embed"`, `FormatGeminiBatchEmbed = "gemini_batch_embed"`; add both to the non-chat case of `IsChatRequest` and to `SupportedSourceFormat`; add `ModelInPath(f Format) bool` (true for `FormatGemini`, `FormatGeminiEmbed`, `FormatGeminiBatchEmbed`).
- [x] 2.2 Create `pkg/infra/providers/adapter/gemini_embed_adapter.go`: `GeminiEmbedAdapter{batch bool}` with wire structs from design (`geminiEmbedRequest`, `geminiBatchEmbedRequest`, `geminiEmbedConfig`, parts with `text`/`inlineData`/`fileData`).
  - DecodeRequest: top-level `model` only, `models/` prefix stripped → `CanonicalRequest.Model` and canonical `Model`; one content = one input, text parts joined with `"\n"`; non-text part or content with no text → `*UnsupportedContentError`; empty request / empty `requests` → `*UnsupportedContentError`; JSON error → `&RequestDecodeError{Format, Cause}`; `taskType`/`title`/`outputDimensionality` top-level, falling back to `embedContentConfig`; `autoTruncate` dropped; batch with differing `taskType` or `outputDimensionality` → `*UnsupportedContentError`; negative dimensionality → `*UnsupportedContentError`; `Titles` aligned to inputs, nil when none.
  - EncodeResponse: single → `{"embedding":{"values":…}}`, error unless exactly one vector; batch → `{"embeddings":[…]}` always (one item stays a list).
  - DecodeResponse delegates to `VertexEmbedAdapter.DecodeResponse`; EncodeRequest encodes the action's envelope from canonical; stream methods return `nil, nil`.
- [x] 2.3 `pkg/infra/providers/adapter/registry.go`: register `FormatGeminiEmbed` → `&GeminiEmbedAdapter{}` and `FormatGeminiBatchEmbed` → `&GeminiEmbedAdapter{batch: true}`.
- [x] 2.4 `pkg/infra/providers/adapter/error_envelope.go`: add both formats to the `FormatGemini` case of `errorDialect`.
- [x] 2.5 Create `gemini_embed_adapter_test.go`: shape by format (batch of one stays a batch, single with ≠1 vectors errors); multi-part content → one input; non-text, empty, bad JSON errors and their types; mixed batch → error; `models/` stripped and per-request `model` ignored; `embedContentConfig` fallback and top-level precedence; cross-format via `AdaptEmbeddingRequestForProvider` to vertex_embed (taskType/title/outputDimensionality per request), openai_embeddings (openai keeps `dimensions`, mistral drops), cohere_embed (input_type), bedrock_titan_embed; response round trip from each target's sample body.
- [x] 2.6 `error_envelope_test.go` (or existing): Gemini error object for both new formats; `format_test.go`: `ModelInPath`, `IsChatRequest`, `SupportedSourceFormat` rows.

Verify: `go test -race ./pkg/infra/providers/adapter/`

## Phase 3: Resolver, model from the path, app wiring

Commit: `feat(proxy): route native Gemini and Vertex embeddings actions on gateway consumers`

- [x] 3.1 `pkg/api/resolver/proxy_path_resolver.go`: `nativeAction{format, capability}` and `geminiActions` table (generateContent, streamGenerateContent → Gemini chat; embedContent → `FormatGeminiEmbed`; batchEmbedContents → `FormatGeminiBatchEmbed`); `vertexActions` = `geminiActions` for now. Gemini prefix branch splits with `adapter.SplitGeminiModelAction` and looks up the action; `matchesVertexLayout` returns the action; remove `vertexChatActions`. No action, `countTokens`, `predict`, `rawPredict`, `streamRawPredict`, `batchGenerateContent` → `ErrUnknownProxyPath`.
- [x] 3.2 `pkg/api/resolver/proxy_path_resolver_test.go`: table rows for every action × {Gemini, Vertex regional v1/v1beta1, Vertex express}; 404 rows for the set above on both families; existing chat rows untouched; `AllowedMethods` is POST only for the new routes. `TestGeminiModelFromPath` unchanged.
- [x] 3.3 `pkg/app/proxy/routing.go`: `modelRefFromRequest` and `applyIntentToBody` use `adapter.ModelInPath(format)` instead of `== FormatGemini`.
- [x] 3.4 `pkg/app/proxy/routing_forwarder_test.go`: copy `TestForward_VertexNativePathTakesModelFromPath`: embeddings path model stamped into the body; `auto` in the path strips it; qualified `registry/model` overrides.
- [x] 3.5 `pkg/app/proxy/provider_embeddings_test.go`: copy `TestProviderInvoke_VertexEmbeddingsCrossFormat`: Gemini single and batch-of-one → Vertex (upstream body and client response shapes); Gemini batch → OpenAI (cross-format, `dimensions` sent) and → Mistral (`dimensions` dropped); → Cohere (`input_type`); disallowed path model → `ErrModelNotAllowed`; mixed batch → `ErrInvalidRequestPayload`.
- [x] 3.6 `pkg/api/handler/http/proxy/proxy_handler_test.go`: GET on an embeddings native path → 405 with `Allow: POST` (behaviour already exists at `methodNotAllowed`, test only); a 400 on a Gemini embeddings path comes back as the Gemini error object.

Verify: `go test -race ./pkg/api/resolver/ ./pkg/app/proxy/ ./pkg/api/handler/http/proxy/`, then `make test`

## Phase 4: Functional QA coverage

Commit: `test(functional): native Gemini and Vertex embeddings end to end`

- [x] 4.1 Create `tests/functional/native_embeddings_test.go` (build tag `functional`) reusing `newVertexEmbeddingsUpstream`, `setupEmbeddingsRoute`, `proxyPost` from `embeddings_provider_test.go`:
  - `/v1beta/models/gemini-embedding-001:embedContent` with a Vertex registry → `{"embedding":{"values":[…]}}`.
  - `:batchEmbedContents` with one request → `{"embeddings":[…]}` with one item.
  - `/v1/projects/x/locations/y/publishers/google/models/{m}:embedContent` with arbitrary project/region; the fake upstream sees the registry's project/location in the URL.
  - Same Gemini request against an OpenAI fake upstream → Gemini-shaped vectors.
  - Model not allowed by the consumer's model policy → rejected, Gemini error object.
  - `:countTokens` on both families → 404.
  - `/v1/embeddings` regression case unchanged.
- [x] 4.2 Traces/cost parity: assert the trace/metrics record for the native call carries the same capability/model fields as a `/v1/embeddings` call through the same fake (usage nil for OpenAI/Vertex is pre-existing; no assertion on tokens beyond parity).

Verify: `go vet -tags functional ./tests/functional/...` and `go test -tags functional -run 'NativeEmbeddings' ./tests/functional/...` (see local functional recipe if ports clash)

## Phase 5: Docs

Commit 5a: `docs: list native Gemini and Vertex embeddings paths`

- [x] 5.1 `README.md` section 7: add the inbound paths (Gemini `:embedContent`/`:batchEmbedContents`, Vertex regional + express), which targets serve them, fields carried/dropped, and fix the L98 wording that reads as an inbound route.
- [x] 5.2 Try swag with `:` in `@Router`: doc-only `HandleGeminiNativeEmbeddings` godoc stub in `pkg/api/handler/http/proxy/proxy_handler.go` modelled on `HandleBedrockNative`, plus `docs/openapi_gemini_native_test.go` modelled on `openapi_bedrock_native_test.go`. If swag rejects the `:` or `make docs` drags unrelated drift, drop 5.2/5.3 and keep README only (record in state.yaml).

Commit 5b (own commit, only if 5.2 holds): `docs: regenerate OpenAPI`

- [x] 5.3 `make docs`; commit only the generated `docs/` files.

Verify: `go test ./docs/...`, `make test`

## Phase 6 (CUTTABLE — Edu decides at approval): Vertex `:predict`

Closes ENG-3023 as well. Skip the whole phase if cut; nothing in phases 1-5 depends on it.

Commit: `feat(proxy): accept native Vertex :predict embeddings requests`

- [x] 6.1 `format.go`: `FormatVertexPredictEmbed = "vertex_predict_embed"`; add to `IsChatRequest` non-chat, `SupportedSourceFormat`, `ModelInPath`; `error_envelope.go`: Gemini dialect; `registry.go`: register.
- [x] 6.2 Create `pkg/infra/providers/adapter/vertex_predict_embed_adapter.go`: decode `instances[].content` (string), `task_type`/`taskType`, `title`, `parameters.outputDimensionality`; same mixed-value, empty and decode-error rules as phase 2; `autoTruncate` dropped; encode response `predictions[].embeddings.values` (one per vector), `statistics` omitted.
- [x] 6.3 `proxy_path_resolver.go`: `vertexActions` gains `predict` → `FormatVertexPredictEmbed`, embeddings. Gemini `/v1beta/models/{m}:predict` stays 404.
- [x] 6.4 Tests: `vertex_predict_embed_adapter_test.go` (decode, both task-type spellings, cross-format to vertex_embed/openai/cohere, response shape); resolver rows (Vertex predict routes, Gemini predict 404); `provider_embeddings_test.go` case; functional case reproducing the ENG-3023 request (`/v1beta1/projects/bv-juia-uat/locations/global/publishers/google/models/gemini-embedding-001:predict` → 200 with `predictions`).
- [x] 6.5 README: add `:predict` to section 7.

Verify: `go test -race ./pkg/infra/providers/adapter/ ./pkg/api/resolver/ ./pkg/app/proxy/`, `go vet -tags functional ./tests/functional/...`

---

## Per-phase gate (every phase)

- Code review of the phase diff against `.agents/AGENTS.md` + golang-pro; fix CRITICAL/WARNING.
- `clean-comments` on touched Go files (haiku), then `git diff` check for deleted Swagger `// @` and doc lines that must stay.
- One commit per phase; never stage `.cursor/`.

## Open items carried from design

- Live check in DEV that Vertex upstream accepts `:embedContent`/`:batchEmbedContents` for gemini-embedding-001 (pre-existing outbound risk; Vertex docs show `:predict`).
- google-genai SDK `embedContentConfig` nesting and `:predict` `statistics` requirement: unverified live; design accepts both / omits statistics.
- Follow-up (not in this change): embeddings usage is nil for OpenAI/Cohere/Vertex targets, so cost and token rate limits do not count them on `/v1/embeddings` either.
