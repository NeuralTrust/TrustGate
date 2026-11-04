# Design: Native Gemini and Vertex embeddings on gateway consumers (ENG-1624)

## Technical Approach

The inbound path decides the dialect. New source formats, one per inbound action, decode into the canonical embedding request and encode the canonical embedding response, so the response shape follows what the client called and not the vector count. They are never targets: `ResolveTargetFormatForCapability` keeps picking `vertex_embed`, `openai_embeddings`, `cohere_embed` or `bedrock_titan_embed`, so `source != target` always and every request is re-encoded. The model rides in the path, is stamped into the body by `applyIntentToBody` (so `modelallowlist` and `EnforceModel` see it), and is read back from the top-level `model` by the new decoder.

Everything below was checked against `origin/develop` 7c61bbce.

## Architecture Decisions

### Decision: one source format per inbound action

**Choice**: `FormatGeminiEmbed = "gemini_embed"` (`:embedContent`), `FormatGeminiBatchEmbed = "gemini_batch_embed"` (`:batchEmbedContents`), and, in the cuttable phase, `FormatVertexPredictEmbed = "vertex_predict_embed"` (`:predict`). The Gemini `/v1beta/models/` path and both Vertex layouts share the first two: the body schema is the same.
**Alternatives considered**: reuse `vertex_embed` as source (ambiguous: it is the Vertex target and an error dialect key, and `AdaptEmbeddingRequest` would pass the body through untouched, stamped `model` included); one `gemini_embed` format plus a shape hint carried on the request context (adapters are stateless and `AdaptEmbeddingResponse` only sees formats, so the hint would need a new parameter through `adaptResponseBody`).
**Rationale**: the adapter registry is keyed by format and adapters are stateless; a format per action keeps the single/batch shape a property of the adapter with no new plumbing.

### Decision: one adapter type, two registrations

**Choice**: `GeminiEmbedAdapter{batch bool}` in `pkg/infra/providers/adapter/gemini_embed_adapter.go`, registered as `r.Register(FormatGeminiEmbed, &GeminiEmbedAdapter{})` and `r.Register(FormatGeminiBatchEmbed, &GeminiEmbedAdapter{batch: true})` next to `registry.go:116`.
**Rationale**: decode is identical except for the envelope; encode differs only in the envelope.

### Decision: the top-level `model` is the only model source

**Choice**: the decoder sets `CanonicalRequest.Model` and `CanonicalEmbeddingRequest.Model` from the top-level `model` only, with a `models/` prefix stripped. Per-request `requests[].model` is ignored.
**Alternatives considered**: fall back to the first `requests[].model`.
**Rationale**: `applyIntentToBody` (`routing.go:381-410`) stamps the path model for a short model, overrides it for a qualified one, and strips it for `auto` and pools. A fallback would resurrect `models/auto` or `models/pool:x` from the client body after the strip. The stamp runs before the pre_request plugins (`forwarder.go:240` then `:263`), so a `modelallowlist` substitution also lands on the top-level `model` the decoder reads.

### Decision: one content is one input

**Choice**: the new decoder joins the text parts of one `content` with `"\n"` into one input. A content with no text part, or any non-text part (`inlineData`, `fileData`), returns `*UnsupportedContentError` (400).
**Rationale**: Gemini returns one vector per content. `textsFromVertexContent` (`vertex_embed_adapter.go`) flattens parts into N inputs, which would return N vectors for one request. That helper is left alone for the `vertex_embed` target path.

### Decision: canonical carries task type, titles and dimensions

**Choice**: `CanonicalEmbeddingRequest` (`cohere_embed_adapter.go:19-24`) gains:

```go
TaskType   string   `json:"task_type,omitempty"`
Titles     []string `json:"titles,omitempty"`
Dimensions int      `json:"dimensions,omitempty"`
```

`TaskType` keeps the Gemini vocabulary. `Titles` is aligned to `Inputs` (empty string when a request has none) and is nil when no request has a title.
A batch whose requests disagree on `taskType` or `outputDimensionality` returns `*UnsupportedContentError` (400). A negative `outputDimensionality` is a 400 too; zero means unset.
**Rationale**: these are the only three knobs any target understands. Per-request disagreement is rare and cannot be expressed by OpenAI, Cohere or Titan.

### Decision: how each target uses the new fields

| Target encoder | TaskType | Titles | Dimensions |
|---|---|---|---|
| `VertexEmbedAdapter.EncodeRequest` | `taskType` on each request | `title` on the request at the same index | `outputDimensionality` on each request |
| `CohereEmbedAdapter.EncodeRequest` | `input_type` when canonical `InputType` is empty: RETRIEVAL_QUERY→search_query, RETRIEVAL_DOCUMENT→search_document, CLASSIFICATION→classification, CLUSTERING→clustering, anything else→`search_document` (current default) | dropped | dropped |
| `OpenAIEmbeddingsAdapter.EncodeRequest` | dropped | dropped | `dimensions`, only after the provider gate below |
| `BedrockTitanEmbedAdapter.EncodeRequest` | dropped | dropped | dropped |

`vertexEmbedRequest` gains `TaskType string \`json:"taskType,omitempty"\``, `Title string \`json:"title,omitempty"\``, `OutputDimensionality int \`json:"outputDimensionality,omitempty"\``. The count-based single/batch choice in `EncodeRequest` and `vertex/client.go:embeddingsAction` are unchanged. Nothing in `OpenAIEmbeddingsAdapter.DecodeRequest` changes, so `/v1/embeddings` traffic encodes exactly as today (all new fields are zero).

### Decision: gate `dimensions` by provider at the adapter seam

**Choice**: new `AdaptEmbeddingRequestForProvider(registry *Registry, body []byte, source, target Format, providerName string) ([]byte, error)` in `cohere_embed_adapter.go`. It decodes, clears `Dimensions` unless `providerName` is `provider.OpenAI` or `provider.Azure`, and encodes. `AdaptEmbeddingRequest` keeps its signature (the rerank adapter, `cohere_rerank_adapter.go:87`, and 10 tests call it) and delegates with `providerName == ""`, which drops `Dimensions`. `provider.go:720` switches to the new function; `providerName` already reaches `adaptRequestBody` (`provider.go:709-713`, called at `:439` with `bk.Provider()`).
**Alternatives considered**: strip `dimensions` from the encoded JSON after the fact (second marshal pass, format-specific key knowledge in the proxy); a provider-aware encoder interface (wider change).
**Rationale**: `openai_embeddings` is the target for OpenAI, Azure, Mistral and openai_compatible (`providers/capabilities.go:33-41`); only OpenAI and Azure document `dimensions`. The decision lives next to the canonical model and needs one call-site change.

Canonical update helper: since the canonical embedding rides as JSON in `Metadata["embedding"]`, the gate reads it with `embeddingFromCanonical`, clears the field and writes `json.RawMessage` back.

### Decision: decode errors are 400s

**Choice**: the new decoder wraps JSON errors as `&RequestDecodeError{Format: f, Cause: err}` (`registry.go:23-35`); `prepare` already maps that and `*UnsupportedContentError` to `ErrInvalidRequestPayload` (`provider.go:440-450`). An empty request (no content, empty `requests`) is an `UnsupportedContentError`.
**Rationale**: `AdaptEmbeddingRequest` returns decoder errors unwrapped, and a bare `json.SyntaxError` falls into the `adapt request` 5xx branch.

### Decision: Vertex `embedContentConfig`

**Choice**: read `taskType`, `title`, `outputDimensionality` top-level (Gemini API and Vertex REST `EmbedContentRequest`); when a top-level value is absent and an `embedContentConfig` object carries it, use that. `autoTruncate` (either place) is dropped.
**Rationale**: the google-genai SDK summary suggested a nested config for Vertex `:embedContent`; accepting both costs one struct field and avoids a silent drop. Not verified against a live SDK call (see Open Questions).

### Decision: resolver routes by action

**Choice**: one action table, used by both path families in `proxy_path_resolver.go`:

| Action | Gemini `/v1beta/models/{m}:` | Vertex regional + express | Format | Capability |
|---|---|---|---|---|
| `generateContent`, `streamGenerateContent` | yes | yes | `FormatGemini` | chat |
| `embedContent` | yes | yes | `FormatGeminiEmbed` | embeddings |
| `batchEmbedContents` | yes | yes | `FormatGeminiBatchEmbed` | embeddings |
| `predict` (cuttable phase) | no | yes | `FormatVertexPredictEmbed` | embeddings |
| anything else, or no action | 404 | 404 | — | — |

```go
type nativeAction struct {
	format     adapter.Format
	capability ProxyCapability
}

var geminiActions = map[string]nativeAction{
	"generateContent":       {adapter.FormatGemini, CapabilityChat},
	"streamGenerateContent": {adapter.FormatGemini, CapabilityChat},
	"embedContent":          {adapter.FormatGeminiEmbed, CapabilityEmbeddings},
	"batchEmbedContents":    {adapter.FormatGeminiBatchEmbed, CapabilityEmbeddings},
}
```

`vertexActions` is `geminiActions` plus `predict` when the phase is kept. `formatForRoute` (`:203-211`) becomes: for the Gemini prefix, split the segment after `GeminiModelsRoutePrefix` with `adapter.SplitGeminiModelAction` and look the action up; for Vertex, `matchesVertexLayout` returns the action instead of a bool (`vertexChatActions` at `:216` goes away). `geminiMethods` in `format.go:80-88` already lists every action, so `SplitGeminiModelAction` splits them; `countTokens`, `rawPredict`, `streamRawPredict` and (Gemini path) `predict` split correctly and then miss the table → `ErrUnknownProxyPath` → 404 via `auth.go:80`. `/v1beta/models/gemini-pro` (no action) and `:batchGenerateContent` (not in `geminiMethods`, so all model, action "") → 404, where today they route to chat.
`TestGeminiModelFromPath` tests `adapter.GeminiModelFromPath`, which does not change, so its `"/v1beta/models/gemini-pro": "gemini-pro"` row stays. `c.Path()` (`request_target.go:40`, `auth.go:80`) excludes the query string, so `?alt=sse` and `?key=` never reach the split. `AllowedMethods` needs no change: embeddings fall into the POST-only default.

### Decision: model in the path is a format property

**Choice**: `adapter.ModelInPath(f Format) bool` in `format.go`, true for `FormatGemini`, `FormatGeminiEmbed`, `FormatGeminiBatchEmbed` (and `FormatVertexPredictEmbed`). `modelRefFromRequest` (`routing.go:358`) and `applyIntentToBody` (`routing.go:407`) call it instead of comparing with `FormatGemini`.
**Rationale**: these are the only two `FormatGemini` path-model sites (`GeminiModelFromPath` has no other non-test caller). Model policy then holds twice, as for `/v1/embeddings`: the `modelallowlist` plugin reads the stamped body, and `applyModelEnforcement` (`provider.go:351`) checks the target body after `CarryModel` (`provider.go:456-459`) copies the stamped model onto encoders that drop it (Vertex, Titan).

### Decision: format lists

- `IsChatRequest` (`format.go:188-199`): add the new formats to the non-chat case (only consulted when capability is empty).
- `SupportedSourceFormat` (`format.go:201-212`): add them.
- `errorDialect` (`error_envelope.go:162-175`): add them to the `FormatGemini` case, so gateway errors (400 mixed batch, 403 model denied, 404 unknown model) reach Google clients as the Gemini error object.

### Decision: guardrails, policies, traces, cost — parity only

Guardrails skip embeddings today (`pluginutil.SkipNonChatRoute`, capability != chat) and keep doing so. Usage: `decodeResponseMeta` (`provider.go:274-280`) reads `CanonicalResponse.Usage`; `OpenAIEmbeddingsAdapter.DecodeResponse` (`cohere_embed_adapter.go:81-103`) puts usage only inside `ProviderExtensions["embedding"]`, and Cohere and Vertex decode none, so only Titan (`bedrock_titan_embed_adapter.go:73-83`) reports tokens. Confirmed by code reading; pre-existing for `/v1/embeddings`, recorded as a follow-up, not fixed here. The new routes inherit the same behaviour because usage is decoded from the target format.

## Data Flow

```
POST /{slug}/v1beta/models/gemini-embedding-001:batchEmbedContents
  │ resolver: action → gemini_batch_embed, embeddings
  ▼
forwarder: modelRefFromRequest (ModelInPath → path model)
           applyIntentToBody   (stamp top-level "model")
           pre_request plugins (modelallowlist reads body model)
  ▼
providerInvoker.prepare: target = ResolveTargetFormatForCapability(provider, embeddings)
  AdaptEmbeddingRequestForProvider(gemini_batch_embed → vertex_embed|openai_embeddings|cohere_embed|bedrock_titan_embed)
  CarryModel → EnforceModel (allowed models)
  ▼
EmbeddingsClient.Embeddings
  ▼
AdaptEmbeddingResponse(target decode → GeminiEmbedAdapter{batch}.EncodeResponse)
  → {"embeddings":[{"values":[…]}]}   (single: {"embedding":{"values":[…]}})
```

## Interfaces / Contracts

Gemini wire structs (new file):

```go
type geminiEmbedConfig struct {
	TaskType             string `json:"taskType,omitempty"`
	Title                string `json:"title,omitempty"`
	OutputDimensionality int    `json:"outputDimensionality,omitempty"`
}

type geminiEmbedRequest struct {
	Model                string             `json:"model,omitempty"`
	Content              *geminiContent     `json:"content,omitempty"`
	TaskType             string             `json:"taskType,omitempty"`
	Title                string             `json:"title,omitempty"`
	OutputDimensionality int                `json:"outputDimensionality,omitempty"`
	EmbedContentConfig   *geminiEmbedConfig `json:"embedContentConfig,omitempty"`
}

type geminiBatchEmbedRequest struct {
	Model    string               `json:"model,omitempty"`
	Requests []geminiEmbedRequest `json:"requests"`
}
```

`geminiContent` reuses the parts shape with `Text`, `InlineData` and `FileData` as `json.RawMessage` so non-text parts are detected and rejected. Response encoding reuses `vertexEmbedResponse`/`vertexEmbedding`: single → `{"embedding":{"values":…}}` (error if the canonical response does not hold exactly one vector), batch → `{"embeddings":[…]}` always. `DecodeResponse` delegates to `VertexEmbedAdapter.DecodeResponse`; `EncodeRequest` encodes the action's envelope from the canonical request (used in round-trip tests). Stream methods return `nil, nil` like every embed adapter.

Cuttable phase — `VertexPredictEmbedAdapter` (`vertex_predict_embed_adapter.go`):

```go
type vertexPredictInstance struct {
	Content   string `json:"content"`
	TaskType  string `json:"task_type,omitempty"`
	TaskTypeC string `json:"taskType,omitempty"`
	Title     string `json:"title,omitempty"`
}

type vertexPredictRequest struct {
	Instances  []vertexPredictInstance `json:"instances"`
	Parameters *struct {
		OutputDimensionality int  `json:"outputDimensionality,omitempty"`
		AutoTruncate         *bool `json:"autoTruncate,omitempty"`
	} `json:"parameters,omitempty"`
}

type vertexPredictResponse struct {
	Predictions []struct {
		Embeddings struct {
			Values []float64 `json:"values"`
		} `json:"embeddings"`
	} `json:"predictions"`
}
```

Same mixed-value rule as the batch format. Response: one prediction per vector; `statistics` is omitted (canonical usage is aggregate and only Titan sets it). `autoTruncate` dropped.

## File Changes

| File | Action | Description | Prod | Test |
|------|--------|-------------|-----:|-----:|
| `pkg/api/resolver/proxy_path_resolver.go` | Modify | action table; Gemini and Vertex lookups; 404 for others | ~35 | — |
| `pkg/api/resolver/proxy_path_resolver_test.go` | Modify | new routes; 404 for countTokens/predict(Gemini)/no action/batchGenerateContent | — | ~50 |
| `pkg/infra/providers/adapter/format.go` | Modify | two (three) formats, `ModelInPath`, `IsChatRequest`, `SupportedSourceFormat` | ~20 | — |
| `pkg/infra/providers/adapter/registry.go` | Modify | register adapters | ~3 | — |
| `pkg/infra/providers/adapter/error_envelope.go` | Modify | Gemini dialect for the new formats | ~1 | ~10 |
| `pkg/infra/providers/adapter/gemini_embed_adapter.go` | Create | Gemini/Vertex embedContent + batchEmbedContents adapter | ~170 | — |
| `pkg/infra/providers/adapter/gemini_embed_adapter_test.go` | Create | decode/encode, shape fidelity, parts join, mixed batch, non-text, model prefix, embedContentConfig, cross-format to each target | — | ~220 |
| `pkg/infra/providers/adapter/cohere_embed_adapter.go` | Modify | canonical fields, `AdaptEmbeddingRequestForProvider`, Cohere taskType map, OpenAI `dimensions` | ~45 | — |
| `pkg/infra/providers/adapter/vertex_embed_adapter.go` | Modify | per-request taskType/title/outputDimensionality on encode | ~15 | — |
| `pkg/infra/providers/adapter/*_embed_adapter_test.go` | Modify | Vertex/Cohere/OpenAI field mapping, provider gate, `/v1/embeddings` unchanged | — | ~90 |
| `pkg/app/proxy/routing.go` | Modify | `ModelInPath` at two sites | ~4 | — |
| `pkg/app/proxy/provider.go` | Modify | call `AdaptEmbeddingRequestForProvider` | ~1 | — |
| `pkg/app/proxy/routing_forwarder_test.go` | Modify | path model stamped for embeddings; auto strips it | — | ~60 |
| `pkg/app/proxy/provider_embeddings_test.go` | Modify | Gemini→Vertex/OpenAI/Cohere invoke; batch-of-one shape; allowed models reject; dimensions to OpenAI vs Mistral | — | ~130 |
| `tests/functional/native_embeddings_test.go` | Create | QA checklist end to end (build tag `functional`) | — | ~160 |
| `README.md` | Modify | section 7: native Gemini/Vertex paths | ~15 | — |
| `pkg/api/handler/http/proxy/proxy_handler.go` | Modify | doc-only `HandleGeminiNativeEmbeddings` godoc stub, like `HandleBedrockNative` (`:150-174`) | ~25 | — |
| `docs/*` (generated) + `docs/openapi_gemini_native_test.go` | Modify/Create | `make docs` in its own commit; test like `openapi_bedrock_native_test.go` | gen | ~25 |
| **Core total** | | | **~335** | **~770** |
| Cuttable: `vertex_predict_embed_adapter.go` (+ test, resolver row, functional case) | Create | Vertex `:predict` | ~110 | ~150 |

Generated `docs/` files are excluded from the review budget. If swag rejects the `:` in `/{consumer_slug}/v1beta/models/{model}:embedContent` or `make docs` drags unrelated drift, the OpenAPI task is dropped and README alone documents the paths.

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit — resolver | every action × layout → format/capability; 404 set; existing chat rows untouched | table tests in `proxy_path_resolver_test.go` |
| Unit — adapter | single/batch envelope by format (batch of one stays a batch); parts joined; non-text and empty → `UnsupportedContentError`; bad JSON → `RequestDecodeError`; mixed taskType/dimensions → error; top-level model only, `models/` stripped; `embedContentConfig` fallback; Vertex/Cohere/OpenAI/Titan carry-or-drop table; `AdaptEmbeddingRequestForProvider` keeps `dimensions` for openai/azure only; OpenAI→X `/v1/embeddings` bodies byte-identical to today | `gemini_embed_adapter_test.go`, existing `*_embed_adapter_test.go` |
| Unit — app | `modelRefFromRequest`/`applyIntentToBody` for the new formats; invoker cross-format with a disallowed model → `ErrModelNotAllowed`; error dialect | copy `TestForward_VertexNativePathTakesModelFromPath` (`routing_forwarder_test.go:326`) and `TestProviderInvoke_VertexEmbeddingsCrossFormat` (`provider_embeddings_test.go:49`) |
| Functional | QA checklist: Gemini single + batch-of-one vs a Vertex fake upstream; Vertex regional path with arbitrary project/region, upstream URL from the registry; Gemini vs OpenAI fake (cross-format); model denied by the consumer; `:countTokens` 404 on both families | new `tests/functional/native_embeddings_test.go` reusing `newVertexEmbeddingsUpstream`, `setupEmbeddingsRoute`, `proxyPost` (`embeddings_provider_test.go:199-229`); run `go vet -tags functional ./...` locally since `make test` skips them |
| Live | Vertex upstream accepts `:embedContent` for gemini-embedding-001 | DEV throwaway gateway after merge (pre-existing outbound risk) |

## Migration / Rollout

No migration required. The new formats are reachable only from the new routes. Behaviour changes for existing traffic are limited to `/v1beta/models/{m}` paths with no action, `:countTokens`, `:embedContent`/`:batchEmbedContents` (previously misrouted to chat) and other unknown actions, which now return 404 or route to embeddings.

## Open Questions

- [ ] Whether the google-genai SDK nests options in `embedContentConfig` for Vertex `:embedContent` (design accepts both; confirm with a live SDK capture).
- [ ] Whether the google-genai SDK requires `predictions[].embeddings.statistics` when parsing `:predict` responses (design omits it; confirm before shipping the cuttable phase).
- [ ] Whether swag accepts `:` inside an `@Router` path (decides the OpenAPI task).
