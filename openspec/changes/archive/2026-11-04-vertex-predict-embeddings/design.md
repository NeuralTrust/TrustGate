# Design: Native Vertex `:predict` embeddings on consumers (ENG-3023)

## Linked artifacts

- Linear: ENG-3023. Proposal (binding): [`proposal.md`](./proposal.md), scope and success criteria.
- Out of scope, tracked in ENG-1624: inbound `embedContent` and `batchEmbedContents`, `task_type` and `title` across providers, decoding OpenAI `dimensions` on `/v1/embeddings`.
- Format reference: [`group-scoped-personal-keys/design.md`](../group-scoped-personal-keys/design.md). Conventions: `.agents/AGENTS.md`.

## Technical approach

Four seams change. Everything downstream (policies, guardrails, traces, cost) is reused unchanged because the canonical embedding shape is unchanged.

1. **Resolver.** `isVertexGenerateContentPath` becomes `vertexAction(rest) (model, action string, ok bool)`; `matchesVertexLayout` returns the action instead of a bool. `formatForRoute` branches on it: chat actions stay `FormatGemini` and `CapabilityChat`; `predict` on a model that passes `isEmbeddingModel` (prefixes `gemini-embedding-`, `text-embedding-`, `text-multilingual-embedding-`) becomes `FormatVertexPredictEmbed` and `CapabilityEmbeddings`; anything else returns `ErrUnknownProxyPath` (404).
2. **Format and adapter.** New `FormatVertexPredictEmbed = "vertex_predict_embed"` and `VertexPredictEmbedAdapter`, registered in `registry.go` and used both as source (`DecodeRequest`, `EncodeResponse`) and as target (`EncodeRequest`, `DecodeResponse`). The adapter must decode predict responses too, because `decodeResponseMeta` reads usage with `prep.targetFormat`, which is the predict format on passthrough.
3. **Routing and body stamp.** `modelRefFromRequest` and `applyIntentToBody` treat the new format like `FormatGemini`: model comes from the path and is stamped into the body. Without this the predict body has no `model` and model policies see an empty model.
4. **Target selection and Vertex client.** `ResolveTargetFormatForCapability` returns `FormatVertexPredictEmbed` for a Vertex registry when the source is the predict format. The Vertex client selects `predict` when the body has `instances`, and removes the stamped `model` key from that body before sending. The strip is scoped to the predict branch so other embedding bodies are unchanged.

## Data flow

### (a) Vertex registry, passthrough (same wire format)

```
POST /{consumer}/v1beta1/projects/P/locations/L/publishers/google/models/gemini-embedding-001:predict
resolver        formatForRoute            -> FormatVertexPredictEmbed, CapabilityEmbeddings
routing         modelRefFromRequest       -> GeminiModelFromPath (path model), policies see it
                applyIntentToBody         -> OverrideModel(body, model)  (short model only)
provider.go:399 ResolveTargetFormatForCapability(vertex, embeddings, predict) -> predict
provider.go:423 ShouldPassthroughSameWireFormat -> true, crossFormat = false
                body forwarded as stamped: no DecodeRequest, no CarryModel
                NormalizeRequestForProvider: no-op (target is not OpenAI)
resolveSentModel                          -> model read from the stamped body
vertex client   Embeddings: resolveModel(config.Model); action = predict (instances present)
                adapter.StripModel(body) removes `model` before POST ...:predict
response        raw predict body; decodeResponseMeta(predict) -> usage from statistics.token_count
                crossFormat false: body returned unchanged
```

`task_type`, `title` and `autoTruncate` survive because the body is not re-encoded.

### (b) OpenAI registry, cross-format

```
resolver / routing       identical to (a)
provider.go:399          ResolveTargetFormatForCapability(openai, embeddings, predict) -> openai_embeddings
provider.go:423          crossFormat = true
adaptRequestBody         VertexPredictEmbedAdapter.DecodeRequest
                           -> CanonicalRequest{Metadata.embedding: {Model, Inputs, Dimensions}}
                         OpenAIEmbeddingsAdapter.EncodeRequest
                           -> {"model", "input", "dimensions"?}  (dimensions only when > 0)
                         empty instances -> RequestDecodeError -> ErrInvalidRequestPayload -> 400
CarryModel               keeps sentModel
openai client            POST /v1/embeddings
response                 OpenAIEmbeddingsAdapter.DecodeResponse -> canonical
                         VertexPredictEmbedAdapter.EncodeResponse
                           -> {"predictions":[{"embeddings":{"values", "statistics":{"token_count", "truncated"}}}]}
usage                    decodeResponseMeta(openai_embeddings) -> canonical usage
```

## File-change table

| File | Change |
|---|---|
| `pkg/api/resolver/proxy_path_resolver.go` | `isVertexGenerateContentPath` -> `vertexAction`; `matchesVertexLayout` returns the action; `formatForRoute` branches on action; new `isEmbeddingModel` prefix gate |
| `pkg/api/resolver/proxy_path_resolver_test.go` | Rows: predict on embedding model, both layouts, `v1` and `v1beta1`; predict on a chat model returns 404; chat actions and `/v1beta/models/{m}:predict` unchanged |
| `pkg/infra/providers/adapter/format.go` | Add `FormatVertexPredictEmbed` (enum ~:50); add to non-chat list in `IsChatRequest` (~:194), `SupportedSourceFormat` (~:207); `ResolveTargetFormatForCapability` (~:425) returns it for a Vertex registry when source is predict |
| `pkg/infra/providers/adapter/format_chat_request_test.go` | Add the new format to the non-chat table (~:41) |
| `pkg/infra/providers/adapter/error_envelope.go` | `errorDialect` (:166) maps the new format to `FormatGemini`; `EncodeErrorBody` and `NeedsAdaptedError` switch on `errorDialect(source)` so gateway errors (auth, policy, usage) reach the client in the Google envelope (see Resolved questions 4) |
| `pkg/infra/providers/adapter/registry.go` | Register the adapter next to `FormatVertexEmbed` (:116) |
| `pkg/infra/providers/adapter/vertex_predict_embed_adapter.go` (new) | Decode and encode request and response; empty or blank instances return a `RequestDecodeError`; `token_count` summed into usage |
| `pkg/infra/providers/adapter/vertex_predict_embed_adapter_test.go` (new) | Round trip; empty and blank instances; `token_count` sum; `outputDimensionality` mapped to `Dimensions` both ways |
| `pkg/infra/providers/adapter/cohere_embed_adapter.go` | `CanonicalEmbeddingRequest.Dimensions int \`json:"dimensions,omitempty"\`` (:19); `openAIEmbeddingRequest` (:34) gains `Dimensions`, emitted when > 0 |
| `pkg/app/proxy/routing.go` | `modelRefFromRequest` (:358) and `applyIntentToBody` (:407): new format handled like `FormatGemini` |
| `pkg/infra/providers/vertex/client.go` | `embeddingsAction` (:188) returns `predict` when body has `instances`; `Embeddings` (:133) applies `adapter.StripModel` on the predict branch only |
| `pkg/infra/providers/vertex/client_test.go` | Predict URL; outgoing body has no `model`; `embedContent` and `batchEmbedContents` URLs unchanged (~:215) |
| `pkg/app/proxy/provider_embeddings_test.go` | Passthrough predict to a Vertex fake; cross-format predict to an OpenAI fake (`dimensions` present only when set) (~:49) |
| `pkg/api/handler/http/proxy/proxy_handler_test.go` | Predict path returns 200 and the path model reaches policy input (~:595) |
| `tests/functional/embeddings_provider_test.go` | Fake Vertex serves `:predict`; full chain through the proxy, mirroring `TestVertexProvider_Embeddings` (:216) |

`provider.go` needs no code change. Its decode-error mapping (:447) runs only on the cross-format branch; see Risks.

## Decisions

| # | Decision | Rejected | Rationale |
|---|---|---|---|
| D1 | New source format `vertex_predict_embed` with its own adapter | Reuse `vertex_embed` | `vertex_embed` decodes `embedContent`; a predict body yields zero inputs. |
| D2 | Translate nothing on Vertex passthrough; forward the body byte-exact | Always decode to canonical | Canonical translation drops `task_type`, `title`, `autoTruncate`. |
| D3 | Gate by action plus model prefix in the resolver | Any `:predict` maps to embeddings | `imagen:predict` and other models must keep returning 404. |
| D4 | Gate by prefix list | Exact model allowlist | A prefix survives new versions of a family. A new family falls back to 404, which is the status quo. |
| D5 | Model from path, stamped into body | Body-only model | The predict body has no `model`, so policies would see an empty model. |
| D6 | Strip `model` in the Vertex client, predict branch only | Strip in `applyIntentToBody` | Stripping in routing would remove the stamp that `sentModel` and cross-format need. |
| D7 | `Dimensions` on canonical, emitted only when > 0 | Per-provider fields | One field, zero-value means unset, so existing OpenAI and Vertex output is unchanged. |
| D8 | Reuse the `Metadata["embedding"]` canonical shape | New metadata key | Consumer inspection and accounting stay identical to `/v1/embeddings`. |
| D9 | `outputDimensionality` per item in `requests` for batches | Top-level on a batch | Superseded: out of scope, see Resolved questions 1. |

## Testing strategy

| Level | What |
|---|---|
| Resolver | Table: match on both layouts and both versions; 404 for a chat model and for `/v1beta/models/{m}:predict`; chat routes unchanged |
| Adapter | Round trip for request and response; empty and blank instances; `token_count` summed; `Dimensions` both ways; `requests` items carry the field only for batches |
| Routing | Path model stamped into body; policy-visible model equals path model |
| Vertex client | Predict URL; `model` absent from outgoing body; `task_type` present; `embedContent` and batch URLs unchanged |
| Proxy (passthrough) | Fake Vertex receives the body minus `model`; usage populated from `token_count` |
| Proxy (cross-format) | Fake OpenAI receives `input` and `dimensions` only when set; response re-encoded as predictions |
| Handler | 200 on predict path; 404 on non-embedding predict |
| Functional | Full chain with fake Vertex, mirroring `TestVertexProvider_Embeddings` |

Gates: `make test`, `make test-race` (proxy path is concurrent), `go vet -tags functional`, `make lint`.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Passthrough skips `DecodeRequest`, so the gateway never rejects empty instances; Vertex decides | Medium | Accept upstream status on passthrough; test it; the 400 criterion applies to cross-format. Decide before merge (Open questions). |
| Stamped `model` reaches Vertex and is rejected as an unknown field | Medium | Strip on predict branch; test the outgoing body |
| Error-envelope switches at `error_envelope.go` :199, :312, :379, :403 receive the raw source format, which the new format would not match | Medium | Audit the callers; add the new format where they key on Gemini |
| Cohere `output_dimension` and Titan `dimensions` are dropped on cross-format | Low | Documented gap, same as `task_type`; not in ENG-3023 |
| Prefix gate misses a future embedding family | Low | Falls back to 404, as today |
| Emitting `dimensions` changes OpenAI output | Low | Emitted only when `Dimensions` > 0 |
| Delivery to production needs a develop-to-main promote | High | Requires Edu's approval; not implied here |

## Resolved questions

Settled by the orchestrator against the code before tasks:

1. **Dimensions on Vertex `embedContent` (D9) are dropped from scope.** `Dimensions` > 0 only comes from a `vertex_predict_embed` source, and that source on a Vertex registry is a passthrough, so `VertexEmbedAdapter.EncodeRequest` never sees it. Only the OpenAI encoder (cross-format) and the predict encoder emit it. `VertexEmbedAdapter` is not touched.
2. **Batch placement** is moot for the same reason.
3. **`statistics.token_count`** is optional: summed into usage when present, usage left empty otherwise (same as `/v1/embeddings` to Vertex today, whose `embedContent` response carries no usage).
4. **Error envelopes.** `auth.go`, `proxy_handler.go`, `plugin_runner.go`, `usage_guard.go` and `stream_guard.go` call `EncodeErrorBody(format, …)` with the raw source format, and `EncodeErrorBody` switches on `normalizeFormat`, so `vertex_embed` already falls through to the OpenAI shape. Fix: `errorDialect` maps `vertex_predict_embed` to Gemini, and `EncodeErrorBody` / `NeedsAdaptedError` switch on a narrower `gatewayErrorDialect` that only moves `vertex_predict_embed` to Gemini. Switching them to `errorDialect` would also move `/v1/rerank` (`cohere_rerank`) errors to the Cohere envelope, a change outside this ticket. The stream switches (:312, :379) are chat-only and stay as they are.
5. **Empty `instances` on passthrough.** No gateway-side check: Vertex answers 400 in its own Google envelope, which the gateway relays. The gateway 400 applies to the cross-format branch, where `DecodeRequest` runs.
6. **`statistics.truncated`** is omitted on cross-format responses.
7. **`dimensions` on OpenAI-dialect registries.** `outputDimensionality` is sent as `dimensions` to every registry that speaks the OpenAI embeddings dialect (OpenAI, Azure, openai_compatible, Mistral, …). A provider that cannot honour it answers its own 4xx, which is preferable to silently returning vectors of a different size than the client asked for. Cohere, Bedrock Titan and Vertex `embedContent` drop it.
