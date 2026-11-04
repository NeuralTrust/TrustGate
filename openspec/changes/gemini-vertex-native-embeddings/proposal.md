# Proposal: Native Gemini and Vertex embeddings on gateway consumers (ENG-1624)

## Intent

Clients on the Google SDK must rewrite embeddings calls to OpenAI `/v1/embeddings`. Today `/v1beta/models/{m}:embedContent` is misrouted as chat, and Vertex embeddings paths return 404.

## Scope

### In Scope
- Gemini `/{consumer}/v1beta/models/{model}:embedContent|:batchEmbedContents`.
- Vertex regional and express layouts: `:embedContent|:batchEmbedContents`.
- Resolver: only generate/streamGenerateContent (chat) and the two embed actions route. `countTokens`, `predict`, `rawPredict` and requests with no action return 404.
- Model from the path, stamped into the body so `modelallowlist` and the targets see it.
- Single or batch response shape follows the inbound action.
- `taskType`, `title` and `outputDimensionality` carried where the target supports them, dropped explicitly elsewhere.
- README section 7 lists the paths.
- **Cuttable phase (Edu decides at the tasks gate):** Vertex `:predict` (`vertex_predict_embed`): `instances[].content|task_type|title`, `parameters.outputDimensionality`. The response is `predictions[].embeddings.values`, plus `statistics.token_count` when the target reports usage. This phase also closes ENG-3023.

### Out of Scope
- Native Google auth (stays `X-AG-API-Key`), an AI Studio `EmbeddingsClient`, Bedrock native embeddings, `countTokens` and `rawPredict`.
- Decoding `dimensions` on `/v1/embeddings`, because it would change live traffic.
- Fixing the nil embeddings usage in the OpenAI, Cohere and Vertex decoders (pre-existing, follow-up).

## Decisions

| # | Decision |
|---|---|
| D1 | New source formats: `gemini_embed` (embedContent) and `gemini_batch_embed` (batchEmbedContents), shared by the Gemini and Vertex paths. Always re-encoded to the target. The `vertex_embed` target adapter and the Vertex client are unchanged. |
| D2 | `modelRefFromRequest` and `applyIntentToBody` treat the new formats like `FormatGemini`. The path model wins over per-request `model`, and the decoder strips the `models/` prefix. |
| D3 | One `content` is one input: its parts are joined. This applies only in the new decoder. |
| D4 | The canonical request gains `TaskType` (Gemini vocabulary), `Titles` (aligned to inputs) and `Dimensions`. |
| D5 | Vertex gets all three. Cohere `input_type` comes from taskType: RETRIEVAL_QUERY→search_query, RETRIEVAL_DOCUMENT→search_document, CLASSIFICATION→classification, CLUSTERING→clustering; other values fall back to the default. OpenAI and Azure get `dimensions`, gated by provider rather than by the shared `openai_embeddings` format. Mistral, openai_compatible, other OpenAI-wire providers, Titan and Cohere drop it. |
| D6 | A batch that mixes `taskType` or `outputDimensionality` across requests returns 400. |
| D7 | `errorDialect`, `IsChatRequest` and `SupportedSourceFormat` list the new formats. |
| D8 | Guardrails, policies, traces and cost match `/v1/embeddings`: guardrails skip, and the existing usage path applies. |
| D9 | OpenAPI is changed only if a hand-written native-route pattern exists. Any `make docs` run goes in its own commit. |

## Capabilities

### New Capabilities
- `native-embeddings-routing`: resolver actions, the 404 for others, and the path model with policy enforcement.
- `native-embeddings-mapping`: request and response mapping, shape fidelity, and option carry/drop per target.

### Modified Capabilities
None (no existing spec covers proxy routing).

## Affected Areas

| Area | Impact |
|------|--------|
| `pkg/api/resolver/proxy_path_resolver.go` | Modified: action routing (Gemini and Vertex) |
| `pkg/infra/providers/adapter/format.go`, `registry.go`, `error_envelope.go` | Modified: new formats |
| `pkg/infra/providers/adapter/gemini_embed_adapter.go` (+ `vertex_predict_embed_adapter.go`) | New |
| `pkg/infra/providers/adapter/cohere_embed_adapter.go`, `vertex_embed_adapter.go` | Modified: canonical fields, encode mapping |
| `pkg/app/proxy/routing.go`, `provider.go` | Modified: path model; provider-gated `dimensions` |
| `tests/functional/`, `README.md` | New tests, docs |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Upstream Vertex rejects `:embedContent` for gemini-embedding-001 (the docs show `:predict`) | Med | Verify in DEV; this is independent of the inbound change |
| A client relying on `:countTokens` or action-less paths falling through to chat | Low | Those calls were wrong already; covered by resolver tests |
| `dimensions` sent to a provider that rejects it | Low | Gated per provider, with tests |

## Rollback Plan

Revert the PR. The new formats are reachable only through the new routes, and `/v1/embeddings` and the chat paths keep their behaviour.

## Dependencies

- ENG-1436 and ENG-2825 (Vertex native and express paths), both already in `develop`.

## Deviations

- Base is `develop`, not `main` as the issue says. `develop` holds ENG-1436 and ENG-2825, and feature work goes there.

## Success Criteria

- [ ] All QA checklist items in ENG-1624 pass (unit + functional).
- [ ] `/v1/embeddings` and the Gemini/Vertex chat tests are unchanged and green.
- [ ] A disallowed path model is rejected by the consumer policy.
