# Proposal: Native Vertex `:predict` embeddings on consumers (ENG-3023)

Linear: ENG-3023, "Native Vertex `:predict` embeddings request returns 404 on gateway consumer".
Repo: TrustGate (Go). Base branch: `develop`.

## Intent

The google-genai SDK in Vertex mode calls `POST /{consumer}/v1beta1/projects/{project}/locations/global/publishers/google/models/gemini-embedding-001:predict` for embeddings. The gateway answers 404 because `pkg/api/resolver/proxy_path_resolver.go` accepts only the Vertex chat actions `generateContent` and `streamGenerateContent` on that layout. Clients work around it by calling `/{consumer}/v1/embeddings`. This change makes the native `:predict` path resolve to the embeddings capability, so the SDK works unchanged and the request goes through the same consumer policies, guardrails, traces and cost as `/v1/embeddings`.

## Scope

### In scope

- Resolver: on the Vertex layout, both `/{consumer}/{v1|v1beta1}/projects/*/locations/*/publishers/google/models/{model}:predict` and the express form `/{v1|v1beta1}/publishers/google/models/{model}:predict`, a `:predict` on an embedding model resolves to `CapabilityEmbeddings`. The model is read from the path. Embedding models are matched by prefix: `gemini-embedding-*`, `text-embedding-*`, `text-multilingual-embedding-*`.
- `:predict` on any other model keeps returning 404. Vertex chat actions keep their current routing. `/v1beta/models/{m}:predict` is unchanged.
- A new source-only wire format `vertex_predict_embed` with its own adapter. Inbound, `instances[].content` becomes the canonical inputs and `parameters.outputDimensionality` becomes the canonical dimensions. Outbound, canonical embeddings are returned as `predictions[].embeddings.values`, and `statistics.token_count` is summed into usage.
- `Dimensions int` on `CanonicalEmbeddingRequest`. Encoders that support it emit it when it is set: OpenAI `dimensions`, Vertex `embedContent` `outputDimensionality`, and Vertex `predict` `parameters.outputDimensionality`.
- Routing: for the new format the model comes from the path (`adapter.GeminiModelFromPath`). It is stamped into the body the same way `FormatGemini` does, so model policies, `sentModel` and cross-format adapters see it.
- Target selection: a Vertex registry with source `vertex_predict_embed` targets `vertex_predict_embed`, and the body is forwarded byte-exact, so `task_type`, `title` and `autoTruncate` survive. The Vertex client sends `predict` when the body has `instances`, and strips the stamped `model` key before sending. Other registries (OpenAI, Cohere, Bedrock Titan, Azure) go through canonical cross-format translation.
- Plumbing: register the adapter, add it to `SupportedSourceFormat`, to the non-chat list in `IsChatRequest`, and map its errors to the Gemini error envelope.
- Tests: resolver table tests (match, and 404 for non-embedding models and other actions), adapter round-trip tests, a routing test that checks policies see the path model, a Vertex client test for the `predict` URL and the `model` strip, and a cross-format test to an OpenAI target.

### Out of scope (ENG-1624)

- Inbound `embedContent` and `batchEmbedContents`.
- Gemini `/v1beta/models/*` embeddings.
- `task_type` and `title` mapping across providers. They survive only on Vertex passthrough and are dropped on cross-format hops.
- Decoding OpenAI `dimensions` on `/v1/embeddings`.

## Approach

Chosen: a dedicated source format, `vertex_predict_embed`, with its own adapter.

1. `VertexPredictEmbedAdapter` (`adapter.FormatVertexPredictEmbed`). Decode instances into `CanonicalEmbeddingRequest{Model, Inputs, Dimensions}`. Encode canonical into instances and parameters. Decode predictions into canonical embeddings and usage. Encode canonical into predictions. Empty instances, or instances with no text, are a request decode error and return 400.
2. Canonical output reuses the `Metadata["embedding"]` shape, so consumer-side inspection and accounting behave exactly as on `/v1/embeddings`.
3. Resolver: `matchesVertexLayout` returns the action. Chat actions go to `FormatGemini` and `CapabilityChat`, as today. `predict` with an embedding-model prefix goes to `FormatVertexPredictEmbed` and `CapabilityEmbeddings`. Anything else returns `ErrUnknownProxyPath`, which is the 404.
4. Pass-through on the same Vertex format keeps the upstream body exact, so Vertex-only fields are not lost.

Rejected alternatives:

- (A) Reuse `vertex_embed` as the source format. That format is also the upstream wire for `/v1/embeddings` and has the `embedContent` shape. Decoding a `:predict` body with it yields zero inputs.
- (B) Translate `:predict` into upstream `embedContent`. This is lossy, and multi-instance calls depend on Vertex `batchEmbedContents` support, which is unverified.

Parity note: TrustGuard's LLM inspection reads canonical Messages, so embedding inputs are not inspected on `/v1/embeddings` today either. The new adapter uses the same canonical shape, so behaviour matches exactly. This change adds no new gap and no new coverage.

## Affected Areas

| Area | Impact |
|---|---|
| `pkg/api/resolver/proxy_path_resolver.go` | Modified: `matchesVertexLayout` returns the action, and the `predict` branch is added |
| `pkg/infra/providers/adapter/` (new `vertex_predict_embed` adapter, canonical embedding request, format registry, `SupportedSourceFormat`) | Modified and new |
| `pkg/infra/providers/adapter/` OpenAI and Vertex embedding encoders | Modified: emit `Dimensions` when set |
| Routing and body-stamping path (`modelRefFromRequest`, `applyIntentToBody`) | Modified |
| Vertex provider client (`embeddingsAction`, `model` strip) | Modified |
| `IsChatRequest` and error dialect mapping | Modified |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| The stamped `model` key reaches the `:predict` body, and Vertex rejects it as an unknown field | Medium | Strip it in the Vertex client, with a test on the outgoing body |
| The prefix gate misses a future embedding model family | Low | It returns 404 as today; add the prefix when the family ships |
| Emitting `dimensions` changes OpenAI output | Low | Emitted only when `Dimensions` is greater than zero |
| Delivery to production needs a develop-to-main promote | High | Requires Edu's approval; no promote is implied by this proposal |

## Rollback Plan

The change is stateless. There are no schema, config or migration changes. Reverting the PR returns `:predict` to 404, and clients fall back to `/v1/embeddings`, which it already uses.

## Dependencies

- Edu's approval for the develop-to-main promotion before production clients can use it.
- A live check on DEV with a Vertex registry and a key. Not prod.
- No dependency on other open changes in this repo.

## Success Criteria

- [ ] `:predict` on an embedding model returns 200 with `predictions[].embeddings.values` through the gateway, on both layouts and for both `v1` and `v1beta1`.
- [ ] `:predict` on a non-embedding model still returns 404.
- [ ] Consumer model policies, guardrails, traces and cost match `/v1/embeddings` for the same request.
- [ ] The reported request returns 200 with embeddings, verified on DEV before any promote.
- [ ] Vertex chat routes and `/v1beta/models/{m}:predict` are unchanged, shown by the existing tests.
- [ ] `make test`, `go vet -tags functional`, lint and verifier are all green.
