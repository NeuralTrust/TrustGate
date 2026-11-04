# Exploration: native Gemini and Vertex embeddings on gateway consumers (ENG-1624)

## Current state (origin/develop 7c61bbce)

- Resolver `pkg/api/resolver/proxy_path_resolver.go` `formatForRoute`: `/v1beta/models/{model}:*` -> `FormatGemini, CapabilityChat` for any action in `geminiMethods` (incl. `embedContent`, `batchEmbedContents`, `countTokens`, `predict`), and with no action at all. Vertex layouts (regional + express) accept only `vertexChatActions` (generate/streamGenerateContent); anything else -> `ErrUnknownProxyPath` -> 404.
- `c.Path()` excludes the query string, so `?alt=sse` / `?key=` never reach the resolver.
- Embeddings flow: `request_target.go` copies SourceFormat/Capability -> `routing.go` capability filter (`providers.SupportsCapability`; Google AI Studio has no embeddings) -> `provider.go` `ResolveTargetFormatForCapability` (Cohere->cohere_embed, Vertex->vertex_embed, Bedrock->bedrock_titan_embed, rest->openai_embeddings) -> `AdaptEmbeddingRequest` (passthrough when source==target) -> `EmbeddingsClient.Embeddings` -> `AdaptEmbeddingResponse` (target decode -> source encode).
- Model from path only for `FormatGemini`: `modelRefFromRequest` (routing.go:358) and `applyIntentToBody` (routing.go:407, stamps short model). `modelallowlist` reads `ExtractModel(body)`, so the stamp is what enforces policy.
- `errorDialect` (`error_envelope.go:166`) maps FormatGemini/FormatVertexEmbed to the Gemini error object. `IsChatRequest` lists non-chat formats when capability is empty.
- Guardrails skip embeddings today (`pluginutil.SkipNonChatRoute`, capability != chat). Parity = same skip.
- Usage: by code reading, OpenAI/Cohere/Vertex embed decoders do not set `CanonicalResponse.Usage` (only Titan). Pre-existing; parity only, follow-up candidate.

## Canonical model and adapters

- `CanonicalEmbeddingRequest{Model, Inputs, Tokens, InputType}`; `CanonicalEmbeddingResponse{Model, Embeddings, Usage}` (`cohere_embed_adapter.go`).
- `VertexEmbedAdapter` (target for Vertex): decode flattens every part into its own input (a multi-part content would yield N vectors), ignores model/taskType/title/outputDimensionality; encode picks single vs batch by count. `vertex/client.go` `embeddingsAction` probes `requests` to choose the upstream action, and `resolveModel` prefers config model, then default, then body.
- `vertex_embed` is not used as an inbound source anywhere today (no route produces it); `SupportedSourceFormat` has no callers outside its definition.
- No adapter maps OpenAI `dimensions`; `input_type` only Cohere->Cohere; Cohere encode defaults `search_document`.
- `openai_embeddings` target is shared by OpenAI, Azure, openai_compatible, Mistral, DigitalOcean, ... -> `dimensions` must be gated per provider.

## What real Google SDK clients send (google-genai python, main)

- Gemini Developer API mode: always `{model}:batchEmbedContents`, body `requests[].{model, content, taskType, title, outputDimensionality}`; response `embeddings[].values`.
- Vertex mode: `{model}:predict` by default (body `instances[].{content, task_type, title}`, `parameters.{outputDimensionality, autoTruncate}`; response `predictions[].embeddings.{values, statistics.{token_count, truncated}}`); `{model}:embedContent` only for models gated by `t_is_vertex_embed_content_model` (newer models). Vertex docs show `:predict` for gemini-embedding-001.
- Consequence: Vertex `:embedContent` alone does not fix the BV traffic in ENG-3023 (`:predict`). `:predict` is offered as a separate, cuttable phase for the approval gate.
- Risk to verify in DEV: the outbound Vertex client calls `:embedContent`/`:batchEmbedContents` upstream; Vertex documents `:predict` for gemini-embedding-001. If Vertex rejects those actions, the Vertex-registry QA items fail independently of this change.

## Approaches

| Approach | Pros | Cons |
|---|---|---|
| A. Reuse `vertex_embed` as source | no new format | ambiguous (also target + error dialect); passthrough would forward a stamped `model`; shape by count |
| B. New source formats per inbound action (`gemini_embed`, `gemini_batch_embed`, optional `vertex_predict_embed`) with their own adapters, always re-encoded to the target | stateless adapters keep single/batch shape by format; lossless canonical; `vertex_embed` target untouched | more formats to list in IsChatRequest/errorDialect/SupportedSourceFormat |

Recommendation: B.
