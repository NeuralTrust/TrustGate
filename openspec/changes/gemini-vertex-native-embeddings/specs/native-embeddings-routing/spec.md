# Delta for native-embeddings-routing

New capability (ENG-1624). Covers how the proxy path resolver classifies native Gemini and Vertex model paths, where the model comes from, and how consumer policies see it. `{consumer}` is the consumer slug; `{v}` is `v1` or `v1beta1`. Project and location segments are wildcards; the upstream URL always comes from the registry.

Path families:

- **Gemini**: `/{consumer}/v1beta/models/{model}:{action}`
- **Vertex regional**: `/{consumer}/{v}/projects/{p}/locations/{l}/publishers/google/models/{model}:{action}`
- **Vertex express**: `/{consumer}/{v}/publishers/google/models/{model}:{action}`

## ADDED Requirements

### Requirement: Embeddings actions resolve to the embeddings capability

On every path family, `:embedContent` MUST resolve to `CapabilityEmbeddings` with source format `gemini_embed`, and `:batchEmbedContents` MUST resolve to `CapabilityEmbeddings` with source format `gemini_batch_embed`. Only `POST` is allowed on these routes.

#### Scenario: Gemini embedContent

- GIVEN a consumer with a registry that serves embeddings
- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-embedding-001:embedContent`
- THEN the route has capability embeddings and source format `gemini_embed`

#### Scenario: Gemini batchEmbedContents

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-embedding-001:batchEmbedContents`
- THEN the route has capability embeddings and source format `gemini_batch_embed`

#### Scenario: Vertex regional path with any project and region

- WHEN the client sends `POST /{consumer}/v1/projects/x/locations/y/publishers/google/models/gemini-embedding-001:embedContent`
- THEN the route has capability embeddings and source format `gemini_embed`
- AND the upstream URL uses the registry's project, location and base URL, never `x` or `y`

#### Scenario: Vertex v1beta1 batch path

- WHEN the client sends `POST /{consumer}/v1beta1/projects/p/locations/global/publishers/google/models/text-embedding-005:batchEmbedContents`
- THEN the route has capability embeddings and source format `gemini_batch_embed`

#### Scenario: Vertex express-mode path

- WHEN the client sends `POST /{consumer}/v1/publishers/google/models/gemini-embedding-001:embedContent`
- THEN the route has capability embeddings and source format `gemini_embed`

#### Scenario: Wrong method

- WHEN the client sends `GET /{consumer}/v1beta/models/gemini-embedding-001:embedContent`
- THEN the gateway answers 405 with `Allow: POST`

### Requirement: Only known actions route on native model paths

On every path family, only `generateContent` and `streamGenerateContent` (chat) and `embedContent` and `batchEmbedContents` (embeddings) MUST route. Any other action (`countTokens`, `rawPredict`, `streamRawPredict`, an unknown suffix) and a model segment with no action MUST return 404 from the gateway without calling an upstream. `predict` returns 404 unless the optional `:predict` phase is delivered (see native-embeddings-mapping).

(Previously: every `/v1beta/models/{model}…` path, with any action or none, routed to Gemini chat; Vertex already returned 404 for non-chat actions.)

#### Scenario: countTokens on the Gemini path

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-2.5-flash:countTokens`
- THEN the gateway returns 404
- AND no upstream request is made

#### Scenario: countTokens on the Vertex path

- WHEN the client sends `POST /{consumer}/v1/projects/p/locations/l/publishers/google/models/gemini-2.5-flash:countTokens`
- THEN the gateway returns 404

#### Scenario: No action on the Gemini path

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-2.5-flash`
- THEN the gateway returns 404

#### Scenario: No action on the Vertex path

- WHEN the client sends `POST /{consumer}/v1/publishers/google/models/gemini-2.5-flash`
- THEN the gateway returns 404

#### Scenario: Unknown action is part of the model id

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-2.5-flash:batchGenerateContent`
- THEN the gateway returns 404

### Requirement: Native chat routes keep their behaviour

`generateContent` and `streamGenerateContent` on all three path families MUST keep resolving to `CapabilityChat` with source format `google`, with the model from the path, exactly as before this change. Query strings (`?alt=sse`, `?key=`) MUST NOT affect route resolution.

#### Scenario: Gemini streamGenerateContent with alt=sse

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse`
- THEN the route has capability chat and source format `google`, and the response streams

#### Scenario: Vertex generateContent

- WHEN the client sends `POST /{consumer}/v1/projects/p/locations/l/publishers/google/models/gemini-2.5-flash:generateContent`
- THEN the route has capability chat and source format `google`

#### Scenario: Model ids containing ':'

- WHEN the client sends `POST /{consumer}/v1beta/models/eu.amazon.nova-lite-v1:0:generateContent`
- THEN the model is `eu.amazon.nova-lite-v1:0` and the action is `generateContent`

### Requirement: Model comes from the path

For `gemini_embed` and `gemini_batch_embed` the routing model reference MUST be the model segment of the path, parsed with the same routing syntax as the Gemini chat path (short model, `registry/model`, `auto`, `pool:x`). A short model MUST be stamped into the top-level `model` of the request body before plugins run, so policies and target encoders see it. Any `model` in the body (top-level or per request, with or without `models/`) MUST NOT override the path model.

#### Scenario: Path model wins over the body

- GIVEN a `batchEmbedContents` body whose requests carry `"model":"models/text-embedding-004"`
- WHEN the path model is `gemini-embedding-001`
- THEN routing and the upstream request use `gemini-embedding-001`

#### Scenario: Qualified model in the path

- WHEN the path model is `vertex-prod/gemini-embedding-001`
- THEN the request is pinned to the `vertex-prod` registry with model `gemini-embedding-001`

### Requirement: Consumer model policies enforce the path model

The consumer's model allowlist policy MUST evaluate the path model for the new formats, the same way it evaluates the body `model` on `/v1/embeddings`.

#### Scenario: Disallowed model in the path

- GIVEN a consumer whose model allowlist allows only `text-embedding-3-small` and blocks others
- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-embedding-001:embedContent`
- THEN the gateway rejects the request with the same status and reason as a disallowed model on `/v1/embeddings`
- AND no upstream request is made

#### Scenario: Allowed model in the path

- GIVEN the allowlist allows `gemini-embedding-001`
- WHEN the client sends the same request
- THEN it is forwarded

### Requirement: Embeddings parity for policies, guardrails, traces and cost

Requests on the new routes MUST go through the same embeddings pipeline as `/v1/embeddings`: capability filtering of candidate registries (registries without embeddings support are excluded; a pinned incapable registry is terminal), the same policy and guardrail stages (guardrails that skip embeddings today keep skipping), and the same trace, metric and cost events with capability embeddings and the resolved model.

#### Scenario: Registry without embeddings support

- GIVEN a consumer whose only registry is Google AI Studio (no embeddings client)
- WHEN the client sends a Gemini `:embedContent` request
- THEN the gateway answers the same unsupported-capability error as `/v1/embeddings` for that consumer, in the Gemini error envelope

#### Scenario: Trace and cost event

- WHEN a Gemini `:embedContent` request succeeds against a Vertex registry
- THEN the emitted trace/metric event has capability embeddings, the path model and the registry, with the same usage/cost fields that a `/v1/embeddings` call to the same registry produces

### Requirement: /v1/embeddings unchanged

`POST /{consumer}/v1/embeddings` MUST keep source format `openai_embeddings`, the same decoding (no new fields such as `dimensions` are read) and the same responses for every target.

#### Scenario: OpenAI client to Vertex registry

- WHEN the client sends `{"model":"gemini-embedding-001","input":"hi","dimensions":256}` to `/v1/embeddings` with a Vertex registry
- THEN the upstream Vertex body is identical to the one sent before this change (no `outputDimensionality`)
