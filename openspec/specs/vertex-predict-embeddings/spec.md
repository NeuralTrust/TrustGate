# Specification: vertex-predict-embeddings

## Purpose

Gateway consumers accept embeddings in the native Vertex `:predict` dialect (`instances[].content` in, `predictions[].embeddings.values` out), as sent by the google-genai SDK in Vertex mode. A Vertex registry receives the body as sent; other registries get it translated through the canonical embedding model. Inbound `embedContent` / `batchEmbedContents` and Gemini `/v1beta/models/*` embeddings are out of scope.

## Requirements

### Requirement: Route resolution for Vertex `:predict`

On the Vertex layouts, a `:predict` action on an embedding model MUST resolve to the embeddings capability with wire format `vertex_predict_embed`, and the model MUST be read from the path. Both layouts are in scope, for `v1` and `v1beta1`:

- full regional: `/{consumer}/{v1|v1beta1}/projects/{project}/locations/{location}/publishers/google/models/{model}:predict`
- express: `/{consumer}/{v1|v1beta1}/publishers/google/models/{model}:predict`

Embedding models are those whose name starts with `gemini-embedding-`, `text-embedding-` or `text-multilingual-embedding-`. Any other model MUST answer 404 on `:predict`. The chat actions `generateContent` and `streamGenerateContent` on the same layouts MUST keep their current routing and capability. `/v1beta/models/{model}:predict` MUST be unchanged.

#### Scenario: Full regional layout, embedding model

- GIVEN a consumer `c1` and the path `/c1/v1beta1/projects/p/locations/global/publishers/google/models/gemini-embedding-001:predict`
- WHEN the path is resolved
- THEN the capability is `embeddings`, the wire format is `vertex_predict_embed`, and the model is `gemini-embedding-001`

#### Scenario: Express layout, embedding model

- GIVEN the path `/c1/v1/publishers/google/models/text-multilingual-embedding-002:predict`
- WHEN the path is resolved
- THEN the capability is `embeddings`, the wire format is `vertex_predict_embed`, and the model is `text-multilingual-embedding-002`

#### Scenario: Each embedding prefix matches

- GIVEN models `gemini-embedding-001`, `text-embedding-005` and `text-multilingual-embedding-002`
- WHEN each is posted to `:predict` on either layout
- THEN each resolves to `embeddings` with wire format `vertex_predict_embed`

#### Scenario: Non-embedding model on predict

- GIVEN the path `/c1/v1beta1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:predict`
- WHEN the path is resolved
- THEN the gateway answers 404 in the Gemini error envelope

#### Scenario: Chat actions unchanged

- GIVEN the paths `.../models/gemini-2.5-flash:generateContent` and `.../models/gemini-2.5-flash:streamGenerateContent` on either layout
- WHEN resolved
- THEN they keep the current wire format `gemini` and capability `chat`

#### Scenario: Gemini predict path unchanged

- GIVEN the path `/v1beta/models/gemini-embedding-001:predict`
- WHEN resolved
- THEN the result is identical to the one before this change

### Requirement: Model from path drives routing and policies

For `vertex_predict_embed` the model MUST be taken from the path and stamped into the request body the same way `FormatGemini` does, so that consumer model policies, `sentModel` and cross-format adapters see it. A model disallowed by the consumer's model policy MUST be rejected exactly as it is on `/v1/embeddings`.

#### Scenario: Disallowed embedding model

- GIVEN a consumer whose model policy allows only `text-embedding-005`
- WHEN `:predict` is called for `gemini-embedding-001` on that consumer
- THEN the request is rejected with the same status and policy error as an equivalent disallowed model on `/v1/embeddings`

#### Scenario: Allowed embedding model reaches the upstream

- GIVEN a consumer whose model policy allows `gemini-embedding-001`
- WHEN `:predict` is called for `gemini-embedding-001`
- THEN the request proceeds and the policy sees model `gemini-embedding-001`

### Requirement: Vertex registry forwards the body as received

When the target registry is Vertex and the source format is `vertex_predict_embed`, the request body MUST be forwarded with the same JSON content, except that the gateway-stamped top-level `model` key MUST be removed (key order and whitespace may change). `task_type`, `title`, `autoTruncate` and any other `parameters` fields MUST survive. The upstream URL MUST be the registry's base URL followed by `/{model}:predict`. The Vertex client MUST send `predict` when the body carries `instances`. The upstream response MUST be returned unchanged, including `predictions[].embeddings.values`.

#### Scenario: Passthrough preserves Vertex-only fields

- GIVEN a Vertex registry and the body `{"instances":[{"content":"hi","task_type":"RETRIEVAL_QUERY","title":"t"}],"parameters":{"autoTruncate":true}}` with the model stamped
- WHEN the request is sent upstream
- THEN the outgoing body is JSON-equal to the original body with no `model` key

#### Scenario: Upstream URL

- GIVEN a Vertex registry with base URL `B` and model `gemini-embedding-001`
- WHEN the request is sent
- THEN the target URL is `B/gemini-embedding-001:predict`

#### Scenario: Response passthrough

- GIVEN an upstream response `{"predictions":[{"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":3,"truncated":false}}}]}`
- WHEN returned to the client
- THEN the body is unchanged

### Requirement: Cross-format translation for non-Vertex registries

When the target registry is not Vertex (for example OpenAI, Cohere, Bedrock Titan or Azure), the request MUST be translated through the canonical embedding request: `instances[].content` becomes the ordered input list, and `parameters.outputDimensionality` becomes `dimensions` when it is greater than zero. The upstream response MUST be translated to `predictions[].embeddings.values`, one prediction per input, in input order.

#### Scenario: OpenAI target

- GIVEN an OpenAI registry and the body `{"instances":[{"content":"a"},{"content":"b"}],"parameters":{"outputDimensionality":256}}`
- WHEN translated and sent
- THEN the upstream body has input `["a","b"]` and `dimensions` 256

#### Scenario: Response order

- GIVEN an OpenAI response whose `data` items arrive as indexes 1 then 0
- WHEN translated back
- THEN `predictions` lists the embedding for input 0 first, then input 1, each under `embeddings.values`

#### Scenario: No dimensions

- GIVEN a body without `parameters.outputDimensionality`
- WHEN translated to OpenAI
- THEN the upstream body has no `dimensions` field

### Requirement: Invalid body is a 400 in the Google envelope

When the request is translated for a non-Vertex registry, a `vertex_predict_embed` request whose `instances` is missing, empty, or whose items carry no text content MUST be rejected with 400 before any upstream call. The error MUST use the Gemini/Google error envelope. On a Vertex registry the body is forwarded as received and Vertex's own 400 (already in the Google envelope) is relayed.

#### Scenario: Missing instances

- GIVEN a consumer bound to a non-Vertex embeddings registry and a `:predict` body `{"parameters":{}}`
- WHEN sent to the gateway
- THEN the gateway answers 400 in the Google error envelope and makes no upstream call

#### Scenario: Empty instances

- GIVEN a body `{"instances":[]}`
- WHEN sent
- THEN 400 in the Google error envelope, no upstream call

#### Scenario: Instance without text

- GIVEN a body `{"instances":[{"task_type":"RETRIEVAL_QUERY"}]}`
- WHEN sent
- THEN 400 in the Google error envelope, no upstream call

#### Scenario: Vertex registry relays the upstream 400

- GIVEN a consumer bound to a Vertex registry and a body `{"instances":[]}`
- WHEN sent
- THEN the request reaches Vertex and its 400 is returned to the client

### Requirement: Usage accounting from Vertex statistics

When the upstream returns `predictions[].embeddings.statistics.token_count`, the gateway MUST sum those counts across predictions into the request usage. When the field is absent, usage MUST be accounted as it is for `/v1/embeddings` for the same upstream.

#### Scenario: Two predictions

- GIVEN an upstream response with two predictions whose `token_count` values are 3 and 5
- WHEN usage is recorded
- THEN the usage total is 8

#### Scenario: Missing statistics

- GIVEN an upstream response without `statistics`
- WHEN usage is recorded
- THEN usage is accounted as on `/v1/embeddings` for the same upstream, and no error is raised

### Requirement: Gateway-generated errors use the Google envelope

Errors the gateway itself encodes for the `vertex_predict_embed` route (authentication, usage limits, invalid payload, upstream failures) MUST use the Gemini/Google error envelope, not the OpenAI envelope. Policy plugins keep their own rejection body, which is the same on every route.

#### Scenario: Invalid payload envelope

- GIVEN a non-Vertex registry and a `:predict` body with no instances
- WHEN the request is rejected
- THEN the error body follows the Google error envelope

#### Scenario: Policy rejection keeps the plugin body

- GIVEN a model allowlist that excludes the path model
- WHEN the request is rejected
- THEN the status is 403 with the `model_not_allowed` body the allowlist returns on every route, and no upstream call is made

### Requirement: Observability and guardrail parity with `/v1/embeddings`

For the same request, `:predict` MUST produce the same traces, the same telemetry with capability `embeddings`, and the same guardrail behaviour as `/v1/embeddings`. Embedding inputs MUST be carried in the same canonical shape, so inspection coverage is unchanged and no new inspection gap is added.

#### Scenario: Telemetry capability

- GIVEN a successful `:predict` on an embedding model
- WHEN telemetry is emitted
- THEN the capability is `embeddings` and the trace attributes match those of an equivalent `/v1/embeddings` request

#### Scenario: Guardrail parity

- GIVEN a guardrail that applies to embedding inputs on `/v1/embeddings`
- WHEN the same input is sent through `:predict`
- THEN the guardrail outcome is the same as on `/v1/embeddings`

### Requirement: Dimensions encoding

`CanonicalEmbeddingRequest` MUST carry `Dimensions`. Encoders MUST emit it only when it is greater than zero: OpenAI as `dimensions` and Vertex `predict` as `parameters.outputDimensionality`. Other encoders (Vertex `embedContent`, Cohere, Bedrock Titan) drop it. When it is zero, existing outbound bodies MUST be unchanged.

#### Scenario: Zero dimensions unchanged

- GIVEN an existing `/v1/embeddings` request with no dimensions
- WHEN encoded to OpenAI
- THEN the body is byte-identical to the one produced before this change

#### Scenario: Dimensions on Vertex predict

- GIVEN canonical dimensions 768 targeting Vertex `predict`
- WHEN encoded
- THEN `parameters.outputDimensionality` is 768
