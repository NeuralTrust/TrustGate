# Delta for native-embeddings-mapping

New capability (ENG-1624). Covers how `gemini_embed` and `gemini_batch_embed` bodies map to and from the canonical embedding model and to every embeddings target (Vertex `vertex_embed`, OpenAI-wire `openai_embeddings`, Cohere `cohere_embed`, Bedrock `bedrock_titan_embed`). Gemini and Vertex `embedContent`/`batchEmbedContents` share one wire shape:

- `embedContent` request: `{"model"?, "content":{"parts":[{"text":…}]}, "taskType"?, "title"?, "outputDimensionality"?}`; response `{"embedding":{"values":[…]}}`
- `batchEmbedContents` request: `{"requests":[<embedContent request>, …]}`; response `{"embeddings":[{"values":[…]}, …]}`

## ADDED Requirements

### Requirement: Request decoding

The `gemini_embed` decoder MUST read one `content`; the `gemini_batch_embed` decoder MUST read `requests[]`. Each content MUST produce exactly one canonical input, built by joining the text of its parts in order with `"\n"`. Non-text parts MUST be rejected with 400 (the targets embed text only). An empty input list (no content, no requests, or contents with no text) MUST be rejected with 400. The model is taken from the path (native-embeddings-routing).

#### Scenario: Multi-part content gives one vector

- GIVEN an `embedContent` body whose content has two text parts `"a"` and `"b"`
- WHEN it is sent to an OpenAI registry
- THEN the upstream body has one input `"a\nb"`
- AND the client receives one `embedding`

#### Scenario: Batch of three

- GIVEN a `batchEmbedContents` body with three requests
- THEN the target receives three inputs in the same order
- AND the client receives three `embeddings` in the same order

#### Scenario: Inline data part

- GIVEN a content part with `inlineData`
- THEN the gateway returns 400 in the Gemini error envelope and makes no upstream call

### Requirement: Response shape follows the inbound action

The response MUST be encoded in the shape of the action the client called, independent of how many vectors the target returned or which upstream action the target used: `gemini_embed` → `{"embedding":{"values":[…]}}`; `gemini_batch_embed` → `{"embeddings":[{"values":[…]}, …]}`.

#### Scenario: embedContent against a Vertex registry

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-embedding-001:embedContent` with a Vertex registry
- THEN the response is `{"embedding":{"values":[…]}}`

#### Scenario: Batch of one keeps the batch shape

- WHEN the client sends `:batchEmbedContents` with one request
- THEN the response is `{"embeddings":[{"values":[…]}]}` with exactly one item
- AND this holds for Vertex, OpenAI, Cohere and Titan registries

#### Scenario: Cross-format to an OpenAI registry

- GIVEN a consumer with an OpenAI registry serving `text-embedding-3-small`
- WHEN the client sends a Gemini-format `:embedContent` with path model `text-embedding-3-small`
- THEN the upstream receives `{"model":"text-embedding-3-small","input":[…]}` (OpenAI shape)
- AND the client receives `{"embedding":{"values":[…]}}`

### Requirement: Task type, title and output dimensionality

The canonical embedding request MUST carry `taskType` (Gemini vocabulary), per-input titles, and output dimensionality from the new decoders. Within a batch, every request MUST share the same `taskType` and the same `outputDimensionality` (absent counts as a value); otherwise the gateway MUST return 400 without calling an upstream. Titles MAY differ per request. Target mapping:

| Target | taskType | title | outputDimensionality |
|---|---|---|---|
| Vertex (`vertex_embed`) | `taskType` on each request | `title` on its request | `outputDimensionality` on each request |
| Cohere (`cohere_embed`) | `input_type`: RETRIEVAL_QUERY→`search_query`, RETRIEVAL_DOCUMENT→`search_document`, CLASSIFICATION→`classification`, CLUSTERING→`clustering`; other or absent → current default `search_document` | dropped | dropped |
| OpenAI and Azure providers | dropped | dropped | `dimensions` |
| Other OpenAI-wire providers (Mistral, openai_compatible, DigitalOcean, …) | dropped | dropped | dropped |
| Bedrock Titan | dropped | dropped | dropped |

Dropped fields MUST NOT appear in the upstream body.

#### Scenario: Vertex keeps all three

- GIVEN `{"content":…, "taskType":"RETRIEVAL_DOCUMENT", "title":"Doc", "outputDimensionality":256}` on `:embedContent`
- WHEN routed to a Vertex registry
- THEN the upstream Vertex body carries `taskType`, `title` and `outputDimensionality` with those values

#### Scenario: Cohere input_type from taskType

- GIVEN `taskType` `RETRIEVAL_QUERY`
- WHEN routed to a Cohere registry
- THEN the upstream body has `"input_type":"search_query"` and no `taskType`, `title` or dimensionality field

#### Scenario: Cohere with an unmapped taskType

- GIVEN `taskType` `SEMANTIC_SIMILARITY`
- WHEN routed to a Cohere registry
- THEN the upstream body has `"input_type":"search_document"`

#### Scenario: OpenAI receives dimensions

- GIVEN `outputDimensionality` 256
- WHEN routed to an OpenAI or Azure registry
- THEN the upstream body has `"dimensions":256`

#### Scenario: Mistral drops dimensions

- GIVEN `outputDimensionality` 256
- WHEN routed to a Mistral or openai_compatible registry
- THEN the upstream body has no `dimensions`

#### Scenario: Titan drops everything

- GIVEN `taskType`, `title` and `outputDimensionality`
- WHEN routed to a Bedrock Titan registry
- THEN the upstream body has only the Titan input fields

#### Scenario: Mixed taskType in a batch

- GIVEN a `batchEmbedContents` whose requests have `taskType` `RETRIEVAL_QUERY` and `RETRIEVAL_DOCUMENT`
- THEN the gateway returns 400 in the Gemini error envelope and makes no upstream call

#### Scenario: Mixed outputDimensionality in a batch

- GIVEN requests with `outputDimensionality` 256 and absent
- THEN the gateway returns 400

### Requirement: Gemini error envelope

Every gateway-generated or upstream error on `gemini_embed` and `gemini_batch_embed` routes MUST be returned in the Gemini error envelope `{"error":{"code":…, "message":…, "status":…}}`, the same as Gemini chat routes, with credentials redacted.

#### Scenario: Upstream 400 from an OpenAI registry

- GIVEN the OpenAI upstream returns 400 with an OpenAI error body
- THEN the client receives 400 with a Gemini error object carrying the upstream message

#### Scenario: Gateway 400 on invalid JSON

- WHEN the body is not valid JSON
- THEN the client receives 400 in the Gemini error envelope

### Requirement: Existing adapters unchanged for existing sources

The `vertex_embed` target encoder MUST keep choosing `embedContent` vs `batchEmbedContents` by input count, as the Vertex client's upstream action selection expects. The OpenAI, Cohere, Titan and Vertex adapters MUST produce the same bodies as before for requests coming from `/v1/embeddings` (the new canonical fields are empty there).

#### Scenario: OpenAI client batch of one to Vertex

- WHEN `/v1/embeddings` sends `{"input":["x"]}` to a Vertex registry
- THEN the upstream call is `:embedContent` with the same body as before this change

## ADDED Requirements — Phase: optional (vertex :predict)

Delivered only if kept at the tasks gate. Closes ENG-3023.

### Requirement: Vertex :predict embeddings route

On both Vertex layouts, `:predict` MUST resolve to `CapabilityEmbeddings` with source format `vertex_predict_embed` and the model from the path. On the Gemini path, `:predict` stays 404.

#### Scenario: BV request

- GIVEN a consumer with a Vertex registry serving `gemini-embedding-001`
- WHEN the client sends `POST /{consumer}/v1beta1/projects/bv-juia-uat/locations/global/publishers/google/models/gemini-embedding-001:predict` with `{"instances":[{"content":"hi"}]}`
- THEN the gateway returns 200 with `{"predictions":[{"embeddings":{"values":[…]}}]}`

#### Scenario: Gemini path predict

- WHEN the client sends `POST /{consumer}/v1beta/models/gemini-embedding-001:predict`
- THEN the gateway returns 404

### Requirement: :predict mapping

The decoder MUST map each `instances[i].content` (string) to one canonical input, `instances[i].task_type` to taskType, `instances[i].title` to the input title, and `parameters.outputDimensionality` to output dimensionality; the same uniformity rule and target mapping table as the embedContent formats apply. `parameters.autoTruncate` MUST be dropped. The response MUST be `{"predictions":[{"embeddings":{"values":[…]}}, …]}` with one prediction per instance, in order; when the target reports per-input token counts, `embeddings.statistics.token_count` MUST carry them, otherwise `statistics` is omitted.

#### Scenario: outputDimensionality to Vertex

- GIVEN `parameters.outputDimensionality` 768
- WHEN routed to a Vertex registry
- THEN the upstream body carries `outputDimensionality` 768

#### Scenario: Cross-format to OpenAI

- GIVEN two instances
- WHEN routed to an OpenAI registry
- THEN the client receives two predictions in order

#### Scenario: Errors

- WHEN the upstream fails
- THEN the client receives the Gemini error envelope

#### Scenario: Chat Vertex routes unchanged

- WHEN the client sends `:generateContent` on the same Vertex layout
- THEN it still routes to chat
