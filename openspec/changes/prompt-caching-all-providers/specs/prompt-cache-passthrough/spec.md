# Delta for prompt-cache-passthrough

New capability. Contract: ENG-1618 scope block 3. Response-side re-encoding for Groq and OpenRouter is kept (`x_groq`, `provider` metadata, SSE comments).

## ADDED Requirements

### Requirement: Mistral carries the cache key

A request routed to Mistral MUST send `prompt_cache_key` when the client supplied one (OpenAI Chat `prompt_cache_key`, Responses `prompt_cache_key`), buffered and streaming. Tool-ID rewriting MUST keep working.

#### Scenario: OpenAI client to Mistral

- GIVEN a Chat request with `prompt_cache_key=tenant-42`, `stream` false and true
- WHEN routed to Mistral
- THEN the upstream body contains `prompt_cache_key=tenant-42`

#### Scenario: No key

- GIVEN a request without a key
- THEN the upstream body has no `prompt_cache_key`

### Requirement: OpenRouter gets a safe allowlist of client keys

A request routed to OpenRouter from an OpenAI-format client MUST be re-encoded through the canonical model, as for any other cross-dialect target (design D6, amended). After re-encoding, the gateway MUST copy from the client body only `provider` (a JSON object, with any `model` or `models` key inside it removed), `session_id` and `user` (strings). It MUST NOT forward `models`, `route`, `transforms`, `plugins` or any other unmodelled key. Cache intent MUST follow the OpenRouter profile rows of the intent spec. The response MUST still be re-encoded.

#### Scenario: Routing and session keys survive

- GIVEN an OpenAI client body with `provider={order:["anthropic"]}`, `session_id` and `user`
- WHEN routed to OpenRouter
- THEN the upstream body carries the three keys JSON-equal

#### Scenario: Model and billing overrides are stripped

- GIVEN an OpenAI client body with `models`, `route`, `transforms`, `plugins` and `provider.models`
- WHEN routed to OpenRouter with `AllowedModels` set
- THEN none of those keys reaches the upstream, and the model sent is the enforced one

#### Scenario: Claude upstream via OpenRouter

- GIVEN parts-level `cache_control` on the last system part
- WHEN routed to OpenRouter with model `anthropic/claude-*`
- THEN the marker is forwarded (at most 4 breakpoints, 1h before 5m) and the second identical call reports R>0 (e2e)

#### Scenario: Model without documented breakpoints

- GIVEN the same body with model `meta-llama/*`
- THEN no `cache_control` is sent

#### Scenario: Response still normalised

- GIVEN an OpenRouter SSE stream with `: OPENROUTER PROCESSING` comments
- WHEN streamed to an OpenAI client
- THEN the client stream matches today's re-encoded output

### Requirement: Groq requests are re-encoded

A request routed to Groq from an OpenAI-format client MUST be re-encoded through the canonical model, then normalised by `NormalizeGroqRequest`, so fields Groq rejects (`n>1`, `service_tier`, `logprobs`, `messages[].name`, `metadata`, `modalities`) never reach it and `developer` messages become `system`. Groq caches automatically, so no cache field is sent. Modelled fields (`seed`, `parallel_tool_calls`, `response_format` with its `json_schema`) MUST survive. Responses MUST stay re-encoded.

#### Scenario: Rejected fields dropped

- GIVEN an OpenAI client body with `n=2`, `service_tier="default"`, `logprobs`, `prompt_cache_key` and `seed`
- WHEN routed to Groq
- THEN only `seed` of those reaches the upstream, and Groq-specific normalisation still applies

### Requirement: Azure keeps its API selection and maps cache options

Azure MUST keep today's API selection (design D5). When a Responses-format request is sent to Azure Chat, `prompt_cache_key` and `prompt_cache_retention` MUST be mapped to the Chat fields of the same name. If Azure rejects a `prompt_cache_retention` the gateway mapped with a 400, the request MUST fall back to sending the key only, and the deployment MUST stop receiving the mapped retention for a bounded time. Retention a client sent itself on a passthrough MUST NOT be retried.

#### Scenario: Responses client to Azure Chat

- GIVEN `/v1/responses` with `prompt_cache_key=k1` and `prompt_cache_retention=24h` to an Azure registry
- WHEN proxied, buffered and streaming
- THEN the upstream path is the Azure Chat endpoint and the body carries `prompt_cache_key=k1` and `prompt_cache_retention=24h`

#### Scenario: Retention rejected

- GIVEN the same request and Azure answers 400 on `prompt_cache_retention`
- THEN the request is retried once with `prompt_cache_key` only, logged at Info
- AND later gateway-mapped requests to that deployment omit `prompt_cache_retention` for an hour

#### Scenario: Client-sent retention is not retried

- GIVEN a Chat request that carries `prompt_cache_retention` itself (passthrough to Azure)
- WHEN Azure answers 400 naming it
- THEN the 400 is returned to the client and the request is not retried

#### Scenario: Chat client to Azure unchanged

- GIVEN a Chat request to Azure
- THEN it is still sent as Chat

### Requirement: E2E acceptance

For Mistral, OpenRouter (Claude and OpenAI upstreams), Groq and Azure, against a local gateway: native `make matrix-ag UPSTREAM=X AGENT=X`, cross-format `make matrix-ag PROVIDER=X`, each with and without `STREAM=1`, and `pytest -m prompt_caching` MUST pass. Groq's cache assertion applies only to gpt-oss models.

#### Scenario: Mistral cached second call

- GIVEN a long prefix with `prompt_cache_key`
- WHEN sent twice through the gateway
- THEN the second response and its playground trace report the same R, with R>0 (the Mistral usage field for cached tokens needs live confirmation)
