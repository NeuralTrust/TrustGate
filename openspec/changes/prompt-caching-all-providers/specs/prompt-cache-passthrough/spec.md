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

### Requirement: OpenRouter keeps cache and routing fields

A request routed to OpenRouter from an OpenAI-format client MUST carry top-level and parts-level `cache_control`, `session_id`, and the routing keys `provider`, `models`, `transforms`, `route` unchanged. The response MUST still be re-encoded.

#### Scenario: Routing keys survive

- GIVEN an OpenAI client body with `provider={order:["anthropic"]}`, `models`, `transforms`, `route`
- WHEN routed to OpenRouter
- THEN the upstream body has the four keys byte-equivalent (JSON-equal)

#### Scenario: Claude upstream via OpenRouter

- GIVEN parts-level `cache_control` on the last system part
- WHEN routed to OpenRouter with model `anthropic/claude-*`
- THEN the marker is forwarded and the second identical call reports R>0 (e2e)

#### Scenario: Response still normalised

- GIVEN an OpenRouter SSE stream with `: OPENROUTER PROCESSING` comments
- WHEN streamed to an OpenAI client
- THEN the client stream matches today's re-encoded output

### Requirement: Groq keeps unmodelled request fields

A request routed to Groq MUST keep top-level fields the canonical model does not represent (e.g. `prompt_cache_key`, `seed`), after `NormalizeGroqRequest`. Responses MUST stay re-encoded.

#### Scenario: Unknown field preserved

- GIVEN an OpenAI client body with `prompt_cache_key` and `seed`
- WHEN routed to Groq
- THEN both keys reach the upstream and Groq-specific normalisation still applies

### Requirement: Azure keeps its API selection and maps cache options

Azure MUST keep today's API selection (design D5). When a Responses-format request is sent to Azure Chat, `prompt_cache_key` and `prompt_cache_retention` MUST be mapped to the Chat fields of the same name. If Azure rejects `prompt_cache_retention` with a 400, the request MUST fall back to sending the key only.

#### Scenario: Responses client to Azure Chat

- GIVEN `/v1/responses` with `prompt_cache_key=k1` and `prompt_cache_retention=24h` to an Azure registry
- WHEN proxied, buffered and streaming
- THEN the upstream path is the Azure Chat endpoint and the body carries `prompt_cache_key=k1` and `prompt_cache_retention=24h`

#### Scenario: Retention rejected

- GIVEN the same request and Azure answers 400 on `prompt_cache_retention`
- THEN the request is retried once with `prompt_cache_key` only

#### Scenario: Chat client to Azure unchanged

- GIVEN a Chat request to Azure
- THEN it is still sent as Chat

### Requirement: E2E acceptance

For Mistral, OpenRouter (Claude and OpenAI upstreams), Groq and Azure, against a local gateway: native `make matrix-ag UPSTREAM=X AGENT=X`, cross-format `make matrix-ag PROVIDER=X`, each with and without `STREAM=1`, and `pytest -m prompt_caching` MUST pass. Groq's cache assertion applies only to gpt-oss models.

#### Scenario: Mistral cached second call

- GIVEN a long prefix with `prompt_cache_key`
- WHEN sent twice through the gateway
- THEN the second response and its playground trace report the same R, with R>0 (the Mistral usage field for cached tokens needs live confirmation)
