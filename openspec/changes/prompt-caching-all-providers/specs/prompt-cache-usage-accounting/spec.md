# Delta for prompt-cache-usage-accounting

New capability. Contract: ENG-1618 scope block 1. Notation: I = input, R = cache read, W = cache write, W1h = 1h share of W, O = output.

## ADDED Requirements

### Requirement: Canonical usage invariant

Every adapter's decode MUST produce `CanonicalUsage` where `InputTokens` includes R and W, `R + W <= InputTokens`, `W1h <= W`, and `TotalTokens >= InputTokens + OutputTokens`. This holds for buffered bodies and for the merged result of a stream (`MergeUsage`), not only per chunk.

#### Scenario: Stream merge keeps the invariant

- GIVEN a stream whose first chunk reports R and W and whose last chunk reports O only
- WHEN the chunks are merged
- THEN the merged usage satisfies every inequality above

### Requirement: Per-provider decode mapping

Each target adapter MUST map its wire fields as below, buffered and streaming. When a provider reports the same count in two fields, the adapter MUST take the max, never the sum.

| Provider | R source | W / W1h source | I rule |
|---|---|---|---|
| Bedrock (Converse HTTP + SDK) | `cacheReadInputTokens` | `cacheWriteInputTokens`; W1h from `CacheDetails` entries with TTL `1h` | I = `inputTokens` + R + W; Total = max(`totalTokens`, I+O) |
| Anthropic | unchanged (already folded) | unchanged, incl. `cache_creation.ephemeral_1h_input_tokens` | unchanged |
| OpenAI / Azure Chat | `prompt_tokens_details.cached_tokens` | `prompt_tokens_details.cache_write_tokens` | `prompt_tokens` |
| OpenAI / Azure Responses | `input_tokens_details.cached_tokens` | `input_tokens_details.cache_write_tokens` | `input_tokens` |
| DeepSeek | max(`prompt_cache_hit_tokens`, `details.cached_tokens`) | none | `prompt_tokens` (hit + miss) |
| Moonshot | max(top-level `cached_tokens`, `details.cached_tokens`) | `cache_write_tokens` | `prompt_tokens` |
| OpenRouter | `details.cached_tokens` | `details.cache_write_tokens` | `prompt_tokens` |
| Cohere | `usage.cached_tokens` | none | I = `tokens.input_tokens` (`cached_tokens` ⊆ it; live-confirm) |
| Gemini / Vertex | unchanged (`cachedContentTokenCount`) | none | unchanged |

OpenRouter `cost` and `cache_discount` MUST be logged only and MUST NOT feed `CostUSD`.

#### Scenario: Bedrock buffered hit (fixture replaces the wrong one)

- GIVEN Converse usage `inputTokens=12, cacheReadInputTokens=4, cacheWriteInputTokens=2, outputTokens=7, totalTokens=19`
- WHEN decoded
- THEN I=18, R=4, W=2, O=7, Total=25

#### Scenario: Bedrock SDK 1h split

- GIVEN SDK `TokenUsage` with W=300 and `CacheDetails` `[{1h:200},{5m:100}]`
- WHEN `wireUsage` maps it
- THEN W=300 and W1h=200

#### Scenario: Bedrock streaming metadata

- GIVEN a ConverseStream `metadata` event with the same counts as the buffered hit
- WHEN observed through the stream path
- THEN the merged usage equals the buffered result

#### Scenario: DeepSeek double report

- GIVEN `prompt_cache_hit_tokens=80` and `prompt_tokens_details.cached_tokens=80`, `prompt_tokens=100`
- WHEN decoded
- THEN R=80, not 160

#### Scenario: OpenAI GPT-5.6 write, streaming

- GIVEN the final `include_usage` chunk carries `cache_write_tokens=500`
- WHEN observed
- THEN W=500 and the write is priced at the cache-write rate

#### Scenario: Converse totalTokens semantics (needs live confirmation)

- GIVEN a `bedrock_live` call sending the same long prefix twice
- WHEN the second response arrives
- THEN R>0, the raw `inputTokens` excludes R+W, and canonical Total >= I+O

#### Scenario: Moonshot shape (needs live confirmation)

- GIVEN a Moonshot body with cached tokens in either documented location
- WHEN decoded
- THEN R equals the larger reported value

### Requirement: Client encoders emit cache usage

Chat, Responses, Cohere and Anthropic response encoders (buffered and SSE) MUST emit R and W in the client's native fields; Anthropic MUST also emit `cache_creation.{ephemeral_5m,ephemeral_1h}_input_tokens`. The Bedrock encoder MUST reverse the fold (`inputTokens` = I − R − W). A decode of the encoded body MUST return the same `CanonicalUsage`.

#### Scenario: Cross-format tokenratelimit

- GIVEN an OpenAI Chat client, an Anthropic upstream reporting R=1000, and `CountCacheReads=false`
- WHEN the buffered response is re-encoded and tokenratelimit decodes the client body
- THEN the counted input excludes the 1000 cached tokens

#### Scenario: Anthropic SSE breakdown

- GIVEN canonical usage W=300, W1h=200
- WHEN encoded as Anthropic `message_start`
- THEN `cache_creation.ephemeral_1h_input_tokens=200` and `ephemeral_5m_input_tokens=100`

### Requirement: Pricing rules

`CostUSD` MUST price (I−R−W)·Input + R·CacheRead + (W−W1h)·CacheWrite + W1h·CacheWrite1h + O·Output. `CacheWrite1h` precedence: registry override, else 2×Input for Claude models (Anthropic direct or Bedrock), else CacheWrite. The registry discount MUST apply to catalog-derived rates after resolution; override prices stay as configured (current override behaviour).

#### Scenario: Claude 1h without override

- GIVEN a Claude model with Input $3/M, CacheWrite $3.75/M and no override
- WHEN W1h=1000 is priced
- THEN the 1h cost is $0.006

#### Scenario: Non-Claude model

- GIVEN a GPT model with no override
- THEN CacheWrite1h equals CacheWrite

#### Scenario: Derived rate with discount

- GIVEN a Claude model with catalog Input $3/M, no override, discount 0.2
- THEN CacheWrite1h is $4.80/M

#### Scenario: Override wins

- GIVEN a registry override `cache_write_1h=$5/M` on a Claude model
- THEN CacheWrite1h is $5/M, not 2×Input

### Requirement: E2E acceptance per modified provider

Against a local gateway built from the worktree (never prod), each provider below MUST pass: native `make matrix-ag UPSTREAM=X AGENT=X` and cross-format `make matrix-ag PROVIDER=X`, each with and without `STREAM=1`, and `pytest -m prompt_caching`. The run MUST stop and report when an API key is missing.

Providers: Bedrock (implicit and explicit, 5m and 1h), Anthropic, OpenAI, Azure, Mistral, OpenRouter (Claude and OpenAI upstreams), DeepSeek, Groq, Cohere, Gemini (also covers Vertex-Gemini). Moonshot, Vertex and openai_compatible are unit-only. xAI and Cerebras SHOULD run `prompt_caching` as regression (Cerebras: usage parsed only).

#### Scenario: prompt_caching test

- GIVEN a prefix above the provider minimum sent twice, buffered then streaming
- WHEN the second response returns with `X-AG-Trace-Id`
- THEN the provider usage reports R>0 (Cohere, Cerebras: usage present)
- AND `GET /v1/playground/traces/{id}` with `X-AG-Playground-Token` shows the same I, R, W and a cost matching the pricing rules
