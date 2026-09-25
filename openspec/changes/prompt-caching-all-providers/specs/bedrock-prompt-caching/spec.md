# Delta for bedrock-prompt-caching

New capability. Contract: ENG-1618 scope block 4 and open question 2. Applies to the Converse HTTP adapter and the SDK path (`bedrock/converse.go`). Usage folding is in prompt-cache-usage-accounting.

## ADDED Requirements

### Requirement: cachePoint emission

For a model that supports explicit caching, the Bedrock encoder MUST emit a `cachePoint` block after each canonical breakpoint: in `toolConfig.tools`, in `system`, and at the end of the message `content`. It MUST apply the prompt-cache-intent limits (max 4, tools → system → messages, drop earliest message breakpoints first, 1h after 5m downgraded). TTL MUST be sent as `ttl` only when it is `1h` and the model supports 1h; otherwise the TTL MUST be 5m (omitted).

#### Scenario: Anthropic client to Claude on Bedrock (cross-format cell)

- GIVEN a `/v1/messages` body with breakpoints on the last tool, system and last user block
- WHEN routed to `anthropic.claude-*` on Bedrock, `stream` false and true
- THEN the Converse request has three `cachePoint` blocks in those positions

#### Scenario: OpenAI client with key only

- GIVEN a Chat request with `prompt_cache_key` and no breakpoint
- WHEN routed to Bedrock
- THEN no `cachePoint` is emitted and the key is dropped

#### Scenario: 1h on a 5m-only model

- GIVEN a 1h breakpoint and a model listed without 1h support
- THEN the `cachePoint` is emitted without `ttl`

### Requirement: Automatic caching

Top-level automatic caching (Anthropic or OpenAI Chat `cache_control`) MUST become one `cachePoint` after the last block of the last message, counted in the cap and last in TTL order. When that message already ends with an explicit `cachePoint`, only one is sent: with the client's TTL when the client put the marker on its last block, otherwise with the automatic TTL.

#### Scenario: Automatic only

- GIVEN an Anthropic body with top-level `cache_control` and no other marker
- WHEN routed to Bedrock
- THEN the last message ends with the only `cachePoint`

### Requirement: Valid cachePoint positions on the SDK path

A `cachePoint` MUST only follow a kept block that is not itself a `cachePoint`, in content, system and tools. Blocks the SDK translation has no member for (documents, videos, S3 images, citations) are dropped, and a `cachePoint` that followed one is dropped with it. System `guardContent` MUST be sent as `SystemContentBlockMemberGuardContent`, never as an empty text block.

#### Scenario: AWS documentation example

- GIVEN a native Bedrock turn `[document, cachePoint, text]`
- THEN the SDK input is `[text]`

### Requirement: Model capability table

A table in code MUST list, by model-family prefix (after stripping region or global inference-profile prefixes), whether explicit caching and 1h TTL are supported. Unlisted models, ARNs and unknown IDs MUST get no `cachePoint`. Minimum token counts MUST NOT be enforced.

#### Scenario: Unsupported family

- GIVEN a breakpoint and model `mistral.mistral-7b-instruct`
- THEN the Converse request has no `cachePoint`

#### Scenario: Profile prefix

- GIVEN `global.anthropic.claude-sonnet-4-6`
- THEN it resolves to the Claude family entry

#### Scenario: Short prefix

- GIVEN a breakpoint on a system prompt below the model minimum
- THEN the `cachePoint` is still sent

### Requirement: ValidationException fallback

When Bedrock rejects a request that contains `cachePoint` with a `ValidationException`, the gateway MUST retry once without any `cachePoint`, mirroring the system-prompt fallback, and MUST remember the model so later requests skip `cachePoint`. Errors other than `ValidationException` MUST NOT trigger the retry.

#### Scenario: Retry succeeds

- GIVEN an upstream that returns `ValidationException` when `cachePoint` is present
- WHEN a request with breakpoints is sent, buffered or streaming
- THEN a second call without `cachePoint` is made and its response is returned
- AND the next request to that model sends no `cachePoint` first

#### Scenario: Throttling not retried

- GIVEN a `ThrottlingException`
- THEN no cachePoint-less retry occurs

### Requirement: System fold keeps cachePoint

When `foldSystemIntoFirstTurn` moves the system prompt into the first user turn, a system `cachePoint` MUST follow the folded text in that turn.

#### Scenario: Fold path

- GIVEN a system breakpoint and a model that needs the system fold
- THEN the first user turn is `[text(system), cachePoint, …]`

### Requirement: SDK path parity

`decodeConverseBody` and `sdkContentBlock`/`sdkToolConfig` MUST translate `cachePoint` on system, content and tools into the SDK `CachePoint` members instead of dropping them.

#### Scenario: SDK translation

- GIVEN a Converse body with `cachePoint{type:default, ttl:1h}` in system
- WHEN translated to the SDK input
- THEN it is a `SystemContentBlockMemberCachePoint` with TTL one hour

### Requirement: E2E and live acceptance

A `bedrock_live` test MUST send the same long prefix twice and assert R>0 and the raw `inputTokens` semantics. Against a local gateway, native `make matrix-ag UPSTREAM=bedrock AGENT=bedrock`, cross-format `make matrix-ag PROVIDER=bedrock`, each with and without `STREAM=1`, and `pytest -m prompt_caching` MUST pass for implicit caching and explicit 5m and 1h.

#### Scenario: Explicit 1h e2e

- GIVEN a Claude model, a long system prefix with a 1h breakpoint, sent twice
- WHEN the second response arrives
- THEN R>0 in the response and the playground trace, and the first call's trace shows W1h>0 priced at 2×Input
