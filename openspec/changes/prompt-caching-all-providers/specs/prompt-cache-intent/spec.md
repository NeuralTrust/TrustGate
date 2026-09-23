# Delta for prompt-cache-intent

New capability. Contract: ENG-1618 scope block 2 and open question 1 (Approach A, sidecar markers). Gateway-inserted breakpoints are out of scope.

## ADDED Requirements

### Requirement: Canonical cache intent

`CanonicalRequest` MUST carry: a breakpoint with TTL (`5m` | `1h`) on system, on each tool and on each message, and request-level options `{Key, Retention, Mode, Auto}`. A breakpoint means "cache boundary at the end of this segment". `Content`/`System` strings stay unchanged, so content-reading plugins are unaffected. Absence MUST mean "no intent", never a default TTL.

#### Scenario: No markers

- GIVEN a request without any cache field
- WHEN decoded by any adapter
- THEN every breakpoint and option is nil and the encoded body has no cache field

### Requirement: Faithful decode and encode per format

Anthropic, OpenAI Chat and OpenAI Responses MUST round-trip intent (decode → encode yields the same markers on the same segments):

| Format | Breakpoint wire | Options wire |
|---|---|---|
| Anthropic | `cache_control{type:ephemeral, ttl}` on system blocks, tools, message blocks | top-level `cache_control` → `Auto` |
| OpenAI Chat | parts-level `cache_control` (OpenRouter-style) | `prompt_cache_key`, `prompt_cache_retention`, `prompt_cache_options` |
| OpenAI Responses | `prompt_cache_breakpoint` on an input part | same three keys |

The encoder MUST attach a breakpoint to the last block it emits for the segment (after ENG-1608 images). Several system breakpoints collapse to one at the end of system.

#### Scenario: Anthropic round-trip, buffered and streaming request

- GIVEN a `/v1/messages` body with `cache_control` (1h) on the last system block, the last tool and the last user block
- WHEN decoded and re-encoded as Anthropic, with `stream` false and true
- THEN the three markers and TTLs are present at the same positions

#### Scenario: Image before text

- GIVEN a user message with an image and a text part, breakpoint on the message
- WHEN encoded as Anthropic
- THEN `cache_control` is on the text block, the last emitted

#### Scenario: Responses options

- GIVEN a Responses body with `prompt_cache_key=k1` and `prompt_cache_retention=24h`
- WHEN round-tripped
- THEN both keys are emitted unchanged

### Requirement: Cross-format mapping

When source and target differ, intent MUST map where the target has an equivalent and MUST be dropped deliberately (with a documented no-op, no error) where it does not.

| Target | Breakpoints | Key / Retention | Auto |
|---|---|---|---|
| Anthropic | mapped, TTL kept | dropped | mapped |
| Bedrock | `cachePoint` (see bedrock-prompt-caching) | dropped | dropped |
| OpenAI / Azure / xAI Chat | dropped deliberately (OpenAI rejects parts-level `cache_control`) | Key, Retention and `prompt_cache_options` mapped | dropped |
| OpenAI Responses, GPT-5.6+ | `prompt_cache_breakpoint` on system and messages | mapped | dropped |
| OpenAI Responses, other models | dropped | mapped | dropped |
| OpenRouter | parts-level `cache_control` (the only Chat target that gets it), TTL kept | dropped | top-level `cache_control` |
| Mistral | dropped | Key → `prompt_cache_key` | dropped |
| Gemini / Vertex, Cohere | dropped | dropped | dropped |

#### Scenario: Anthropic client to OpenAI upstream (cross-format matrix cell)

- GIVEN an Anthropic client with a system breakpoint, routed to OpenAI Responses with a GPT-5.6+ model
- WHEN translated, buffered and streaming
- THEN the last system input part carries `prompt_cache_breakpoint`
- AND the response usage reports cache fields in Anthropic shape

#### Scenario: Breakpoints dropped for OpenAI Chat and older Responses models

- GIVEN the same request routed to OpenAI Chat, Azure, xAI, or Responses with `gpt-4o`
- WHEN translated
- THEN no per-block marker is sent, request-level key/retention/options are still mapped, and the request succeeds

#### Scenario: OpenAI client to Anthropic upstream

- GIVEN a Chat request with `prompt_cache_key` and a parts-level marker on the last user part
- WHEN translated to Anthropic
- THEN the last user block has `cache_control` and no `prompt_cache_key` is sent

#### Scenario: Drop to Gemini

- GIVEN an Anthropic request with three breakpoints routed to Gemini
- WHEN translated
- THEN the Gemini body has no cache field and the request succeeds

### Requirement: Precedence and limits

Client markers MUST always win over any gateway default. For targets with a maximum (Anthropic and Bedrock: 4), the encoder MUST keep order tools → system → messages and, when over the limit, drop the earliest message breakpoints first, keeping the last breakpoint of each section. A 1h breakpoint that follows a 5m breakpoint in that order MUST be downgraded to 5m.

#### Scenario: Six breakpoints to Anthropic

- GIVEN one tool, one system and four message breakpoints from an OpenAI client
- WHEN encoded as Anthropic
- THEN the tool, system and last two message breakpoints remain (4 total)

#### Scenario: TTL downgrade

- GIVEN system 5m and last message 1h
- WHEN encoded for Anthropic or Bedrock
- THEN the message breakpoint is emitted as 5m

#### Scenario: Same-format passthrough untouched

- GIVEN an Anthropic client with five breakpoints to Anthropic, no re-encoding plugin
- WHEN proxied
- THEN the body is forwarded unchanged and the provider's own validation applies

### Requirement: E2E acceptance

For Anthropic, OpenAI and Azure, `make matrix-ag PROVIDER=X` (with and without `STREAM=1`) against a local gateway MUST pass, and `pytest -m prompt_caching` MUST show R>0 on the second call for a cross-format request (Anthropic client → OpenAI upstream, OpenAI client → Anthropic upstream), with the playground trace matching the provider usage.

#### Scenario: Cross-format cached second call

- GIVEN an OpenAI client, Anthropic upstream, a long system prefix with a breakpoint
- WHEN sent twice
- THEN the second response and its trace report R>0
