# Delta for plugin-cache-preservation

New capability. Contract: ENG-1618 scope block 5. Depends on the faithful decode/encode in prompt-cache-intent.

## ADDED Requirements

### Requirement: Re-encoding plugins keep cache intent

`regexreplace`, `bedrockguardrail` anonymize, `googlemodelarmor` anonymize and `trustguard` rewrite MUST preserve every breakpoint (position and TTL) and every cache option when they rewrite a request, in Anthropic, OpenAI Chat and OpenAI Responses bodies. When they rewrite a response (buffered or SSE), the emitted usage MUST keep R, W and W1h.

#### Scenario: regexreplace on Anthropic passthrough

- GIVEN an Anthropic body with `cache_control` on the last system block and a regex that masks an email in a user message
- WHEN `PreRequest` rewrites the body
- THEN the system `cache_control` and its TTL are unchanged and only the masked text differs

#### Scenario: Anonymize on Responses

- GIVEN a Responses body with `prompt_cache_key` and a PII match
- WHEN bedrockguardrail or googlemodelarmor anonymizes it
- THEN `prompt_cache_key` is still present

#### Scenario: Response rewrite keeps usage

- GIVEN an upstream response with R=900, W=100 and a trustguard response rewrite
- WHEN the response is re-encoded, buffered and streaming
- THEN the client body reports R=900 and W=100 and tokenratelimit counts the same as without the plugin

#### Scenario: No-op when nothing matches

- GIVEN a body where the plugin matches nothing
- THEN the body is forwarded byte-identical

### Requirement: Tool-rewriting plugins keep per-tool markers

`toolinjection`, `toolallowlist` and `pertoolratelimit` MUST keep the cache marker on every tool they do not remove, and MUST NOT reorder retained tools. When the tool that carried the last breakpoint is removed, the marker MUST move to the last retained tool. Injected tools MUST be appended after retained ones and carry no marker.

#### Scenario: Allowlist removes a tool

- GIVEN tools `[a, b, c]` with `cache_control` on `c`, and an allowlist of `a, c`
- WHEN the plugin filters
- THEN tools are `[a, c]` with `cache_control` on `c`

#### Scenario: Marked tool removed

- GIVEN `cache_control` on `c` and an allowlist of `a, b`
- THEN tools are `[a, b]` with `cache_control` on `b`

#### Scenario: Injection

- GIVEN tools `[a]` with a marker on `a` and an injected tool `x`
- THEN tools are `[a, x]`, the marker stays on `a`

### Requirement: Prefix-stability documentation

Plugin documentation MUST state which plugins change the cached prefix (`prompttemplate` per-user system variables, `toolinjection`, `toolallowlist`, `pertoolratelimit` when the tool set varies per request) and that `promptcompression` skips bodies with cache markers.

#### Scenario: Doc check

- GIVEN the plugin docs
- THEN each plugin above has a prompt-caching note

### Requirement: E2E acceptance

For Anthropic and OpenAI, `pytest -m prompt_caching` MUST include a run with `regexreplace` and `toolallowlist` enabled on the consumer, and the second call MUST still report R>0 in the response and the playground trace.

#### Scenario: Cached with plugins

- GIVEN regexreplace and toolallowlist active and a long prefix with breakpoints
- WHEN sent twice
- THEN the second response reports R>0
