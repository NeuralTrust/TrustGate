# Spec: per_tool_rate_limiter counts real executions (LLM + MCP) — RUN-965

## Purpose

Behavioral contract for `per_tool_rate_limiter` (`pkg/infra/plugins/pertoolratelimit`)
after moving quota accounting from *proposed* assistant `tool_calls` to *real
executions*. On the LLM path executions are observed on the next request's
`role:"tool"` results; on the MCP path a `tools/call` is one execution counted
after upstream success. Fixed-window + Redis-TTL algorithm, scope model, config
schema, headers, and key layout are unchanged. Requirements use RFC 2119 keywords;
each scenario is mappable to a unit or functional test.

## Requirements — LLM path

### PTRL-1: Proposals are never counted

The plugin MUST NOT charge quota for an assistant `tool_calls` entry that the
client never executes (no subsequent `role:"tool"` result for that `tool_call_id`).

#### Scenario: model proposes a tool that never runs
- GIVEN a request/response turn where the model returns a `tool_call` (id `call_1`, name `send_email`)
- WHEN no later request carries a `role:"tool"` message with `tool_call_id = call_1`
- THEN the `send_email` window counter remains unchanged

### PTRL-2: Executed tool results increment exactly once

On `pre_request`, for each `role:"tool"` result whose `tool_call_id` resolves to a
tool name via an assistant `tool_calls` entry in the same canonical message list,
the plugin MUST increment that tool's window counter(s) exactly once.

#### Scenario: next request carries a tool result
- GIVEN a `pre_request` whose messages include assistant `tool_calls` `[{id: call_1, name: send_email}]` and a `role:"tool"` message with `tool_call_id = call_1`
- WHEN the plugin executes the `pre_request` stage
- THEN the `send_email` window counter increments by exactly 1
- AND each configured window for the matched rule is incremented once

### PTRL-3: Replayed tool_call_id does not double-count

The plugin MUST dedupe by `tool_call_id` using a Redis `SET NX EX` guard before
INCR, with TTL equal to the largest configured window duration for the matched
rule. A repeated `tool_call_id` MUST NOT increment counters again.

#### Scenario: retried/replayed request resends the same result
- GIVEN a `role:"tool"` result with `tool_call_id = call_1` that was already counted
- WHEN a replayed or retried request carries `tool_call_id = call_1` again
- THEN the NX guard fails and the counter does NOT increment a second time
- AND the dedupe key expires after the largest configured window duration

### PTRL-4: Multiple distinct results each count once

When one request contains several distinct `role:"tool"` results, the plugin MUST
count each resolved tool exactly once.

#### Scenario: two tool results in one request
- GIVEN a `pre_request` with `role:"tool"` results for `call_1`→`send_email` and `call_2`→`send_email`
- WHEN the plugin executes the `pre_request` stage
- THEN the `send_email` counter increments by 2 (one per distinct `tool_call_id`)

### PTRL-5: Enforcement of declared tools in the same pre_request

In the same `pre_request` (after counting executed results), for each tool
*declared* in the request body whose window is already exhausted, the plugin MUST
apply the rule behavior: `reject_response` → 429 with `X-RateLimit-*` and
`Retry-After` headers; `strip_tool_from_request` → tool removed from the forwarded
body (non-canonical fields preserved); `inject_error_result` → handled at
`pre_response` for non-streaming and degraded to strip at `pre_request` for
streaming, unchanged from current behavior.

#### Scenario: reject over-budget declared tool
- GIVEN `send_email` is at its window max and is declared in the request
- WHEN the `pre_request` stage runs
- THEN a `PluginError` with status 429 is returned carrying `X-RateLimit-consumer-*`, `X-RateLimit-Tool`, and `Retry-After`

#### Scenario: strip over-budget declared tool
- GIVEN `strip_tool_from_request` and `send_email` over budget, declared alongside `lookup`
- WHEN the `pre_request` stage runs
- THEN the forwarded body contains only `lookup` and preserves non-canonical fields (e.g. `temperature`, `seed`)

#### Scenario: inject over-budget tool (non-streaming vs streaming)
- GIVEN `inject_error_result` and a tool over budget
- WHEN the response is non-streaming
- THEN `pre_response` drops the offending `tool_calls` and appends the templated assistant message (`StopUpstream`), unchanged
- AND WHEN the request is streaming, `pre_request` degrades to stripping the tool, unchanged

### PTRL-6: Cross-provider tool_call_id resolution

The plugin MUST resolve `tool_call_id → tool name` from the canonical request for
both OpenAI and Anthropic sources using the existing adapter mapping.

#### Scenario: OpenAI and Anthropic both resolve
- GIVEN an OpenAI `role:"tool"` result and, separately, an Anthropic `tool_result` block, each with a matching assistant `tool_calls`/`tool_use` entry
- WHEN the `pre_request` stage runs for each provider
- THEN the correct tool name is resolved and counted in both cases

### PTRL-7: Streaming counting is stream-independent

Counting MUST NOT depend on parsing the streamed response; executed-tool results
arrive in the following request body.

#### Scenario: streamed tool_calls do not drive counting
- GIVEN a streaming response that emitted `tool_calls`
- WHEN the stream completes with no follow-up `role:"tool"` request
- THEN no counter changes as a result of the stream

## Requirements — MCP path (`tools/call`)

### PTRL-8: tools/call counts once after upstream success

For an MCP `tools/call` routed through the gateway, the plugin MUST increment the
counter for `params.name` exactly once in `pre_response`, which runs only after
upstream `CallTool` succeeds. No `tool_call_id` dedupe key is used on MCP.

#### Scenario: successful tool call counts once
- GIVEN an MCP `tools/call` for `params.name = get_weather` that succeeds upstream
- WHEN `pre_response` runs
- THEN the `get_weather` window counter increments by exactly 1

### PTRL-9: tools/list never counts

The plugin MUST NOT count `tools/list` (or any non-`tools/call` MCP method).

#### Scenario: listing tools is free
- GIVEN an MCP `tools/list` request
- WHEN the plugin runs
- THEN no counter changes

### PTRL-10: MCP over-limit denies in pre_request; behaviors collapse to deny

On MCP, when `params.name` is already over its window, the plugin MUST block in
`pre_request` before upstream `CallTool` is dialed, returning a `PluginError` the
MCP runner maps to a JSON-RPC block. All three behaviors
(`reject_response`, `strip_tool_from_request`, `inject_error_result`) MUST
collapse to deny/block on MCP.

#### Scenario: over-limit tools/call blocked pre-dial
- GIVEN `get_weather` is at its window max
- WHEN a `tools/call` for `get_weather` reaches `pre_request`
- THEN a block is returned as JSON-RPC and upstream `CallTool` is NOT invoked
- AND the outcome is identical regardless of configured behavior

### PTRL-11: Failed upstream call is not counted

Because MCP counting happens in `pre_response` after success, an upstream
`CallTool` failure MUST NOT increment any counter.

#### Scenario: upstream failure leaves counter unchanged
- GIVEN a `tools/call` for `get_weather` whose upstream `CallTool` errors
- WHEN the dispatch completes
- THEN the `get_weather` counter is unchanged

## Requirements — Cross-cutting (unchanged semantics)

### PTRL-12: Scope semantics unchanged

Scope MUST derive from `RuntimeScope` only: `consumer` → consumerID,
`global` → gatewayID; never from request/wire data.

#### Scenario: consumer and global counters are isolated
- GIVEN the same executed tool under a consumer scope and a global scope
- WHEN both are counted
- THEN each writes its own key and neither leaks into the other

### PTRL-13: Fixed-window + TTL semantics unchanged

Counting MUST remain fixed-window with the Redis TTL anchored on the first
increment (EXPIRE set only when TTL is unset); key layout
`pertoolrl:{configID}:{dimension}:{subject}:{tool}:w{window}` is unchanged.

#### Scenario: window anchored on first increment
- GIVEN an empty window key
- WHEN the first execution is counted
- THEN the key gets a positive TTL and subsequent increments within the window do not reset it

### PTRL-14: Fail-open on Redis/decoding errors, no counting

On Redis unavailability or body/canonical decode failure, the plugin MUST fail
open (LLM returns an OK result; MCP fails open per RUN-832) and MUST NOT count.

#### Scenario: Redis down does not block traffic
- GIVEN Redis is unavailable
- WHEN a `pre_request`/`pre_response` runs on either path
- THEN the request proceeds (no reject/block) and no counter is written

## REMOVED Requirements

### Requirement: post_response counting of proposed tool_calls
(Reason: quota is now charged from real executions; the `post_response` counting
path and the count-only `streamToolNames` stream handling are removed. If
`post_response` remains a supported stage, it MUST NOT increment counters.)

## Tests to rewrite

Existing tests encode the old proposal-time contract and MUST be rewritten:

- `pkg/infra/plugins/pertoolratelimit/plugin_test.go`:
  `TestPlugin_PostResponse_CountsNonStreaming`, `…_CountsEachToolCall`,
  `…_CountsStreaming`, `…_TwoWindows`, `…_UnmatchedToolNoCount`,
  `…_ScopeIsolation`, `…_ConcurrentAtomic`, `…_EmptyToolNameNotCounted` →
  recast as `pre_request` counting from `role:"tool"` results (PTRL-2/4/12/13);
  add `tool_call_id` NX dedupe (PTRL-3); add MCP counting/enforcement
  (PTRL-8/9/10/11); `TestPlugin_FullCycle_CountThenReject` → count via next-turn
  `role:"tool"` results; `TestPlugin_Stages` updated if `post_response` counting
  is dropped (PTRL REMOVED). Run with `-race`.
- `tests/functional/plugin_per_tool_rate_limiter_test.go`:
  `TestPluginE2E_PerToolRateLimiter_RejectResponse`, `…_InjectErrorResult`,
  `…_StripToolFromRequest`, `…_GlobMatchUsesDefaultBehavior` → drive counting via
  a follow-up turn carrying `role:"tool"` results (PTRL-2/5); add MCP `tools/call`
  count/deny coverage (PTRL-8/10) and `tools/list` no-count (PTRL-9).
