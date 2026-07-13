# Exploration: per_tool_rate_limiter must count tool executions, not LLM tool_calls (RUN-965)

## Current State

`per_tool_rate_limiter` (`pkg/infra/plugins/pertoolratelimit`) is a fixed-window
Redis rate limiter keyed per tool, per scope (consumer or global). It runs on
three stages (`MandatoryStages`/`SupportedStages` = PreRequest, PreResponse,
PostResponse — `plugin.go:89-95`) and only in `ModeEnforce` (`plugin.go:97-99`).

### Counting (the bug)

- Counting happens in **PostResponse** (`plugin.go:330-362`). It calls
  `calledTools(format, resp)` (`plugin.go:364-416`) which decodes the **LLM
  response** and returns the names of every `tool_calls` entry the model
  proposed (non-streaming: `DecodeResponseFor` → `canonical.ToolCalls`;
  streaming: `streamToolNames` accumulates `ToolCallDeltas` by index).
- For each returned name it matches a rule (`matchRule`, glob via `path.Match`
  with `/`→sentinel, `plugin.go:495-510`) and, per window, runs `recordScript`
  (INCR by 1 + set EXPIRE only when TTL == -1) — `plugin.go:349-359`.
- **Root cause**: this counts *model proposals* (assistant `tool_calls`), not
  actual downstream executions. A proposed call that is cancelled / fails client
  validation / aborts still burns quota.
- PostResponse runs **asynchronously after the response is flushed**
  (`pkg/app/proxy/plugin_runner.go:128-162`, `firePostResponse` in a detached
  goroutine with a 30s timeout; streaming buffers up to 8 MiB then fires —
  `wrapStreamWithPostResponse:164-206`). This is why the functional tests use
  `require.Eventually`.

### Enforcement

- **PreRequest** (`plugin.go:130-179`): decodes the request, and for each
  declared tool whose rule is "enforced at request" (`enforcedAtRequest`,
  `plugin.go:181-190`: reject + strip always; inject only when streaming),
  checks `overLimit` (GET each window key, over when `>= Max`,
  `plugin.go:418-434`). `reject_response` → `PluginError` 429 with
  `X-RateLimit-*` + `Retry-After` headers (`reject`, `plugin.go:436-452`);
  `strip_tool_from_request` → removes the tool from the request body
  (`stripTools`+`graftChangedFields`, `plugin.go:192-252`, preserving
  non-canonical fields).
- **PreResponse** (`plugin.go:254-299`): non-streaming only; for
  `inject_error_result` rules over budget it drops the offending `tool_calls`
  from the response and appends a templated assistant message
  (`inject`/`rateLimitTemplate`, `plugin.go:301-328`, `data.go:17`), setting
  `StopUpstream`.
- So today: **enforce reads the counter (PreRequest/PreResponse), count writes
  the counter (PostResponse)** — but the write is keyed on the wrong event.

### Config / scope / Redis

- `config.go`: `rules[]` (tool glob, `windows[]` of `{duration, max}`,
  optional `behavior`), `behavior_default` (default `reject_response`),
  informational `scope`. Durations must be a whole number of ≥1s. Behaviors:
  `reject_response`, `inject_error_result`, `strip_tool_from_request`.
- Scope/subject derived from `RuntimeScope` (`app/plugins/plugin.go:78-98`) —
  `global`→gatewayID or `consumer`→consumerID; never from request data.
- Redis key: `pertoolrl:{configID}:{dimension}:{subject}:{tool}:w{window}`
  (`counterKey`, `plugin.go:480-482`). Fixed window via `recordScript`
  (`plugin.go:39-48`): `INCRBY key tokens`; `EXPIRE` only if `TTL == -1` so the
  window is anchored to the first increment. `data.go` = event extras struct.

### MCP path (uncovered)

- `tools/call` is dispatched in `pkg/api/handler/http/mcp/rpc_dispatcher.go:129-147`:
  `PreRequest` → `composer.CallTool` (upstream) → `PreResponse`. **No
  PostResponse stage exists on the MCP path.**
- `pkg/app/mcp/plugin_runner.go` builds a `RequestContext` with
  `Provider:""`, `SourceFormat:""`, `MCP:true`, and
  `Body = {"name":..., "arguments":...}` (`buildRequestContext:166-187`).
- The plugin no-ops because `wireFormat(req)` returns `""` when both
  `SourceFormat` and `Provider` are empty (`plugin.go:519-527`), so every stage
  short-circuits to `okResult()`. The plugin also never sees a canonical
  `tools/call`; it only understands the LLM canonical decoders.
- MCP fails **open** on non-block errors (`logFailOpen`), and only `PreRequest`
  can block before upstream; `PreResponse` runs after upstream success.

### Cross-provider mapping is available (key enabler)

Both request decoders preserve the `tool_call_id → tool name` chain inside a
single canonical request, so "count on the next turn's tool results" is
resolvable **without external state**:

- `canonical.go:42-70`: `CanonicalMessage{Role, Content, ToolCalls[], ToolCallID}`,
  `CanonicalToolCall{ID, Name, Arguments}`.
- OpenAI request decode maps `role:"tool"` messages' `tool_call_id` and the
  assistant message's `tool_calls[].id/name`
  (`openai_completions_adapter.go:188-202`).
- Anthropic request decode turns `tool_result` blocks into `Role:"tool"` +
  `ToolCallID = tool_use_id`, and `tool_use` blocks into assistant `tool_calls`
  (`anthropic_adapter.go:226-263`).

So on turn N+1 the canonical `Messages` contain both the assistant
`tool_calls` (id→name) and the `role:"tool"` results (tool_call_id), letting the
plugin resolve executed tool names locally.

## Affected Areas

- `pkg/infra/plugins/pertoolratelimit/plugin.go` — move counting off response
  `tool_calls`; add LLM "count executed tool results on the next request" and
  MCP counting; revisit enforcement timing; teach `wireFormat`/`Execute` about
  `in.Request.MCP`.
- `pkg/infra/plugins/pertoolratelimit/config.go` / `data.go` — possible new
  fields (e.g. idempotency), event extras for the new counting point.
- `pkg/infra/plugins/pertoolratelimit/plugin_test.go` — unit tests currently
  assert PostResponse counts response `tool_calls` (e.g.
  `TestPlugin_PostResponse_CountsNonStreaming/Streaming/EachToolCall`,
  `TestPlugin_FullCycle_CountThenReject`) — must be rewritten for the new model.
- `pkg/app/mcp/plugin_runner.go` — populate MCP request context so the plugin
  can act (wire a format/flag), and decide whether counting needs a post-upstream
  hook (PreResponse already runs after `CallTool`, or add a PostResponse).
- `pkg/api/handler/http/mcp/rpc_dispatcher.go:129-147` — the only `tools/call`
  call site; where any new MCP counting/enforcement ordering lands.
- `pkg/app/proxy/plugin_runner.go` / `forwarder.go:145,476,546` — LLM stage
  timing (PreRequest gate, PreResponse gate, async PostResponse); relevant if
  counting moves to PreRequest of the next turn.
- `pkg/infra/providers/adapter/{canonical,openai_completions_adapter,anthropic_adapter}.go`
  — read-only; the mapping types the redesign relies on (no change expected).
- `pkg/container/modules/plugins.go:95` (DI wiring) and
  `pkg/container/modules/mcp.go:126` (PluginRunner) — wiring only changes if new
  deps are introduced.
- `pkg/app/plugins/catalog_metadata.go:418-497` — catalog copy says "per
  observed tool call in model responses" / behavior descriptions tied to
  PreRequest/PreResponse; must be reworded to "executions".
- `tests/functional/plugin_per_tool_rate_limiter_test.go` — E2E flows assume the
  upstream tool_calls response is what counts; must add a follow-up turn with
  `role:"tool"` results (and MCP coverage).
- `postman/TrustGate.postman_collection.json` — sample/docs copy.

## Approaches — LLM counting redesign

1. **Count executed tool results on the next request (PreRequest), enforce on the same PreRequest**
   - On PreRequest, scan canonical `Messages` for `role:"tool"` entries; resolve
     each `tool_call_id` to a name via the assistant `tool_calls` in the same
     message list; INCR those tools; then evaluate `overLimit` and
     reject/strip/inject for the tools *declared* in this same request.
   - Pros: uses only in-request data (no new state); single stage; naturally
     aligns "count then enforce"; works for streaming too (results arrive in the
     next request body, not the stream); cross-provider via canonical mapping.
   - Cons: quota is consumed one turn late (an over-budget tool executes once
     more before the counter catches up — bounded, arguably acceptable);
     idempotency risk if the same conversation/turn is retried or replayed
     (double counting) — needs a dedupe key (e.g. `tool_call_id`) with a TTL set;
     agents that never send results back through the gateway are never counted
     (explicitly out of scope).
   - Effort: Medium.

2. **Two-stage: count on next-turn PreRequest, keep PostResponse for enforcement bookkeeping**
   - Same counting source as (1) but split responsibilities across stages as
     today.
   - Pros: smaller diff to enforcement code; keeps async PostResponse for
     metrics/extras.
   - Cons: PostResponse is async/detached and can be dropped (timeout, >8 MiB
     stream truncation) → unreliable for anything authoritative; ordering
     between the async write and the next PreRequest read is racy. Not suitable
     if PostResponse must count.
   - Effort: Medium.

3. **Persist a pending-execution ledger on PostResponse, reconcile on the next request**
   - PostResponse records proposed `tool_call_id`s as "pending"; the next
     request confirms which ran (has a matching `role:"tool"`) and only then
     INCRs; unconfirmed/cancelled ones expire.
   - Pros: closest to "true executions"; can distinguish proposed-but-cancelled
     precisely; natural idempotency via the ledger id.
   - Cons: most complex; extra Redis structures + TTL lifecycle; relies on the
     unreliable async PostResponse to seed the ledger; more moving parts to test.
   - Effort: High.

## Approaches — MCP counting redesign

A. **Count + enforce in the existing MCP stages, keyed on `params.name`**
   - Teach the plugin to detect `in.Request.MCP` and parse
     `{"name","arguments"}` to get the tool name (bypassing canonical LLM
     decoders / `wireFormat`). Enforce (reject/strip-equivalent) in **PreRequest**
     (before `CallTool`) via `overLimit`; **count in PreResponse** (runs only
     after upstream success — true execution evidence).
   - Pros: matches "count on native tools/call after upstream succeeds"; no new
     dispatcher stage; reuses PreRequest for the 429/deny; MCP already fails open
     safely.
   - Cons: `strip_tool_from_request` and `inject_error_result` have no clean MCP
     analogue (MCP is a single tool call, not a tool list / assistant message) —
     needs a defined mapping (likely both collapse to a JSON-RPC block/deny on
     MCP); PreResponse currently is a block gate, so counting-in-PreResponse must
     not accidentally block.
   - Effort: Medium.

B. **Add a dedicated PostResponse hook to the MCP dispatcher for counting**
   - Extend `PluginRunner` with `PostResponse` and call it after
     `composer.CallTool` succeeds in `rpc_dispatcher.go`; count there, enforce in
     PreRequest.
   - Pros: clean separation (enforce=Pre, count=Post) mirroring the LLM stage
     names; keeps PreResponse purely a block gate.
   - Cons: larger surface (dispatcher + runner + wiring); a synchronous
     PostResponse adds latency unless detached; MCP has no existing PostResponse
     semantics to reuse.
   - Effort: Medium/High.

C. **Optimistic count in PreRequest (before exec), refund on upstream failure**
   - INCR in PreRequest then decrement if `CallTool` errors.
   - Pros: single stage; enforcement and counting co-located.
   - Cons: refund logic is racy/error-prone; a crash between INCR and refund
     over-counts; contradicts "count after upstream success". Not recommended.
   - Effort: Medium.

## Recommendation (for the orchestrator to confirm)

- **LLM**: Approach **1** (count executed `role:"tool"` results on the next
  request's PreRequest, enforce declared tools in the same PreRequest), with an
  explicit `tool_call_id`-based dedupe key (TTL-bounded) for idempotency. It
  needs no new persistent state and works across OpenAI/Anthropic via the
  existing canonical mapping. Avoid relying on the async PostResponse for
  authoritative counting.
- **MCP**: Approach **A** (enforce in PreRequest keyed on `params.name`, count in
  PreResponse after `CallTool` succeeds), teaching the plugin to read
  `in.Request.MCP`. Add a defined behavior mapping for MCP (reject/deny vs.
  strip/inject which don't map 1:1). Approach **B** is the fallback if
  count-in-PreResponse proves awkward against its block-gate contract.

## Risks

- **Idempotency / double counting**: retried or replayed conversations resend the
  same `role:"tool"` results; without a dedupe key the same execution is counted
  repeatedly. Fixed-window + Redis TTL stays (per issue), but the dedupe set adds
  Redis keys.
- **Late enforcement (LLM)**: counting one turn late lets an over-budget tool run
  once more before the limit trips; confirm this is acceptable vs. today's
  proposal-time behavior.
- **Async PostResponse unreliability**: it is detached, timeout-bounded, and
  streaming bodies >8 MiB are dropped (`plugin_runner.go:198-201`) — do not make
  it the authoritative counter.
- **Behavior semantics on MCP**: `strip_tool_from_request` and
  `inject_error_result` have no direct MCP equivalent; leaving them undefined
  risks silent no-ops on the MCP path.
- **Streaming**: with execution-based counting, `streamToolNames` becomes
  unnecessary for counting (results come back on the next request), but confirm
  no other consumer depends on it.
- **Behavior/test churn**: existing unit + functional tests encode the old
  counting contract and will fail until rewritten; catalog/Postman copy must
  change in lockstep to avoid contradicting behavior.

## Open Questions (do NOT resolve — for the orchestrator)

- LLM: is counting on `role:"tool"` result messages reliable across providers,
  and is `tool_call_id`→name resolution guaranteed (missing/duplicate ids)?
  What is the idempotency key and its TTL vs. the window TTL?
- LLM: which stage should now enforce, given counting moves to the next-request
  observation (PreRequest-only, or keep PreResponse inject)?
- MCP: count in PreRequest (optimistic, pre-exec) or PreResponse/PostResponse
  (post-exec)? How do reject/strip/inject behaviors map onto a single MCP
  `tools/call`?
- De-dup / double-count across retries and streaming reconnects — one shared
  mechanism for LLM and MCP, or separate?
