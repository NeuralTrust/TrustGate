# Proposal: per_tool_rate_limiter counts real tool executions (LLM + MCP) — RUN-965

## Intent

`per_tool_rate_limiter` (`pkg/infra/plugins/pertoolratelimit`) charges Redis quota
in `post_response` from the assistant `tool_calls` the LLM *proposed*, not from
tools that actually ran. A proposal that is cancelled, fails client validation, or
never executes still burns quota. Separately, the plugin is a complete no-op on the
MCP `tools/call` path: MCP requests carry no `Provider`/`SourceFormat`, so
`wireFormat` returns `""` and every stage short-circuits. This change makes the
limiter count **real executions** on both paths, keeping the fixed-window + Redis
TTL algorithm unchanged.

## Scope

### In Scope
- **LLM path**: count executed tools on `pre_request` from `role:"tool"` result
  messages; remove `post_response` counting of proposed `tool_calls`.
- **LLM idempotency**: `tool_call_id`-based dedupe via Redis `SET NX EX` before INCR.
- **MCP path**: detect `in.Request.MCP`, parse `{ "name", "arguments" }`, enforce in
  `pre_request` and count in `pre_response` (after `CallTool` succeeds).
- **Behavior mapping** for MCP: all behaviors collapse to deny/block.
- Update catalog copy, Postman collection, unit and functional tests in lockstep.

### Out of Scope (Non-goals)
- Client-side executions that never return through the gateway (uncountable).
- Any change to the fixed-window / Redis-TTL algorithm.
- New window algorithms, scope model changes, or UI redesign.
- Adding a `post_response` stage to the MCP dispatcher.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- None (spec-level rate-limit contract unchanged; this is a counting-source and
  transport-coverage correction).

## Approach

**LLM (count-then-enforce, single `pre_request` stage).** Decode the canonical
request; scan `Messages` for `role:"tool"` entries; resolve each `ToolCallID` to a
tool name via the assistant `tool_calls` (id→name) present in the same message list.
For each executed tool, run a Redis `SET dedupeKey <v> NX EX <ttl>` where the key
encodes config/scope/subject/`tool_call_id` and `ttl` = the largest configured
window duration for that rule; INCR the window counters **only when the NX set
succeeds** (first observation). Then enforce the tools *declared* in this same
`pre_request`. The `post_response` counting path (and `streamToolNames`/stream
counting used only for counting) is removed. Counting relies solely on in-request
canonical data — no new persistent ledger — and works across OpenAI/Anthropic via
the existing `tool_call_id → name` mapping in the request adapters.

**MCP (enforce pre, count post-exec).** Teach the plugin to detect
`in.Request.MCP == true` and parse the `{ "name", "arguments" }` body directly for
the tool name, bypassing `wireFormat`/canonical LLM decoders. Enforce in
`pre_request` before upstream `CallTool`: over-limit returns a `PluginError` that
the MCP `PluginRunner` maps to a JSON-RPC block. Count in `pre_response`, which runs
only after `CallTool` succeeds (= a real execution), keyed on `params.name`. Each
`tools/call` is exactly one execution, so MCP counts once per `pre_response` with no
dedupe key.

**De-dup is separate by design.** LLM dedupes by `tool_call_id` (results can be
replayed across turns/retries); MCP counts once per `pre_response` invocation.

## What Stays Unchanged
- Fixed-window counting with Redis TTL anchored to first increment (`recordScript`).
- Scope model (`consumer` → consumerID, `global` → gatewayID) from `RuntimeScope`.
- Config schema (`rules[]`, `windows[]`, `behavior`, `behavior_default`) and the
  `X-RateLimit-*` / `Retry-After` response headers on reject.
- Redis key layout `pertoolrl:{configID}:{dimension}:{subject}:{tool}:w{window}`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/pertoolratelimit/plugin.go` | Modified | Move LLM counting to `pre_request` from `role:"tool"` results; add `tool_call_id` NX dedupe; teach `wireFormat`/`Execute` about `in.Request.MCP`; add MCP `pre_request` enforce + `pre_response` count; remove `post_response` counting and count-only stream path. |
| `pkg/infra/plugins/pertoolratelimit/config.go` / `data.go` | Modified | Optional idempotency/dedupe config; event extras for the new counting point. |
| `pkg/app/mcp/plugin_runner.go` | Modified | Ensure MCP `RequestContext` lets the plugin act on `tools/call` (flag/body already set); confirm `pre_response` runs post-`CallTool`. |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Read/verify | Sole `tools/call` site; PreRequest→CallTool→PreResponse ordering the MCP counting relies on. No `post_response`. |
| `pkg/app/proxy/plugin_runner.go` | Read/verify | LLM stage timing; ensure counting moved into `pre_request` gate, not async `post_response`. |
| `pkg/app/plugins/catalog_metadata.go` | Modified | Reword copy from "per observed tool call in model responses" to real executions; MCP deny/block behavior. |
| `pkg/infra/plugins/pertoolratelimit/plugin_test.go` | Modified | Rewrite tests that assert `post_response` counts response `tool_calls`. |
| `tests/functional/plugin_per_tool_rate_limiter_test.go` | Modified | Add next-turn `role:"tool"` result flows + MCP `tools/call` coverage. |
| `postman/TrustGate.postman_collection.json` | Modified | Sample/doc copy aligned to execution counting. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| LLM enforcement is one turn late (over-budget tool runs once more before counter catches up). | Med | Bounded by one execution per tool; documented and accepted per RUN-965. |
| Retried/replayed conversations double-count executions. | Med | `tool_call_id` NX dedupe with TTL = largest window duration. |
| `tool_call_id → name` unresolved (missing/duplicate ids). | Low | Resolve within the same request's `tool_calls`; skip counting when unresolved rather than mis-charge. |
| MCP behaviors (`strip_tool_from_request`, `inject_error_result`) have no single-`tools/call` analogue. | Med | Collapse all MCP behaviors to deny/block; state explicitly; aligns with RUN-966 (MCP-first plugin). |
| Catalog/Postman/test copy drifts from new semantics. | Med | Change all copy and tests in lockstep with the plugin. |

## Rollback Plan

Revert the plugin, config/data, catalog, Postman, and test changes in one commit.
Redis keys are unchanged in layout; the new `tool_call_id` dedupe keys expire on
their own TTL and are harmless if left. No migration or schema change to undo.

## Dependencies

- Existing canonical request adapters (`openai_completions_adapter`,
  `anthropic_adapter`, `canonical`) preserve the `tool_call_id → name` chain
  (read-only; no change expected).
- Alignment note: RUN-966 makes this plugin MCP-first, consistent with the MCP
  deny/block behavior mapping introduced here.

## Success Criteria

- [ ] LLM quota is charged only for tools that actually returned a `role:"tool"`
      result, once per `tool_call_id`, across OpenAI and Anthropic.
- [ ] `post_response` counting and count-only stream handling are removed.
- [ ] MCP `tools/call` enforces in `pre_request` and counts once per successful
      execution in `pre_response`, keyed on `params.name`.
- [ ] MCP over-limit returns a JSON-RPC block; all MCP behaviors map to deny.
- [ ] Fixed-window/TTL, scope, config schema, headers, and key layout unchanged.
- [ ] Catalog, Postman, unit and functional tests reflect execution semantics.
