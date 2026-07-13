# Design: per_tool_rate_limiter counts real tool executions (LLM + MCP) — RUN-965

Design phase for the counting-source + transport-coverage correction described in
`proposal.md`. Authoritative inputs (decisions not reopened here): `proposal.md`,
`explore.md`. Binding conventions: `.agents/AGENT.md` (§4 DI, §10 DTO/app layout,
§11 **no code comments — not even Go doc comments**, hook-stripped) and the
`golang-pro` skill (ctx-first, `%w` wrapping, sentinel errors, small interfaces,
table-driven `-race` tests, explicit goroutine lifecycles). All Go shapes below
are comment-free by design.

---

## 1. Chosen approach

**LLM — count-then-enforce in a single `pre_request` stage (explore Approach 1).**
On `pre_request` decode the canonical request and count only the executed tool
results of the *latest* turn: find the index of the last assistant message that
carries `tool_calls` and count only the `role:"tool"` results after it (the
`tool_call_id → name` map is still built from assistant `tool_calls` across the
whole history for resolution robustness). Each executed `tool_call_id` is deduped
and its window counters incremented in one atomic `countOnceScript` Lua call
(`SET NX EX` on the dedupe key, and only when fresh, `INCRBY`+conditional
`EXPIRE` across the window keys). Then run the existing enforce-declared-tools
logic. `post_response` counting (`postResponse`, `calledTools`, `streamToolNames`,
SSE scan) is removed.

**MCP — enforce in `pre_request`, count in `pre_response` (explore Approach A).**
Detect `in.Request.MCP`, parse `{ "name", "arguments" }` directly (bypassing
`wireFormat`/canonical LLM decoders). `pre_request` runs `overLimit` on
`params.name` and, when over, returns a `PluginError` that the MCP `PluginRunner`
maps to a JSON-RPC block. `pre_response` (which runs only after `CallTool`
succeeds) counts once on `params.name`. All MCP behaviors collapse to deny/block.

### Rejected alternatives (from `explore.md`)

| Alternative | Why not |
|---|---|
| LLM Approach 2 — keep async `PostResponse` for counting bookkeeping | `PostResponse` is detached, 30s-timeout-bounded and drops streams > 8 MiB; unreliable as the authoritative counter and racy vs. the next `PreRequest` read. |
| LLM Approach 3 — persistent pending-execution ledger reconciled next turn | Highest effort; extra Redis structures + TTL lifecycle; still seeded by the unreliable async `PostResponse`. Over-engineered for RUN-965. |
| MCP Approach B — new dedicated `PostResponse` hook on the MCP dispatcher | Larger surface (dispatcher + runner + wiring); MCP has no existing `PostResponse` semantics to reuse; `PreResponse` already runs post-`CallTool`. |
| MCP Approach C — optimistic count in `PreRequest`, refund on failure | Refund is racy; a crash between INCR and refund over-counts; contradicts "count after upstream success". |

---

## 2. Change plan — `pkg/infra/plugins/pertoolratelimit/plugin.go`

### 2.1 Stage declaration

`MandatoryStages`/`SupportedStages` drop `StagePostResponse`. The LLM path no
longer needs it (counting moved to `PreRequest`); MCP only uses `PreRequest` +
`PreResponse`.

```go
func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}
```

### 2.2 `Execute` dispatch — MCP branch before wire-format gating

MCP requests carry `Provider=""`/`SourceFormat=""`, so `wireFormat` returns `""`
and the LLM decoders no-op. Branch on `in.Request.MCP` first; delete the
`StagePostResponse` case (falls through to `okResult()`).

```go
switch in.Stage {
case policy.StagePreRequest:
	if in.Request != nil && in.Request.MCP {
		return p.mcpPreRequest(ctx, cfg, in, dimension, subject)
	}
	return p.preRequest(ctx, cfg, in, dimension, subject)
case policy.StagePreResponse:
	if in.Request != nil && in.Request.MCP {
		return p.mcpPreResponse(ctx, cfg, in, dimension, subject)
	}
	return p.preResponse(ctx, cfg, in, dimension, subject)
default:
	return okResult(), nil
}
```

### 2.3 LLM `pre_request` — count executed tool results, then enforce

`preRequest` already decodes the canonical request for enforcement. Reuse that
decode: **count first** from `canonical.Messages`, **then** run the unchanged
enforce-declared-tools loop over `canonical.Tools`.

New counting step (inserted after the successful `DecodeRequestFor`, before the
`strip` loop). Note: the current early return `len(canonical.Tools) == 0` must be
relaxed so a turn that carries results but re-declares no tools still counts —
gate counting on `len(canonical.Messages) > 0` and keep the `Tools`-empty short
circuit only for the enforce loop. A Redis error from counting is wrapped and
returned (fail-closed, matching the enforce loop's `overLimit` handling).

```go
if err := p.countExecuted(ctx, cfg, in, dimension, subject, canonical.Messages); err != nil {
	return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
}
```

Name resolution + counting:

```go
func toolCallNames(messages []adapter.CanonicalMessage) map[string]string {
	names := make(map[string]string)
	for i := range messages {
		for j := range messages[i].ToolCalls {
			tc := messages[i].ToolCalls[j]
			if tc.ID == "" || tc.Name == "" {
				continue
			}
			names[tc.ID] = tc.Name
		}
	}
	return names
}

func latestToolCallTurn(messages []adapter.CanonicalMessage) int {
	last := -1
	for i := range messages {
		if len(messages[i].ToolCalls) > 0 {
			last = i
		}
	}
	return last
}

func (p *Plugin) countExecuted(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
	messages []adapter.CanonicalMessage,
) error {
	turn := latestToolCallTurn(messages)
	if turn < 0 {
		return nil
	}
	names := toolCallNames(messages)
	for i := turn + 1; i < len(messages); i++ {
		if messages[i].Role != "tool" || messages[i].ToolCallID == "" {
			continue
		}
		tool, ok := names[messages[i].ToolCallID]
		if !ok || tool == "" {
			continue
		}
		rule, ok := matchRule(cfg.Rules, tool)
		if !ok {
			continue
		}
		if err := p.recordOnce(ctx, cfg, in, dimension, subject, tool, messages[i].ToolCallID, rule); err != nil {
			return err
		}
	}
	return nil
}
```

`recordOnce` dedupes and counts atomically in one `countOnceScript` Lua call
(`SET NX EX` on the dedupe key; only when fresh, `INCRBY`+conditional `EXPIRE`
per window key — see §3 for keys and the script):

```go
func (p *Plugin) recordOnce(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject, tool, toolCallID string,
	rule *ruleConfig,
) error {
	keys := make([]string, 0, len(rule.Windows)+1)
	keys = append(keys, dedupeKey(in.Config.ID, dimension, subject, toolCallID))
	args := make([]any, 0, len(rule.Windows)+1)
	args = append(args, int(largestWindow(rule)/time.Second))
	for i := range rule.Windows {
		keys = append(keys, counterKey(in.Config.ID, dimension, subject, tool, i))
		args = append(args, rule.Windows[i].windowSeconds())
	}
	res, err := countOnceScript.Run(ctx, p.redis, keys, args...).Result()
	if err != nil {
		return err
	}
	totals, ok := res.([]any)
	if !ok || len(totals) == 0 {
		return nil
	}
	behavior := effectiveBehavior(rule, cfg)
	for i := range rule.Windows {
		if i >= len(totals) {
			break
		}
		total, _ := totals[i].(int64)
		w := rule.Windows[i]
		key := counterKey(in.Config.ID, dimension, subject, tool, i)
		ws := &windowState{key: key, window: w, total: int(total)}
		setExtras(in.Event, p.data(policy.StagePreRequest, ws, tool, toolCallID, dimension, subject, behavior, int(total) >= w.Max))
	}
	return nil
}
```

Design notes:
- **Latest-batch counting** bounds long agent loops: only the results after the
  most-recent assistant `tool_calls` turn are charged, so an older result that
  reappears in a long conversation (after its dedupe key has expired) is never
  re-counted. Correctness no longer depends on the dedupe TTL.
- **Count-then-enforce ordering** matches the old two-stage contract in one stage:
  a result observed this turn is counted before the same turn's re-declared tools
  are checked against the counter.
- **Dedupe + count is atomic.** `countOnceScript` performs the `SET NX EX` and the
  per-window `INCRBY`/`EXPIRE` in a single Lua execution: an empty return means the
  `tool_call_id` was already seen (duplicate/exact retry within TTL) and nothing is
  charged; a non-empty return carries the per-window totals. There is no window
  where the dedupe key is set but a later window INCR is skipped, so per-window
  counters can never diverge. The dedupe key remains a cheap idempotency guard
  against an exact request retry within the TTL.
- **Unresolved / duplicate ids** are skipped (never mis-charged) — matches the
  RUN-965 risk mitigation. Duplicate ids collapse in the map (last-wins) and are
  deduped by the shared `tool_call_id` key regardless.
- **Cross-provider**: relies only on the canonical mapping already produced by the
  OpenAI (`role:"tool"` + `tool_call_id`; assistant `tool_calls[].id/name`) and
  Anthropic (`tool_result` → `Role:"tool"`+`ToolCallID`; `tool_use` → assistant
  `tool_calls`) request decoders. No adapter change.

The existing enforce loop (`overLimit` → `reject` / `stripTools`, and streaming
`inject` degradation) is **kept verbatim**.

### 2.4 LLM `pre_response` — unchanged

`preResponse` keeps the non-streaming `inject_error_result` enforcement
(drop over-budget proposed `tool_calls`, append the templated message,
`StopUpstream`). It reads the counter that `pre_request` now writes. No counting
happens here for the LLM path.

### 2.5 Remove `post_response` counting

Delete: `postResponse`, `calledTools`, `streamToolNames`, `ssePayload`, and the
`sseDataPrefix`/`sseDoneMarker` vars (confirmed used **only** inside this package —
`tokenratelimit`/`semanticcache` have their own separate copies; grep shows no
cross-package consumer). The `StagePostResponse` `Execute` case is removed.

### 2.6 MCP `pre_request` — enforce, deny on over-limit

```go
type mcpToolCallBody struct {
	Name string `json:"name"`
}

func (p *Plugin) mcpToolName(body []byte) string {
	var b mcpToolCallBody
	if err := json.Unmarshal(body, &b); err != nil {
		return ""
	}
	return b.Name
}

func (p *Plugin) mcpPreRequest(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	tool := p.mcpToolName(in.Request.Body)
	if tool == "" {
		return okResult(), nil
	}
	rule, ok := matchRule(cfg.Rules, tool)
	if !ok {
		return okResult(), nil
	}
	ws, err := p.overLimit(ctx, in.Config.ID, dimension, subject, tool, rule)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
	}
	if ws == nil {
		return okResult(), nil
	}
	setExtras(in.Event, p.data(policy.StagePreRequest, ws, tool, dimension, subject, effectiveBehavior(rule, cfg), true))
	return p.reject(ctx, tool, ws, dimension)
}
```

`reject` returns the existing `*PluginError` (429 + `X-RateLimit-*`/`Retry-After`
headers). On the MCP path the `PluginRunner.PreRequest` maps any `PluginError` via
`blockToRPCError` to JSON-RPC `-32001` and the dispatcher skips `CallTool`.
**Behavior collapse:** the configured `behavior` (`reject`/`strip`/`inject`) is
ignored on MCP — a single `tools/call` has no tool-list to strip and no assistant
message to rewrite; all map to deny/block. The `data.behavior` field still records
the configured value for observability.

### 2.7 MCP `pre_response` — count once, never block

```go
func (p *Plugin) mcpPreResponse(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	tool := p.mcpToolName(in.Request.Body)
	if tool == "" {
		return okResult(), nil
	}
	rule, ok := matchRule(cfg.Rules, tool)
	if !ok {
		return okResult(), nil
	}
	behavior := effectiveBehavior(rule, cfg)
	for i := range rule.Windows {
		w := rule.Windows[i]
		key := counterKey(in.Config.ID, dimension, subject, tool, i)
		total, err := recordScript.Run(ctx, p.redis, []string{key}, 1, w.windowSeconds()).Int64()
		if err != nil {
			return nil, fmt.Errorf("per_tool_rate_limiter: record: %w", err)
		}
		ws := &windowState{key: key, window: w, total: int(total)}
		setExtras(in.Event, p.data(policy.StagePreResponse, ws, tool, dimension, subject, behavior, int(total) >= w.Max))
	}
	return okResult(), nil
}
```

- Reached **only after `CallTool` succeeds** (`rpc_dispatcher.go:140-147`) = one
  real execution, so **no dedupe key** — each `tools/call` is counted exactly once.
- Always returns `okResult()` (no `StopUpstream`, 200) so counting can never turn
  into a block; the MCP runner treats a non-error `PreResponse` as pass-through.

> PHASE 1 removed the standalone `recordScript`. The MCP `pre_response` counting
> (PHASE 2, not yet implemented) will INCR the window counters via an atomic Lua
> script with no dedupe key (a single-key variant of `countOnceScript`); the sketch
> above uses `recordScript` only to describe the per-window `INCRBY`+conditional
> `EXPIRE` semantics.

### 2.8 Kept unchanged

`overLimit`, `counterKey`, `reject`, `stripTools`/
`graftChangedFields`, `inject`/`rateLimitTemplate`, `matchRule`/`matchToolPattern`,
`effectiveBehavior`, scope/subject via `RuntimeScope.Subject()`, `setLimitHeaders`
and all `X-RateLimit-*` headers, and the full config schema. (`recordScript` is
replaced by the atomic `countOnceScript`; see §2.3 / §3.)

---

## 3. Redis key design

**Existing (unchanged).** Fixed-window counters:

```
pertoolrl:{configID}:{dimension}:{subject}:{tool}:w{window}
```

anchored to first increment by `countOnceScript` (`EXPIRE` only when `TTL == -1`).

**New — LLM dedupe key** (LLM path only; MCP does not dedupe):

```
pertoolrl:dedupe:{configID}:{dimension}:{subject}:{tool_call_id}
```

Set with `SET <key> 1 NX EX <ttl>` (inside `countOnceScript`). `tool_call_id` is
unique per model tool call, so the tool name is intentionally omitted from the key.

**TTL = the largest configured window duration of the matched rule.**

```go
func dedupeKey(configID, dimension, subject, toolCallID string) string {
	return fmt.Sprintf("pertoolrl:dedupe:%s:%s:%s:%s", configID, dimension, subject, toolCallID)
}

func largestWindow(rule *ruleConfig) time.Duration {
	largest := 0
	for i := range rule.Windows {
		if s := rule.Windows[i].windowSeconds(); s > largest {
			largest = s
		}
	}
	return time.Duration(largest) * time.Second
}
```

Rationale: **correctness is bounded by latest-batch counting, not by the TTL.**
Only the results after the most-recent assistant `tool_calls` turn are counted, so
an old `role:"tool"` result reappearing in a long conversation is never re-counted
even after its dedupe key expires. The dedupe key is a secondary idempotency guard
against an exact request retry (the client resending the identical latest turn)
within the TTL; the largest window is a safe TTL for that guard because any counter
the first observation incremented is still open for at least that long. Keys are
disjoint-per-`(config,scope,subject)` and self-expiring — the rollback plan needs
no cleanup.

**Adopted — atomic `countOnceScript`.** Dedupe and per-window counting run in one
Lua execution: `SET NX EX` on `KEYS[1]` and, only when fresh, `INCRBY`+conditional
`EXPIRE` across `KEYS[2..N+1]`, returning the per-window totals (empty when the id
was already seen). This removes the earlier two-step (`SET NX` then a separate
per-window `recordScript` loop) whose failure between steps could leave the dedupe
key set while some windows went uncharged, diverging the per-window counters.

```
KEYS = [dedupeKey, windowKey0, windowKey1, ...]
ARGV = [dedupeTTL, win0Secs, win1Secs, ...]
```

---

## 4. `config.go` / `data.go`

- **`config.go`: no new user-facing config.** No idempotency knob is exposed —
  dedupe TTL derives from the rule's largest window, so there is nothing to
  configure. Schema (`rules[]`, `windows[]`, `behavior`, `behavior_default`,
  informational `scope`) and all validation stay identical.
- **`data.go`: event extras for the new counting point.** `PerToolRateLimiterData`
  is reused as-is; the `Stage` field now carries `pre_request` (LLM counting) or
  `pre_response` (MCP counting) instead of `post_response`. Add one optional field
  to make execution-counting traceable without a schema break:

```go
type PerToolRateLimiterData struct {
	Stage         string `json:"stage"`
	CounterKey    string `json:"counter_key"`
	Tool          string `json:"tool"`
	ToolCallID    string `json:"tool_call_id,omitempty"`
	Dimension     string `json:"dimension"`
	Subject       string `json:"subject"`
	WindowMax     int    `json:"window_max"`
	WindowSeconds int    `json:"window_seconds"`
	CurrentCount  int    `json:"current_count"`
	Behavior      string `json:"behavior"`
	LimitExceeded bool   `json:"limit_exceeded"`
}
```

`ToolCallID` is populated by LLM counting (`recordOnce`) and left empty for MCP and
for enforcement events. `p.data(...)` gains the extra argument (or a dedicated
`p.countData(...)` builder) — minimal, additive. If even this is deemed out of
scope, `data.go` stays untouched and only `Stage` semantics change.

---

## 5. MCP wiring — `pkg/app/mcp/plugin_runner.go` (+ dispatcher)

**No change required.** The runner already:

- Sets `MCP: true`, `Provider:""`, `SourceFormat:""`, and
  `Body = {"name","arguments"}` in `buildRequestContext` — exactly what
  `mcpPreRequest`/`mcpPreResponse` parse.
- Maps any `*PluginError` from `PreRequest` to a JSON-RPC block via
  `blockToRPCError` (`-32001`), and fails open on non-block errors (`logFailOpen`).
- Calls `PreResponse` **after** `composer.CallTool` succeeds
  (`rpc_dispatcher.go:140-147`: `PreRequest → CallTool → PreResponse`), which is the
  real-execution evidence the MCP counting relies on.

`rpc_dispatcher.go` is read/verify only — it is the sole `tools/call` site and
already provides the `PreRequest → CallTool → PreResponse` ordering with **no**
`PostResponse` stage. `pkg/app/proxy/plugin_runner.go` is read/verify only:
confirms LLM counting now lands inside the synchronous `PreRequest` gate rather
than the async `PostResponse` goroutine. DI wiring (`pkg/container/modules/*`) is
untouched — no new dependencies.

---

## 6. File-change table

| Path | What changes | New/Modified |
|---|---|---|
| `pkg/infra/plugins/pertoolratelimit/plugin.go` | Drop `PostResponse` from stages + `Execute`; remove `postResponse`/`calledTools`/`streamToolNames`/`ssePayload`/SSE vars; add `toolCallNames`, `countExecuted`, `recordOnce`, `dedupeKey`, `largestWindow` (LLM); add `mcpToolName`, `mcpPreRequest`, `mcpPreResponse` (MCP); MCP branch in `Execute`; relax `preRequest` empty-`Tools` early return so results still count. | Modified |
| `pkg/infra/plugins/pertoolratelimit/data.go` | Add optional `ToolCallID` extra for the counting point; `Stage` now `pre_request`/`pre_response`. (Optional; can stay unchanged.) | Modified |
| `pkg/infra/plugins/pertoolratelimit/config.go` | No functional change (no new config). | Unchanged |
| `pkg/infra/plugins/pertoolratelimit/plugin_test.go` | Rewrite `PostResponse_*` counting tests as `PreRequest` execution-counting (id→name resolution, dedupe idempotency, two-turn); add MCP `pre_request` deny + `pre_response` count tests; fix `allStages()`/`TestPlugin_Stages`/`TestPlugin_AppearsInCatalog` to two stages; update `TestPlugin_FullCycle_CountThenReject`. | Modified |
| `pkg/app/plugins/catalog_metadata.go` | Reword `description` from "per observed tool call in model responses" to real executions (LLM `role:"tool"` results + MCP `tools/call`); note MCP behaviors deny/block; adjust behavior field copy (counting on `pre_request`; MCP collapses to deny). | Modified |
| `tests/functional/plugin_per_tool_rate_limiter_test.go` | Add a follow-up `role:"tool"` turn to drive counting; assert reject/inject/strip after the executed-result turn (not the proposal turn); add an MCP `tools/call` case (deny after limit). | Modified |
| `postman/TrustGate.postman_collection.json` | Align sample/doc copy to execution counting + MCP coverage. | Modified |
| `pkg/app/mcp/plugin_runner.go` | Read/verify only — already sufficient. | Unchanged |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Read/verify only — ordering already correct. | Unchanged |
| `pkg/infra/providers/adapter/*` | Read-only — canonical id→name mapping already present. | Unchanged |

### Testing strategy

**Unit (`plugin_test.go`, table-driven, `-race`, `miniredis`):**
- LLM counting on `pre_request`: build a two-turn request (assistant `tool_calls`
  id→name + `role:"tool"` results) for OpenAI **and** Anthropic; assert the window
  counter INCRs once per executed result.
- Dedupe idempotency: replay the same request twice → counter stays at 1; distinct
  `tool_call_id`s → counter increments per id; assert the dedupe key TTL equals the
  largest window.
- Unresolved/missing/duplicate `tool_call_id` → no count (no mis-charge).
- Count-then-enforce: results push the counter to the max, then the same turn
  re-declares the tool → reject/strip fires on that turn.
- MCP `pre_request` deny: seed counter at max, `MCP:true` body `{name}` over a
  matched rule → `PluginError` 429 with headers; under budget → `okResult`.
- MCP `pre_response` count: `MCP:true` → counter INCRs once, result is 200 with no
  `StopUpstream`; no dedupe key created.
- Stage/catalog: `MandatoryStages`/`SupportedStages` == two stages;
  `TestPlugin_AppearsInCatalog` asserts two stages.
- Keep the `inject`/`strip`/header/`overLimit`/`matchToolPattern` tests; delete the
  `PostResponse`-specific ones.

**Functional (`tests/functional`, `//go:build functional`):**
- LLM: first request declares + proposes a tool; drive a **second** request
  carrying the `role:"tool"` result; assert the counter charges on that second
  turn and a subsequent over-budget turn is rejected/injected/stripped. The
  `require.Eventually` async waits can shrink since counting is now synchronous in
  `pre_request` (no detached goroutine).
- MCP: register a `tools/call` route; call the tool up to the limit; assert the
  next `tools/call` returns the JSON-RPC block (`-32001`) and does not reach the
  upstream `CallTool`.

---

## 7. Data-flow

### LLM (two turns)

```
Turn 1
  Client → gateway: request (user msg, tools declared)
  pre_request:  no role:"tool" messages → no count;
                enforce declared tools (overLimit → reject/strip)
  upstream:     assistant tool_calls (proposal)
  pre_response: inject_error_result enforcement (non-streaming) if over budget
  gateway → client: response   [no post_response counting]

  (client executes the tools locally)

Turn 2
  Client → gateway: request incl. assistant tool_calls(id→name)
                    + role:"tool" results(tool_call_id, output)
  pre_request:  toolCallNames(messages) → resolve each role:"tool" id → name
                → matchRule → SET NX dedupe(tool_call_id, ttl=largest window)
                → if fresh: recordScript INCR each window   [COUNT]
                then enforce declared tools in this turn (overLimit → reject/strip)
  ...
```

Counting is one turn late by construction (a tool executes, its result returns on
the next request, then it is charged) — bounded to one extra execution, accepted
per RUN-965.

### MCP (single call)

```
Client → gateway: tools/call { name, arguments }
  PreRequest (mcp):  parse name → matchRule → overLimit
                     over  → PluginError 429 → blockToRPCError(-32001) → STOP (deny)
                     under → allow
  composer.CallTool: upstream executes the tool           [real execution]
  PreResponse (mcp): parse name → matchRule → recordScript INCR each window  [COUNT once]
                     always returns ok (never blocks)
gateway → client: tool result
```

One `tools/call` = one execution = one count; no dedupe needed.

---

## 8. Boundaries, budget, and split

- **Hexagonal:** all logic stays in the infra plugin (`pkg/infra/plugins/...`);
  it consumes the app `adapter.Registry` port and `redis.Client` it already holds
  (§4 DI unchanged, no new wiring). MCP transport concerns remain in
  `pkg/app/mcp` / `pkg/api/.../mcp` (untouched). No new interfaces, so §10.1 (one
  interface per file) is not triggered.
- **No comments (§11):** every shape above is comment-free, including exported
  identifiers — the pre-commit hook strips them.

**PR-size (400-line soft cap).** Non-test production changes are small
(plugin.go net ≈ +160 / −100, catalog + data.go a few lines). Test rewrites
(`plugin_test.go` + functional) are the bulk. LLM and MCP counting are logically
independent but both edit `plugin.go`, so **stack two PRs**:

1. **PR 1 — LLM execution counting** (base): stage change, remove `post_response`
   path, `pre_request` count-then-enforce + dedupe, LLM unit + functional tests,
   catalog/Postman copy for LLM semantics.
2. **PR 2 — MCP counting** (stacked on PR 1): MCP branch in `Execute`,
   `mcpPreRequest`/`mcpPreResponse`, MCP unit + functional tests, catalog/Postman
   MCP copy.

Each stays within the review budget and is independently verifiable.
