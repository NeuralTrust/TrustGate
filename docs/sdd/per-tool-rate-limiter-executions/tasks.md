# Tasks: per_tool_rate_limiter counts real executions (LLM + MCP) — RUN-965

Atomic task breakdown for the counting-source + transport-coverage correction.
Authoritative inputs (not reopened): `design.md`, `spec.md`, `proposal.md`,
`explore.md`. Binding conventions: `.agents/AGENT.md` (§4 DI, §9 testing with
`-race`, §10 DTO/app layout, §11 **no code comments — not even Go doc comments**,
§13 commits/PR budget = 400 changed lines) and the `golang-pro` skill.

Two phases, each a single reviewable work-unit / commit boundary. **PHASE 1 (LLM)
must land before PHASE 2 (MCP)** — both edit `plugin.go`, and PHASE 2 stacks on
PHASE 1. Functional-test updates ship with the phase that introduces the behavior.

Spec ids referenced: `PTRL-1..14` (see `spec.md`).

---

## PHASE 1 — LLM execution counting (base PR)

**Status: [x] DONE (1.1–1.13).** Applied in worktree. Verified: `make fmt`
(gofmt + go vet) clean, `make lint` 0 issues, `go test -race
./pkg/infra/plugins/pertoolratelimit/...` ok; functional package compiles
(`go test -tags functional` runtime-fails only at TestMain for missing
Postgres/Redis). Zero code comments added.

Move LLM quota accounting from proposed `post_response` `tool_calls` to real
executions observed on the next request's `role:"tool"` results, deduped per
`tool_call_id`; remove the `post_response` counting path. Satisfies
`PTRL-1..7` and the REMOVED `post_response` requirement, with `PTRL-12/13/14`
preserved.

### 1.1 Drop `StagePostResponse` from stage declaration
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** `MandatoryStages()`/`SupportedStages()` return only
  `{StagePreRequest, StagePreResponse}`.
- **Spec:** REMOVED (`post_response` counting), `PTRL` stages contract.
- **Verifiable:** `MandatoryStages`/`SupportedStages` length == 2; no
  `StagePostResponse` reference remains in stage getters.

### 1.2 Remove the `post_response` counting path
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** delete `postResponse`, `calledTools`, `streamToolNames`, `ssePayload`,
  and the `sseDataPrefix`/`sseDoneMarker` package vars (confirmed
  package-private, no cross-package consumer); remove the `StagePostResponse`
  case in `Execute` (falls through to `okResult()`).
- **Spec:** REMOVED (`post_response` counting of proposed `tool_calls`), `PTRL-1`,
  `PTRL-7`.
- **Verifiable:** symbols no longer exist; `go build ./pkg/infra/plugins/pertoolratelimit/...`
  compiles with no unused-symbol / dead-code lint.

### 1.3 Add `tool_call_id → name` resolver
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** add `toolCallNames(messages []adapter.CanonicalMessage) map[string]string`
  building id→name from assistant `ToolCalls` (skip empty id/name; last-wins on
  duplicate id).
- **Spec:** `PTRL-2`, `PTRL-6` (cross-provider via canonical mapping).
- **Verifiable:** unit test resolves OpenAI and Anthropic canonical messages to
  the correct names; empty/duplicate ids handled.

### 1.4 Add dedupe key + largest-window helpers
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** add `dedupeKey(configID, dimension, subject, toolCallID) string` →
  `pertoolrl:dedupe:{configID}:{dimension}:{subject}:{tool_call_id}`; add
  `largestWindow(rule *ruleConfig) time.Duration`.
- **Spec:** `PTRL-3` (NX dedupe, TTL = largest window), `PTRL-13` (key layout of
  counters unchanged).
- **Verifiable:** unit test asserts key format and that `largestWindow` returns
  the max window duration of the rule.

### 1.5 Add `recordOnce` dedupe-gated counter
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** add `recordOnce(...)` = `SET NX EX` on `dedupeKey` (TTL
  `largestWindow(rule)`); only on fresh, run the existing `recordScript` per
  window and `setExtras` with the counting event data.
- **Spec:** `PTRL-2`, `PTRL-3`, `PTRL-13` (fixed-window/TTL anchor unchanged),
  `PTRL-14` (fail-open: Redis error returns without counting).
- **Verifiable:** unit test — first call increments once; replayed
  `tool_call_id` does not increment; Redis error path does not count.

### 1.6 Add `countExecuted` and wire into `preRequest`
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** add `countExecuted(...)` iterating `role:"tool"` messages, resolving
  name via `toolCallNames`, `matchRule`, then `recordOnce`; call it in
  `preRequest` after a successful `DecodeRequestFor`, **before** the enforce
  loop; relax the `len(canonical.Tools) == 0` early return so a turn that carries
  results but declares no tools still counts (gate counting on
  `len(canonical.Messages) > 0`; keep `Tools`-empty short-circuit only for the
  enforce loop).
- **Spec:** `PTRL-2`, `PTRL-4` (each distinct result once), `PTRL-5`
  (count-then-enforce ordering), `PTRL-7`.
- **Verifiable:** unit test — two distinct `role:"tool"` results increment by 2;
  results present with empty `Tools` still count; unresolved id → no count.

### 1.7 Keep LLM `pre_response` enforcement unchanged; confirm it reads the new counter
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** leave `preResponse` `inject_error_result` (non-streaming) verbatim; no
  counting here. Verify the `Execute` `StagePreResponse` LLM branch still calls
  `preResponse`.
- **Spec:** `PTRL-5` (inject non-streaming; streaming degrades to strip at
  `pre_request`, unchanged).
- **Verifiable:** existing inject/strip unit tests pass unchanged against the
  counter now written in `pre_request`.

### 1.8 Event extras for the counting point (`data.go`)
- **Files:** `pkg/infra/plugins/pertoolratelimit/data.go`
- **Do:** add optional `ToolCallID string json:"tool_call_id,omitempty"`; adjust
  the `p.data(...)`/builder to accept it (populated by LLM counting, empty
  elsewhere); `Stage` now carries `pre_request` for LLM counting. Additive only —
  no schema break.
- **Spec:** `PTRL-2` (traceability; no behavioral contract change).
- **Verifiable:** compiles; JSON tag additive; existing extras assertions still
  pass.

### 1.9 Rewrite LLM unit tests to `pre_request` execution counting
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin_test.go`
- **Do:** recast `TestPlugin_PostResponse_Counts*`, `…_TwoWindows`,
  `…_UnmatchedToolNoCount`, `…_ScopeIsolation`, `…_ConcurrentAtomic`,
  `…_EmptyToolNameNotCounted` as `pre_request` counting from `role:"tool"`
  results (OpenAI **and** Anthropic); add dedupe idempotency (replay → stays 1;
  distinct ids increment per id; dedupe key TTL == largest window); add
  unresolved/missing/duplicate id → no count; update
  `TestPlugin_FullCycle_CountThenReject` to count via next-turn results. Delete
  `post_response`-specific tests. Table-driven, `miniredis`, run with `-race`.
- **Spec:** `PTRL-2/3/4/6/7/12/13/14`, `PTRL-1` (proposal never counted),
  REMOVED requirement.
- **Verifiable:** `go test -race ./pkg/infra/plugins/pertoolratelimit/...` green.

### 1.10 Fix stage/catalog unit tests to two stages
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin_test.go`
- **Do:** update `allStages()`/`TestPlugin_Stages` and
  `TestPlugin_AppearsInCatalog` to assert `{pre_request, pre_response}`.
- **Spec:** REMOVED (`post_response` stage no longer counts).
- **Verifiable:** stage/catalog tests pass.

### 1.11 Reword catalog copy for LLM execution semantics
- **Files:** `pkg/app/plugins/catalog_metadata.go`
- **Do:** change `description` from "per observed tool call in model responses"
  to real executions (LLM `role:"tool"` results); adjust behavior-field copy to
  note counting on `pre_request`.
- **Spec:** `PTRL-2` (copy must match new semantics).
- **Verifiable:** `TestPlugin_AppearsInCatalog` copy assertions pass; no stale
  "post_response"/"proposed" phrasing.

### 1.12 Update functional test — LLM next-turn counting
- **Files:** `tests/functional/plugin_per_tool_rate_limiter_test.go`
- **Do:** in `…_RejectResponse`, `…_InjectErrorResult`, `…_StripToolFromRequest`,
  `…_GlobMatchUsesDefaultBehavior`, drive a **second** request carrying the
  `role:"tool"` result; assert the counter charges on that turn and a subsequent
  over-budget turn is rejected/injected/stripped. Shrink `require.Eventually`
  waits (counting is now synchronous in `pre_request`).
- **Spec:** `PTRL-2`, `PTRL-5`, `PTRL-1`.
- **Verifiable:** `go test -tags functional -run PerToolRateLimiter ./tests/functional/...`
  green.

### 1.13 Align Postman copy to LLM execution counting
- **Files:** `postman/TrustGate.postman_collection.json`
- **Do:** update sample/doc copy for `per_tool_rate_limiter` to execution
  counting (LLM `role:"tool"` results); remove proposal-time wording.
- **Spec:** `PTRL-2` (copy lockstep).
- **Verifiable:** collection JSON valid; no stale "proposed tool_calls" copy.

---

## PHASE 2 — MCP execution counting (stacked on PHASE 1)

Teach the plugin to detect `in.Request.MCP`, enforce in `pre_request` (deny) and
count once in `pre_response` (after upstream `CallTool` success). All MCP
behaviors collapse to deny/block. Satisfies `PTRL-8/9/10/11`, with
`PTRL-12/13/14` preserved.

### 2.1 Add MCP tool-name parser
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** add `mcpToolCallBody{ Name string json:"name" }` and
  `mcpToolName(body []byte) string` parsing `{ "name", "arguments" }` directly
  (bypassing `wireFormat`/canonical decoders); empty/parse-error → "".
- **Spec:** `PTRL-8`, `PTRL-9` (only `tools/call` bodies carry a name),
  `PTRL-14` (parse error → no count).
- **Verifiable:** unit test parses a `tools/call` body to the tool name; garbage
  body → "".

### 2.2 Branch `Execute` on `in.Request.MCP`
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** in the `StagePreRequest` and `StagePreResponse` cases, when
  `in.Request != nil && in.Request.MCP`, dispatch to `mcpPreRequest` /
  `mcpPreResponse`; otherwise the existing LLM path.
- **Spec:** `PTRL-8`, `PTRL-10`.
- **Verifiable:** unit test — MCP-flagged input routes to MCP handlers; LLM input
  unaffected.

### 2.3 Implement `mcpPreRequest` (enforce, deny on over-limit)
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** parse name → `matchRule` → `overLimit`; over → `setExtras` + return the
  existing `reject` `*PluginError` (429 + `X-RateLimit-*`/`Retry-After`); under /
  no match / empty → `okResult()`. No counting here. All configured behaviors
  collapse to deny (record configured `behavior` in `data` for observability
  only).
- **Spec:** `PTRL-10` (deny pre-dial; behaviors collapse), `PTRL-12`, `PTRL-14`.
- **Verifiable:** unit test — counter at max → `PluginError` 429 with headers;
  under budget → `okResult()`; outcome identical across `reject`/`strip`/`inject`.

### 2.4 Implement `mcpPreResponse` (count once, never block)
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin.go`
- **Do:** parse name → `matchRule` → run `recordScript` per window (no dedupe
  key); `setExtras` with `pre_response` stage; always return `okResult()` (no
  `StopUpstream`). Redis error → wrapped error (fail-open handled by runner).
- **Spec:** `PTRL-8` (count once after success), `PTRL-11` (only reached after
  `CallTool` success), `PTRL-13`, `PTRL-14`.
- **Verifiable:** unit test — MCP `pre_response` increments once, result 200 with
  no `StopUpstream`, no dedupe key created.

### 2.5 Verify MCP wiring (read-only)
- **Files:** `pkg/app/mcp/plugin_runner.go`,
  `pkg/api/handler/http/mcp/rpc_dispatcher.go`
- **Do:** confirm (no edits) the runner sets `MCP:true`, `Provider:""`,
  `SourceFormat:""`, `Body={"name","arguments"}`; maps `*PluginError` from
  `PreRequest` to JSON-RPC `-32001`; calls `PreResponse` only after
  `composer.CallTool` succeeds (`PreRequest → CallTool → PreResponse`, no
  `PostResponse`).
- **Spec:** `PTRL-8/10/11`.
- **Verifiable:** documented confirmation in the PR; no diff to these files.

### 2.6 Add MCP unit tests
- **Files:** `pkg/infra/plugins/pertoolratelimit/plugin_test.go`
- **Do:** add MCP `pre_request` deny (seed at max → 429 + headers; under → ok),
  MCP `pre_response` count-once (increments once, 200, no dedupe key,
  `tools/list`/non-`tools/call` → no count), behavior-collapse (deny identical
  across behaviors), and upstream-failure-not-counted (no `pre_response` →
  counter unchanged). Table-driven, `miniredis`, `-race`.
- **Spec:** `PTRL-8/9/10/11/12/13/14`.
- **Verifiable:** `go test -race ./pkg/infra/plugins/pertoolratelimit/...` green.

### 2.7 Add MCP functional coverage
- **Files:** `tests/functional/plugin_per_tool_rate_limiter_test.go`
- **Do:** register a `tools/call` route; call up to the limit; assert the next
  `tools/call` returns JSON-RPC `-32001` and does not reach upstream `CallTool`;
  assert `tools/list` never counts.
- **Spec:** `PTRL-8/9/10/11`.
- **Verifiable:** `go test -tags functional -run PerToolRateLimiter ./tests/functional/...`
  green.

### 2.8 Extend catalog + Postman copy for MCP
- **Files:** `pkg/app/plugins/catalog_metadata.go`,
  `postman/TrustGate.postman_collection.json`
- **Do:** note MCP `tools/call` coverage and that MCP behaviors deny/block; align
  Postman sample/doc copy.
- **Spec:** `PTRL-8/10` (copy lockstep).
- **Verifiable:** catalog test passes; JSON valid; no contradicting copy.

---

## Review Workload Forecast

Estimated **changed lines = additions + deletions**. Test rewrites dominate
because recasting an existing test counts both the deletion and the replacement.

### PHASE 1 — LLM

| Area | File | Est. changed lines |
|---|---|---|
| Stage decl + remove post_response path + LLM counting | `plugin.go` | ~180 (add ~90 / remove ~90) |
| Event extras | `data.go` | ~10 |
| Catalog copy (LLM) | `catalog_metadata.go` | ~12 |
| Unit tests (recast + dedupe + stage/catalog) | `plugin_test.go` | ~210 |
| Functional (LLM next-turn) | `plugin_per_tool_rate_limiter_test.go` | ~70 |
| Postman copy | `TrustGate.postman_collection.json` | ~8 |
| **Total** | | **~490** |

**Budget:** slightly **over** the 400-line soft cap, driven almost entirely by
the mechanical `plugin_test.go` rewrite.

### PHASE 2 — MCP

| Area | File | Est. changed lines |
|---|---|---|
| MCP parser + Execute branch + mcpPreRequest/mcpPreResponse | `plugin.go` | ~95 |
| Unit tests (MCP) | `plugin_test.go` | ~120 |
| Functional (MCP) | `plugin_per_tool_rate_limiter_test.go` | ~60 |
| Catalog + Postman (MCP) | `catalog_metadata.go`, `TrustGate.postman_collection.json` | ~15 |
| **Total** | | **~290** |

**Budget:** comfortably **within** the 400-line soft cap.

### Recommendation: TWO stacked / chained PRs

Ship as **two stacked PRs (PHASE 1 base → PHASE 2 stacked)**, not one:

- **Rationale — one PR is not viable.** Combined ≈ **780 changed lines**, roughly
  double the 400-line cap; a single PR would lose reviewer focus on the two
  distinct behaviors (LLM next-turn counting vs. MCP transport coverage).
- **Rationale — split boundary is clean.** LLM and MCP counting are logically
  independent and each is independently verifiable, but both edit `plugin.go`, so
  they must stack (PHASE 2 rebases on PHASE 1) rather than run in parallel.
- **PHASE 1 caveat (≈490 lines, ~90 over cap).** Prefer one of, in order:
  1. Trim by keeping deleted `post_response` tests deleted (net removal) and
     writing lean table-driven replacements — realistic landing ≈ 400–440.
  2. If still over after implementation, split the pure `plugin_test.go`
     rewrite into a third stacked test-only PR (production change reviewed first).
  3. Otherwise request a `size:exception` label with rationale (mechanical test
     recast), per `.agents/AGENT.md` §13 / `_base` PR-budget policy.
- **PHASE 2 (≈290 lines)** ships as-is, within budget.

---

## Per-phase verification checklist

Run from the repo root of the worktree
(`/Users/edu/Neuraltrust/TrustGate-per-tool-rate-limiter-executions`). Applies to
**both** phases before their respective commit/PR.

```bash
make fmt
make lint
go test -race ./pkg/infra/plugins/pertoolratelimit/...
go test -tags functional -v -count=1 -run PerToolRateLimiter ./tests/functional/...
```

- `make fmt` → `gofmt -s -w .` + `go vet ./...` clean.
- `make lint` → `golangci-lint run ./...` clean (no dead-code / unused symbols
  from removed `post_response` path).
- `go test -race ...` (plugin package) → green with the race detector (`.agents`
  §9). `make test-race` runs the whole `./pkg/...`; scope to the plugin package
  during iteration.
- Functional command above mirrors `make test-functional`
  (`go test -tags functional`) scoped to this plugin; full suite requires
  Postgres on `localhost:5432`.
- **NO-COMMENTS check (`.agents` §11):** no code comments in any changed `.go`
  file — not even Go doc comments on exported identifiers (the pre-commit hook
  strips them; verify none were reintroduced):

```bash
git diff --name-only | grep '\.go$' | xargs grep -nE '^\s*//' || echo "no comments"
```

---

## Ordering constraint

PHASE 1 (LLM) **must** land before PHASE 2 (MCP): both modify `plugin.go`
(`Execute` dispatch, stage set), and PHASE 2 stacks on PHASE 1's stage/branch
structure. Do not start PHASE 2 tasks until PHASE 1 is merged (or its branch is
the base for the PHASE 2 branch).
