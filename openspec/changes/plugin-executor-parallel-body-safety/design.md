# Design: Plugin executor — safe request/response body mutation in parallel batches

Linear: **RUN-713** · change-name: `plugin-executor-parallel-body-safety`
Artifact mode: hybrid. Builds on `exploration.md` + `proposal.md` (decisions OQ1–OQ6 are closed).

## Technical Approach

Approach 1 (plan-time capability-aware batch planner + executor single-writer fold).
Capabilities are declared as three interface methods, resolved **once** at
`StagePlan` build time (cold path, §14.3), and used to pre-group each stage into
ordered batches where a parallel batch admits **≤1 req-body mutator, ≤1 resp-body
mutator, ≤1 metadata mutator**. The executor becomes the **single writer** of
`req.Body`/`resp.Body`, applying each batch's `Result`s in deterministic order and
folding the body across `[par][seq][par]…` blocks. `model_allowlist` and
`token_rate_limiter` stop mutating `in.Request.Body` in place and return the new
body via `Result.RequestBody`. The fallback `buildStageChain` path reuses the same
pure grouping function so plan and no-plan paths stay in parity.

## Capability matrix (point 1 — confirmed/corrected vs exploration)

| Plugin (slug) | MutatesRequestBody | MutatesResponseBody | MutatesMetadata |
|---|---|---|---|
| `cors` | false | false | false |
| `rate_limiter` | false | false | false |
| `request_size_limiter` | false | false | false |
| `model_allowlist` | **true** (after Result refactor) | false | false |
| `token_rate_limiter` | **true** (after Result refactor) | false | **false** ⚠ correction |
| `per_tool_rate_limiter` | true | true | false |
| `semantic_cache` | false | true | **true** (`markStatus` writes `resp.Metadata`) |
| `tool_call_validation` | false | true | false |

⚠ **Correction (NEW OQ-A):** the prompt listed `token_rate_limiter`
metadata=true ("writes usage metadata"). Code shows it only **reads**
`req.Metadata[adapter.MetadataUsageKey]` (`budget.go:444`, streaming branch) — it
never writes metadata (`grep` for `Metadata[…] =` in `tokenratelimit` → none; the
`*CanonicalUsage` is written upstream by the provider invoker). `MutatesMetadata`
gates **writers** (≤1 writer/batch); readers are unbounded. Recommended value:
**false**. `semantic_cache` is the only true metadata writer.

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|---|---|---|---|
| Where capabilities resolve | 3 interface methods read in `NewStagePlan` → cached on `chainEntry` | registry metadata table; per-request resolution | §14.3 cold-path; OQ5 mandates interface methods |
| Batch grouping site | pure `groupBatches([]chainEntry) [][]chainEntry`, called by `NewStagePlan` and the fallback | runtime `parallelBatch` only | §14.3; keeps plan/no-plan parity |
| Body writer | executor only; plugins return `Result.RequestBody`/`Result.Body` | in-place `in.Request.Body =` | fixes lost-update defects 1+2; deterministic |
| Metadata race | capability + ≤1 writer/batch + keep shallow clone & sequential merge | generic deep-copy of `any` | OQ1; deep-copy unsafe for arbitrary pointers |
| Tie-break | sort `priority → slug → id` | priority only | OQ2; total order ⇒ deterministic batches |
| `isolateRequest`/`mergeIsolated` | **keep** (Headers+Metadata clone + sequential merge) | drop isolation | still required so the single metadata writer's writes don't race concurrent readers; Body no longer needs handling (never mutated in place) |
| StopUpstream cap | enforced at **executor runtime** (deterministic first-in-order wins + log) | planner-only | no StopUpstream capability exists; planner can't fully prevent (e.g. `cors`+`model_allowlist` share a pre_request batch) — see OQ-B |

## Data Flow

```
NewStagePlan (cold)                         RunStage (hot)
  dedup+sort(priority,slug,id)   ── plan ──►  for each precomputed batch:
  read MutatesReq/Resp/Meta()                   len==1 → runOne on real ctx
  groupBatches → ≤1 of each                      len>1 → isolate clones → errgroup
  mutator per parallel batch                            → merge meta/headers back
  log force-sequential demotions                 applyResult in order (single writer):
                                                   req.Body=res.RequestBody (≤1 guard)
                                                   resp.Body/StopUpstream (≤1 guard)
                                                 next batch sees folded body
```

## Interfaces / Contracts

```go
type Plugin interface {
	Name() string
	MandatoryStages() []policy.Stage
	SupportedStages() []policy.Stage
	SupportedModes() []policy.Mode
	ValidateConfig(settings map[string]any) error
	Execute(ctx context.Context, in ExecInput) (*Result, error)
	MutatesRequestBody() bool
	MutatesResponseBody() bool
	MutatesMetadata() bool
}
```

`chainEntry` gains `mutatesReq, mutatesResp, mutatesMeta bool`. `StagePlan` gains
`batches map[policy.Stage][][]chainEntry` (keep `byStage` for `Has`/`Blocks`/
`entriesFor` parity) plus `batchesFor(stage) [][]chainEntry`.
`NewStagePlan(reg, policies, logger)` gains a `*slog.Logger` (OQ-C; `data_finder`
already holds one — pass `f.logger`).

### Refactor before/after (point 2)

`modelallowlist/plugin.go:76,109` — preserve behavior, move write into `Result`:

```go
// before
in.Request.Body = adapter.OverrideModel(in.Request.Body, cfg.DefaultModel)
return okResult(), nil
// after
return &appplugins.Result{StatusCode: http.StatusOK,
	RequestBody: adapter.OverrideModel(in.Request.Body, cfg.DefaultModel)}, nil
```

`tokenratelimit/downgrade.go:64` — return the body up the call chain:

```go
// before
func applyDowngrade(req, orig, target) (string, map[string][]string, bool)
req.Body = adapter.OverrideModel(req.Body, newModel)
// after
func applyDowngrade(req, orig, target) (newModel string, body []byte, headers map[string][]string, ok bool)
body := adapter.OverrideModel(req.Body, newModel)
```

Call sites set `Result.RequestBody = body`: `plugin.go:110` (thread a
`downgradeBody` next to `downgradeHeaders`, assign on `res` before return at :130);
`budget.go:263` (set `RequestBody` on the inline `Result`).

### Grouping algorithm (point 3)

Entries pre-sorted `priority→slug→id`. Greedy: open a parallel batch from
`entries[i]` when `parallel`; admit consecutive same-priority parallel entries
while none repeats an already-used capability flag; on conflict, close the batch
(the conflicting entry opens the next batch → effectively forced sequential) and
`logger.Warn` with named attrs (`slog.String("stage",…)`, `slog.String("slug",…)`,
`slog.String("capability",…)`). Non-parallel entries are singleton batches.
Deterministic because the input order is a total order.

### Executor fold (point 4)

`RunStage` iterates `batchesFor`/grouped-fallback batches. `runBatch`: singleton →
`runOne` on the real context (no clone); parallel → isolate (Headers+Metadata
clone, Body shared read-only), `errgroup`, `mergeIsolated` (meta+headers), then
`applyResult` over results in batch order. Add defense-in-depth guards: count
applied `RequestBody`/`Body` (>1 ⇒ log + first-in-order wins) and `StopUpstream`
(>1 ⇒ log + first-in-order wins). Body is folded across blocks automatically
because `applyResult` mutates the real `req` between batches (OQ6).

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/app/plugins/plugin.go` | Modify | +3 capability methods on `Plugin` |
| `pkg/app/plugins/mocks/plugin_mock.go` | Regenerate | `make gen-mocks` |
| `pkg/infra/plugins/{cors,ratelimit,requestsize}/plugin.go` | Modify | all-false capability methods |
| `pkg/infra/plugins/{modelallowlist,tokenratelimit,pertoolratelimit,semanticcache,tool_call_validation}/plugin.go` | Modify | capability methods per matrix |
| `pkg/infra/plugins/modelallowlist/plugin.go` | Modify | direct body → `Result.RequestBody` |
| `pkg/infra/plugins/tokenratelimit/downgrade.go` (+ `plugin.go`, `budget.go` call sites) | Modify | `applyDowngrade` returns body → `Result.RequestBody` |
| `pkg/app/plugins/plan.go` | Modify | `chainEntry` flags, `groupBatches`, `StagePlan.batches`, `batchesFor`, `NewStagePlan` logger + force-sequential log |
| `pkg/app/plugins/chain.go` | Modify | fallback reuses `groupBatches`; retire/adapt `parallelBatch` |
| `pkg/app/plugins/executor.go` | Modify | consume batches; single-writer fold; ≤1 body/StopUpstream guards |
| `pkg/app/consumer/data_finder.go` | Modify | pass `f.logger` to `NewStagePlan` |
| `pkg/app/plugins/executor_test.go` | Modify | `fakePlugin`/`scopeCapturePlugin` +3 methods; lost-update/determinism/`-race` tests |
| `pkg/app/plugins/registry_test.go` | Modify | `stagePlugin` +3 methods |
| `pkg/app/proxy/plugin_runner_test.go` | Modify | `stubPlugin`/`capturePlugin` +3 methods |
| `pkg/app/plugins/plan_test.go` | Modify | grouping/cap/determinism assertions |
| `pkg/infra/plugins/{modelallowlist,tokenratelimit}/plugin_test.go` | Modify | assert `Result.RequestBody` |
| `.agents/AGENT.md` §14.2 | Modify | new invariant text (point 7) |

## Testing Strategy (point 8)

| Layer | What | How |
|---|---|---|
| Unit | lost-update (direct→Result) | two req-body fakes in one parallel batch → assert final `req.Body` reflects the planned single mutator, no drop |
| Unit | lost-update (`Result.RequestBody`) | planner splits 2 req-body mutators into sequential blocks; later sees earlier output |
| Unit | determinism | unordered slugs/ids at equal priority → stable batch composition (`priority→slug→id`) |
| Unit | normalization | `parallel=true` on conflicting mutators → forced sequential + `logger.Warn` asserted |
| Race | `-race` incl. metadata | `make test-race`; parallel batch with the single `semanticcache`-style meta writer + readers + a body mutator |
| Plugin | offender behavior | `modelallowlist`/`tokenratelimit` tests assert `Result.RequestBody` (not context) |

## AGENT.md §14.2 update text (point 7)

> ### 14.2 Parallel plugins never share mutable maps **and the executor is the
> single writer of the body**
> A parallel batch (`policy.Parallel == true`, same priority) runs each plugin on
> an **isolated clone** of the Request/Response context; per-plugin mutations are
> merged back sequentially, in deterministic batch order (`priority → slug → id`),
> after `errgroup.Wait()`. Plugins MUST treat the context as read-only and return
> body changes via `Result.RequestBody`/`Result.Body` — never assign
> `in.Request.Body`. Capability-aware batch formation at `StagePlan` build time
> guarantees ≤1 request-body, ≤1 response-body, and ≤1 metadata mutator per
> parallel batch (excess is forced sequential and logged); the executor enforces
> ≤1 applied body and ≤1 `StopUpstream` per batch as defense-in-depth. Plugins
> must not write the shared `Headers`/`Metadata` maps concurrently. Single-plugin
> batches skip the clone.

## Phase breakdown (≤400-line budget, chained PRs)

| Phase | Scope | Files | Behavior |
|---|---|---|---|
| 1 | Capability methods + mocks/fakes | `plugin.go`, 8 `plugin.go`, `plugin_mock.go` (regen), `executor_test.go`, `registry_test.go`, `plugin_runner_test.go` | none (pure additive) |
| 2 | Offender refactor to `Result` | `modelallowlist/plugin.go`, `tokenratelimit/{downgrade,plugin,budget}.go`, both `plugin_test.go` | behavior-preserving |
| 3 | Planner + executor fold | `plan.go`, `chain.go`, `executor.go`, `data_finder.go`, `plan_test.go` | core fix |
| 4 | Tests + docs | `executor_test.go` (lost-update/determinism/-race), `.agents/AGENT.md` §14.2 | none |

Dependency order: **1 → 2 → 3 → 4** (Phase 3 relies on capability methods from 1
and Result-returning offenders from 2; Phase 4 exercises 3). Each slice has a
clean start/finish and independent rollback (Phase 1 alone compiles and is inert).

## Migration / Rollout

No data migration, no config schema change. Behavior-preserving for safe configs.
Rollback = revert the four phases; `make gen-mocks` to restore the mock.

## Open Questions

- [ ] **OQ-A (recommend: resolve as false):** `token_rate_limiter.MutatesMetadata()`
      = **false** — it reads, never writes `req.Metadata`. Corrects the prompt's
      metadata=true. `semantic_cache` is the sole metadata writer.
- [ ] **OQ-B (recommend: executor runtime guard):** No StopUpstream capability
      exists, so the planner cannot guarantee ≤1 StopUpstream per batch (e.g.
      `cors` + `model_allowlist` can co-batch). Enforce ≤1 at the executor:
      deterministic first-in-batch-order wins + `logger.Warn`. Do not add a 4th
      capability method (out of scope — point 1 fixes the interface at 3 methods).
- [ ] **OQ-C (recommend: yes):** `NewStagePlan` gains a `*slog.Logger` param for
      force-sequential logging; `data_finder.buildPolicyPlan` passes `f.logger`.
      Update `plan_test.go` constructor calls accordingly.
