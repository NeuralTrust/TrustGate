# Exploration: Plugin executor — unsafe request/response body mutation in parallel batches

Linear: RUN-713 · change-name: `plugin-executor-parallel-body-safety`

## Current State

### Plugin execution path (files)

| Concern | File | Notes |
|---|---|---|
| Plugin interface + `Result` + `ExecInput` | `pkg/app/plugins/plugin.go` | Already documents a read-only/Result contract in doc comments, but it is not enforced. |
| Registry | `pkg/app/plugins/registry.go` | `Register` validates stages/modes; `Get`/`Validate`/`ValidateStages`/`Names`. |
| Per-request chain (fallback) | `pkg/app/plugins/chain.go` | `buildStageChain` (used only when no `Plan`), `isEffectiveStage`, `parallelBatch`. |
| Precomputed plan | `pkg/app/plugins/plan.go` | `StagePlan{ byStage map[Stage][]chainEntry }`, `NewStagePlan`, `entriesFor`, `Has`, `Blocks`. |
| Executor | `pkg/app/plugins/executor.go` | `RunStage`, `runBatch`, `runOne`, `isolateRequest/Response`, `mergeIsolated`, `applyResult`, `copyAnyMap`. |
| Plan build/cache site | `pkg/app/consumer/data_finder.go:139,150` | `buildPolicyPlan` → `appplugins.NewStagePlan` once per gateway aggregate. |
| Plan storage | `pkg/app/consumer/consumer_data.go:34` | `RoutableConsumer.PolicyPlan *appplugins.StagePlan`. |
| Stage drivers | `pkg/app/proxy/plugin_runner.go` | `runPreRequest`, `runPreResponseGated`, `firePostResponse`, stream wrap. |
| Forwarder entry | `pkg/app/proxy/forwarder.go:152` | reads `in.Consumer.PolicyPlan` and passes it to each `RunStage`. |
| Registration | `pkg/container/modules/plugins.go:71-85` | the 8-plugin catalog slice + `reg.Register`. |
| Catalog metadata | `pkg/app/plugins/catalog.go` | `CatalogEntry` reflects `MandatoryStages/SupportedStages/SupportedModes` from the live registry. |
| Domain | `pkg/domain/policy/policy.go:24` | `Policy.Parallel bool`, `Policy.Priority int`. |
| Contexts | `pkg/infra/context/{request,response}_context.go` | `Body []byte`, `Headers map[string][]string`, `Metadata map[string]interface{}`. |

### How `StagePlan.entriesFor` and batching work today

`NewStagePlan` (`plan.go:34`) iterates enabled, deduped policies once, builds one
`chainEntry{plugin, config, mode, priority, parallel, global}` per policy, and
appends it to `byStage[stage]` for every stage where `isEffectiveStage` is true.
Per stage it then `sort.SliceStable`s by `priority` only. `entriesFor(stage)`
just returns `byStage[stage]`.

The executor (`executor.go:74`) walks `entries` and calls `parallelBatch(entries, i)`
(`chain.go:87`): a batch is `entries[i]` alone when `!parallel`, otherwise the
maximal run of consecutive entries that are both `parallel` and share
`entries[i].priority`. So **batch formation today is purely `(parallel, priority)`**;
it ignores what each plugin mutates. `runBatch` clones per entry via
`isolateRequest/isolateResponse`, runs concurrently in an `errgroup`, then
`mergeIsolated`s clones back in batch order, and finally `applyResult` runs
sequentially over each `*Result`.

### Exact copy/merge semantics (the bug surface)

- `isolateRequest` (`executor.go:192`): `clone := *src` (shallow struct copy),
  then deep-copies **only** `Headers` (`cloneHeaders`) and `Metadata`
  (`copyAnyMap`). `Body []byte` is **shared** (same backing array). All other
  fields are copied by value/shared by reference.
- `isolateResponse` (`executor.go:202`): same — `Headers` + `Metadata` only;
  `Body` shared.
- `mergeIsolated` (`executor.go:212`): merges back **only** `Metadata`
  (`mergeAnyMap`) and `Headers` (`mergeHeaderMap`). It **never copies `Body`
  back** to the original. → direct `in.Request.Body = ...` inside a parallel
  batch is silently lost.
- `copyAnyMap` (`executor.go:226`): shallow — copies the top-level map but nested
  values (slices, maps, pointers like `*adapter.CanonicalUsage`) are shared by
  reference across all clones.
- `applyResult` (`executor.go:263`): sequential, over the **original** req/resp.
  `req.Body = res.RequestBody` (last writer wins); `mergeHeaders` appends;
  `StopUpstream` sets the outcome and returns true (short-circuit). There is **no
  guard against multiple `RequestBody` / multiple `StopUpstream` results** in one
  batch.

### The three confirmed defects (RUN-713)

1. **Silent lost-update via direct mutation.** `model_allowlist`
   (`modelallowlist/plugin.go:76,109`) and `token_rate_limiter` downgrade
   (`tokenratelimit/downgrade.go:64`) do `in.Request.Body = adapter.OverrideModel(...)`.
   In a parallel batch they write the *clone's* `Body`, which `mergeIsolated`
   never folds back → change lost. (In a single-plugin batch the clone is skipped
   so it currently "works", which masks the bug.)
2. **Lost-update via `Result.RequestBody`.** Two plugins in one batch each return
   `RequestBody` computed from the *original* body; `applyResult` applies them
   sequentially, last writer wins. Body transforms don't commute.
3. **Latent metadata race.** `copyAnyMap` is shallow. Two parallel plugins
   mutating the same nested structure under `Metadata` race (`go test -race`).
   Real nested-pointer example: `req.Metadata[adapter.MetadataUsageKey]` holds a
   `*adapter.CanonicalUsage` (read in `tokenratelimit/budget.go:444`).

### Per-plugin mutation matrix (all 8)

| Plugin (slug) | Stages | Req body | Resp body | Headers | Metadata | How |
|---|---|---|---|---|---|---|
| `cors` | pre_request | no | no | via Result | no | `Result.Headers` + `StopUpstream` (preflight) |
| `rate_limiter` | pre_request | no | no | via Result | no | `Result.Headers`; error path via `PluginError` |
| `token_rate_limiter` | pre_request, post_response | **YES (direct)** | no | via Result | reads `req.Metadata` (post_response) | `downgrade.go:64 req.Body=...` ← **offender**; headers via Result |
| `per_tool_rate_limiter` | pre_request, pre_response, post_response | **YES (Result)** | **YES (Result)** | via Result | no | `Result.RequestBody` (strip) / `Result.Body`+`StopUpstream` (inject) ← correct pattern |
| `request_size_limiter` | pre_request | no | no | via Result | no | read-only, `Result.Headers`, `PluginError` |
| `semantic_cache` | pre_request, post_response | no | **YES (Result)** | via Result | **writes `resp.Metadata` directly** | hit → `Result.Body`+`StopUpstream`; `markStatus` writes `resp.Metadata[cacheStatus]` (`plugin.go:338`) |
| `model_allowlist` | pre_request | **YES (direct)** | no | no | no | `plugin.go:76,109 in.Request.Body=...` ← **offender**; reject via `Result`+`StopUpstream` |
| `tool_call_validation` | pre_response | no | **YES (Result)** | no | no | redact → `Result.Body`+`StopUpstream`; reject via `PluginError` |

Note: `semantic_cache` and `token_rate_limiter` mutate **`Metadata` through the
context** (not `Result`) as cross-stage signalling. That is the metadata channel
that the deep-copy/Result decision must cover.

### Capability surface to add (blast radius)

New interface methods `MutatesRequestBody() bool` + `MutatesResponseBody() bool`
on `pkg/app/plugins/plugin.go` `Plugin`. Every implementer must add them:

- 8 production plugins: `cors`, `ratelimit`, `tokenratelimit`, `pertoolratelimit`,
  `requestsize`, `semanticcache`, `modelallowlist`, `tool_call_validation`
  (all under `pkg/infra/plugins/<name>/plugin.go`).
- mockery mock: `pkg/app/plugins/mocks/plugin_mock.go` (regenerate via
  `//go:generate mockery` on the `Plugin` interface in `plugin.go:34`; run
  `make gen-mocks` / `go generate ./...`).
- Hand-written test fakes that implement `Plugin` and must gain the methods:
  `pkg/app/plugins/executor_test.go` (`fakePlugin`, `scopeCapturePlugin`),
  `pkg/app/plugins/registry_test.go`, `pkg/app/proxy/plugin_runner_test.go`.
- Optional: `catalog.go` `CatalogEntry` if we want to expose capabilities to the
  admin UI (not required by the issue).

Expected capability values: req-body mutators = `model_allowlist`,
`token_rate_limiter`, `per_tool_rate_limiter`; resp-body mutators =
`per_tool_rate_limiter`, `semantic_cache`, `tool_call_validation`; all others
`false/false`.

### Mock generation

No central `.mockery.yaml`. Each interface carries its own
`//go:generate mockery --name=... --output=./mocks --with-expecter` directive.
`make gen-mocks` (Makefile:135) just runs `go generate ./...`. Adding methods to
`Plugin` → regenerate `plugin_mock.go`.

### Existing tests (patterns to mirror)

- `executor_test.go`: table-ish unit tests using a local `fakePlugin` (configurable
  `result/err/delay/onExec/writeMeta`) + `policies(...)` helper. Already has
  `ParallelBatchRunsConcurrently`, `ParallelBatchIsolatesMetadata`,
  `RequestBodyRewrite`, `UsesPrecomputedPlan`, `MergesHeadersInOrder`,
  `ShortCircuitStopsChain`. These are the natural homes for lost-update +
  determinism + `-race` tests.
- `plan_test.go`: asserts grouping by stage and sort by priority — extend for the
  new batch-formation rules at plan-build time.
- `pertoolratelimit/plugin_test.go`: the canonical "Result.RequestBody" body-rewrite
  test pattern.
- `tests/functional/plugin_policy_composition_test.go`: end-to-end composition.
- `make test-race` exists for the race test.

## Affected Areas

- `pkg/app/plugins/plugin.go` — add capability methods (+ update the contract doc, mindful of §11 no-comments).
- `pkg/app/plugins/plan.go` — **batch formation must move here** (plan-build time, §14.3). `chainEntry` likely needs `mutatesReq/mutatesResp bool` and an `effectiveParallel` decision; `StagePlan` likely needs precomputed batches instead of raw sorted entries.
- `pkg/app/plugins/chain.go` — `parallelBatch` rule changes; keep `buildStageChain` (fallback path) consistent.
- `pkg/app/plugins/executor.go` — executor becomes single writer of `Body`; deterministic `[par][seq][par]` fold; `isolateRequest/mergeIsolated` must handle Body + deep metadata; one StopUpstream per batch.
- `pkg/infra/plugins/modelallowlist/plugin.go`, `pkg/infra/plugins/tokenratelimit/downgrade.go` — stop direct `Body` mutation, return via `Result.RequestBody`.
- All 8 `plugin.go` + `plugin_mock.go` + test fakes — capability methods.
- Validation/normalization layer (location TBD — see OQ4) — force-sequential + log when config `parallel=true` conflicts with capability.
- `.agents/AGENT.md` §14.2 — update the invariant text.

## Approaches

1. **Plan-time batch planner + executor single-writer fold (recommended).**
   Resolve capabilities once in `NewStagePlan`: annotate each `chainEntry` with
   `mutatesReq/mutatesResp`, compute `effectiveParallel`, and pre-group entries
   into ordered batches that admit ≤1 req-body mutator, ≤1 resp-body mutator, ≤1
   StopUpstream, plus any number of read-only plugins. Add a deterministic
   tie-break (by `config.Slug` then `config.ID`) within equal priority. The
   executor folds batch results in deterministic order, and is the *only* code
   that writes `req.Body`/`resp.Body`. `isolateRequest` also deep-copies `Body`
   and deep-copies nested `Metadata`.
   - Pros: honours §14.3 (cold-path planning, hot-path consumes); preserves
     parallelism (mutator + read-only still run concurrently); deterministic;
     fixes all 3 defects centrally.
   - Cons: larger change to `plan.go`/`StagePlan` shape; must keep the
     `buildStageChain` fallback in parity.
   - Effort: Medium-High.

2. **Executor-only fix (group at runtime in `parallelBatch`).**
   Leave the plan as-is and make `parallelBatch` capability-aware.
   - Pros: smaller diff.
   - Cons: violates §14.3 (capability resolution + grouping in the per-request
     hot path); repeated work every request. Rejected.
   - Effort: Low but architecturally wrong.

3. **Serialize all body mutators (drop parallelism for body-mutating batches).**
   - Pros: simplest correctness.
   - Cons: needless latency regression; the issue explicitly wants a mutator to
     still run alongside read-only plugins. Rejected as the primary design.
   - Effort: Low.

## Recommendation

Approach 1. Do capability resolution and batch grouping at `StagePlan` build time
(`plan.go`), keep the executor as the single body writer with a deterministic
sequential fold across `[par][seq][par]…` blocks, deep-copy `Body` + nested
`Metadata` in isolation, and enforce ≤1 req-body mutator / ≤1 resp-body mutator /
≤1 StopUpstream per parallel batch. Refactor `model_allowlist` and
`token_rate_limiter` to return bodies via `Result`. Add a validation/normalization
step that forces sequential execution (and logs) when a `parallel=true` policy
names a plugin whose capability forbids parallel body mutation.

## Open Questions (with recommended answers)

- **OQ1 — Metadata: deep-copy vs route through `Result`?**
  Two plugins use the context metadata channel (`semantic_cache` writes
  `resp.Metadata`; `token_rate_limiter` reads `req.Metadata`). Recommend:
  **deep-copy nested metadata in `isolateRequest/Response`** (lowest blast radius,
  no plugin API churn) for the race fix now, and treat "metadata via Result" as a
  later refactor. Deep-copy must handle arbitrary nested `interface{}` —
  decide copy strategy (reflect-based deep copy vs. typed/`encoding/gob`); a
  scoped deep-copy of maps/slices is likely enough since current nested values
  are a string and a `*CanonicalUsage` pointer (pointer is read-only post-set).

- **OQ2 — Tie-break key for determinism.**
  Recommend `config.Slug` as primary tie-break, `config.ID` as secondary (both
  already on `chainEntry.config`, `plugin.go` `PluginConfig`). `Slug` is stable
  and human-meaningful; `ID` guarantees total order. Sort stays `priority` →
  `slug` → `id`.

- **OQ3 — Does `post_request` being unwired matter?**
  `planStages` includes `StagePostRequest` but **no plugin declares it and the
  forwarder never calls `RunStage(StagePostRequest)`** (no `runPostRequest` in
  `plugin_runner.go`/`forwarder.go`). Recommend: ignore it for this change; the
  batch rules apply uniformly per stage regardless, so no special handling
  needed. Note it as dead-but-harmless.

- **OQ4 — Where does the validation/normalization layer live?**
  Options: (a) at `NewStagePlan` build (annotate + force `effectiveParallel=false`
  + log) — preferred, single source of truth, cold path; (b) at policy
  create/update `ValidateConfig` time in the admin plane. Recommend **(a) for
  runtime safety** (config can predate the rule) and optionally surface a
  warning at admin write-time later. Needs a `logger` available in
  `NewStagePlan`/`buildPolicyPlan` (currently `data_finder` has one).

- **OQ5 — Capability source: interface methods vs. registry metadata table?**
  The issue mandates interface methods. Confirm we do **not** also need a parallel
  `pluginCatalogMeta`-style table. Recommend interface methods only;
  optionally echo them into `CatalogEntry` later for UI.

- **OQ6 — Multiple body mutators that are NOT parallel.**
  In a sequential (`[seq]`) block, multiple body mutators across priorities are
  fine (each sees the previous output) as long as the executor applies bodies in
  order. Confirm the fold applies `Result.RequestBody`/`Body` to the running
  context *between* batches so a later sequential mutator sees the earlier one's
  output. Recommend: yes — single-writer executor updates `req.Body` after each
  batch before starting the next.

## Risks

- Changing `StagePlan` shape touches the cached aggregate; must keep
  `buildStageChain` fallback in parity or remove it.
- Deep-copying metadata on every parallel batch adds hot-path cost; keep it
  shallow-but-correct (only deep-copy what can be mutated) and benchmark.
- Refactoring `model_allowlist`/`token_rate_limiter` changes behavior in
  single-plugin batches too (today they mutate in place); existing tests for
  those plugins must be updated to assert `Result.RequestBody`.
- §11 no-comments + §10 hexagonal/one-use-case-per-file constrain how the new
  planner code is structured; mocks must be regenerated, not hand-edited.

## Ready for Proposal

Yes. Recommend Approach 1. The orchestrator should confirm OQ1 (metadata
deep-copy vs Result) and OQ4 (validation location) with the user before design,
since they shape the public surface; the rest have safe defaults.
