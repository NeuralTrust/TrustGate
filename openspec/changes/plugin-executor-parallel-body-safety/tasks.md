# Tasks: Plugin executor — safe request/response body mutation in parallel batches

Linear: **RUN-713** · change-name: `plugin-executor-parallel-body-safety`
Source of truth: `design.md`. Dependency order **1 → 2 → 3 → 4**. Each phase ends
green: `go build ./...`, `go vet ./...`, `golangci-lint run`, `go test -race ./...`
(touched packages). Enforce NO-COMMENTS (AGENT.md §11) and mockery regen — no
hand-edited mocks (§10).

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~650–900 (P1 ~150, P2 ~120, P3 ~330, P4 ~220) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR1 (Phase 1) → PR2 (Phase 2) → PR3 (Phase 3) → PR4 (Phase 4) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending (team decision: stacked-to-main vs feature-branch-chain) |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Capability interface + all impls + regen mocks/fakes (inert) | PR 1 | base = tracker branch; compiles, no behavior change |
| 2 | model_allowlist + token_rate_limiter return `Result.RequestBody` | PR 2 | base = PR 1; behavior-preserving |
| 3 | Plan-time batch planner + executor single-writer fold | PR 3 | base = PR 2; core fix; largest slice, watch 400-line budget |
| 4 | Tests (lost-update/determinism/-race) + AGENT.md §14.2 | PR 4 | base = PR 3; verification + docs |

## Phase 1: Capability methods + mocks/fakes (inert, pure additive)

- [x] 1.1 Add `MutatesRequestBody() bool`, `MutatesResponseBody() bool`, `MutatesMetadata() bool` to `Plugin` in `pkg/app/plugins/plugin.go`.
- [x] 1.2 Implement all-false on `cors`, `ratelimit`, `requestsize` `pkg/infra/plugins/{cors,ratelimit,requestsize}/plugin.go`.
- [x] 1.3 Implement per matrix: `modelallowlist` (req=true), `tokenratelimit` (req=true, meta=**false**), `pertoolratelimit` (req=true, resp=true), `semanticcache` (resp=true, meta=true), `tool_call_validation` (resp=true) in their `plugin.go`.
- [x] 1.4 Regenerate `pkg/app/plugins/mocks/plugin_mock.go` via `make gen-mocks` / `go generate` (no hand edits).
- [x] 1.5 Add the 3 methods to hand-written fakes: `fakePlugin`/`scopeCapturePlugin` in `executor_test.go`, `stagePlugin` in `registry_test.go`, `stubPlugin`/`capturePlugin` in `pkg/app/proxy/plugin_runner_test.go`.
- [x] 1.6 Green-gate: build, vet, lint, `go test -race` for `pkg/app/plugins/...` and `pkg/infra/plugins/...`.

## Phase 2: Offender refactor to `Result` (behavior-preserving)

- [ ] 2.1 `modelallowlist/plugin.go` (~76,109): replace `in.Request.Body = adapter.OverrideModel(...)` with `return &Result{StatusCode: 200, RequestBody: adapter.OverrideModel(in.Request.Body, cfg.DefaultModel)}`.
- [ ] 2.2 `tokenratelimit/downgrade.go:64`: change `applyDowngrade` to return `(newModel string, body []byte, headers map[string][]string, ok bool)`; compute `body := adapter.OverrideModel(req.Body, newModel)` instead of assigning `req.Body`.
- [ ] 2.3 Thread `downgradeBody` at call site `tokenratelimit/plugin.go:110` and assign `res.RequestBody = body` before return (~:130); set `RequestBody` on inline `Result` at `tokenratelimit/budget.go:263`.
- [ ] 2.4 Update `modelallowlist/plugin_test.go` and `tokenratelimit/plugin_test.go` to assert `Result.RequestBody` (not `in.Request.Body`); override/downgrade still observable.
- [ ] 2.5 Green-gate for `pkg/infra/plugins/{modelallowlist,tokenratelimit}/...`.

## Phase 3: Planner + executor fold (core fix)

- [ ] 3.1 `pkg/app/plugins/plan.go`: add `mutatesReq, mutatesResp, mutatesMeta bool` to `chainEntry`, populated in `NewStagePlan` from the capability methods.
- [ ] 3.2 `plan.go`: add pure `groupBatches([]chainEntry) [][]chainEntry` — pre-sorted `priority→slug→id`; greedy parallel batch admitting ≤1 of each capability flag; conflict closes batch (forces sequential) + `logger.Warn` with `slog.String("stage"/"slug"/"capability", …)`; non-parallel = singleton batch.
- [ ] 3.3 `plan.go`: add `StagePlan.batches map[policy.Stage][][]chainEntry` + `batchesFor(stage) [][]chainEntry`; keep `byStage` for `Has`/`Blocks`/`entriesFor` parity. Add `*slog.Logger` param to `NewStagePlan(reg, policies, logger)`.
- [ ] 3.4 `pkg/app/plugins/chain.go`: `buildStageChain` fallback reuses shared `groupBatches` for parity; retire/adapt `parallelBatch`.
- [ ] 3.5 `pkg/app/plugins/executor.go`: consume `batchesFor`/grouped-fallback batches — singleton → `runOne` on real ctx; parallel → isolate (Headers+Metadata clone, Body read-only), `errgroup`, `mergeIsolated`, then `applyResult` in batch order. Single-writer fold of `req.Body`/`resp.Body` across blocks.
- [ ] 3.6 `executor.go`: defense-in-depth guards — count applied `RequestBody`/`Body` (>1 ⇒ log + first-in-order wins) and `StopUpstream` (>1 ⇒ log + first-in-order wins). No 4th interface method.
- [ ] 3.7 `pkg/app/consumer/data_finder.go`: `buildPolicyPlan` passes `f.logger` to `NewStagePlan`.
- [ ] 3.8 `pkg/app/plugins/plan_test.go`: update constructors for the new logger param; assert grouping (≤1/cap), force-sequential demotion, determinism.
- [ ] 3.9 Green-gate for `pkg/app/plugins/...` and `pkg/app/consumer/...`.

## Phase 4: Tests + docs (verification)

- [ ] 4.1 `executor_test.go`: lost-update (direct→Result) — two req-body fakes in one parallel batch → final `req.Body` reflects the planned single mutator, no drop.
- [ ] 4.2 `executor_test.go`: lost-update via `Result.RequestBody` — planner splits 2 req-body mutators into sequential blocks; later sees earlier output.
- [ ] 4.3 `executor_test.go`: determinism — unordered slugs/ids at equal priority → stable batch composition (`priority→slug→id`).
- [ ] 4.4 `executor_test.go`: `-race` incl. nested metadata — parallel batch with a single `semanticcache`-style meta writer + readers + a body mutator (`make test-race`).
- [ ] 4.5 Confirm `modelallowlist`/`tokenratelimit` behavior asserted via `Result.RequestBody` (cross-check Phase 2 coverage).
- [ ] 4.6 Rewrite `.agents/AGENT.md` §14.2 with the single-writer/≤1-mutator-per-batch invariant text from `design.md`.
- [ ] 4.7 Final green-gate: build, vet, lint, `go test -race ./...` for all touched packages.
