# Proposal: Plugin executor — safe request/response body mutation in parallel batches

Linear: **RUN-713** · change-name: `plugin-executor-parallel-body-safety`

## Why

The plugin executor runs same-priority parallel plugins on **shallow-cloned**
contexts. Three confirmed defects (RUN-713):

- **Silent lost-update (direct mutators).** `model_allowlist` and
  `token_rate_limiter` (downgrade) do `in.Request.Body = ...` on the clone;
  `mergeIsolated` only folds back `Headers`+`Metadata`, never `Body` → the
  rewrite is dropped in any multi-plugin parallel batch. It only "works" today
  because single-plugin batches skip cloning, which masks the bug.
- **Last-writer-wins (`Result.RequestBody`).** Two body-transforming plugins in
  one batch each compute from the original body; `applyResult` applies them
  sequentially with no guard → non-commuting transforms clobber each other.
- **Latent metadata race.** `copyAnyMap` is shallow; nested values
  (e.g. `*adapter.CanonicalUsage` under `req.Metadata`) are shared across
  clones → data race under `go test -race`.

## What changes

- **Plugin capability methods** (code-level, not user config) on the `Plugin`
  interface: `MutatesRequestBody() bool`, `MutatesResponseBody() bool`,
  `MutatesMetadata() bool`.
- **Executor is the single writer of the body.** Plugins treat the context as
  read-only and return transformed bodies via `Result`. Refactor
  `model_allowlist` and `token_rate_limiter` to return `Result.RequestBody`
  instead of mutating `in.Request.Body`.
- **Capability-aware batch formation at plan-build time** (`NewStagePlan`, cold
  path per AGENT.md §14.3 — NOT per-request). A parallel batch admits at most
  **one** request-body mutator, **one** response-body mutator, **one** metadata
  mutator, and **one** StopUpstream; any number of read-only plugins still run
  in parallel alongside it. `effective_parallel = policy.Parallel && capability allows`.
- **Deterministic `[par][seq][par]…` fold** respecting priority, tie-broken
  within equal priority by **slug then id**. The executor chains the body
  sequentially across blocks; within a parallel batch the single mutator's
  `Result` is applied after `errgroup.Wait()`, before the next block.
- **Same treatment for response body, headers, and StopUpstream.**
- **Metadata race fix via capability + ≤1-metadata-mutator-per-batch** (NOT
  generic deep-copy, which is unsafe for arbitrary `any`/pointer values). Keep
  the existing sequential merge-back.
- **Normalization in `NewStagePlan`:** when config requests `parallel=true` on a
  plugin whose capability forbids safe parallelism for that batch, force it
  sequential and log. Admin-write `ValidateConfig` is unchanged.

## Scope

### In scope
- Capability methods on `Plugin` + all 8 production plugins + regenerated
  mockery mock + updated hand-written test fakes.
- Plan-time capability-aware batch planner with deterministic ordering.
- Executor single-writer body/headers fold for request and response.
- Refactor `model_allowlist` + `token_rate_limiter` to return bodies via `Result`.
- Update **AGENT.md §14.2** (the parallel-batch invariant text).

### Out of scope (non-goals)
- **OQ3 — `post_request` stage is unwired** (no plugin declares it, forwarder
  never calls it). Left as-is; batch rules apply uniformly so it needs no
  special handling. Dead-but-harmless.
- **Generic deep-copy of metadata** — deliberately rejected (unsafe for arbitrary
  pointer values); replaced by the capability + ≤1-per-batch rule.
- **Admin-plane validation changes** — `ValidateConfig` unchanged; normalization
  happens at plan build (runtime safety; config can predate the rule).
- **Metadata-via-`Result` channel** — keep the existing context metadata
  channel; later refactor.

## Resolved decisions (do not reopen)

- **OQ1 metadata:** capability + ≤1-per-batch rule, no generic deep-copy.
- **OQ2 tie-break:** slug then id (sort `priority` → `slug` → `id`).
- **OQ4 validation:** normalize in `NewStagePlan` (force-sequential + log).
- **OQ5 capability source:** interface methods only.
- **OQ6 fold:** executor folds body sequentially across blocks; single mutator
  `Result` applied post-`Wait`, so a later sequential mutator sees the earlier output.

## Capabilities

### New Capabilities
- None — no new openspec capability folder.

### Modified Capabilities
- None at the openspec spec level — this is an executor/plugin-contract change
  documented in spec.md within this change.

## Affected areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/app/plugins/plugin.go` | Modified | Add 3 capability methods to `Plugin`; `//go:generate` mock regen. |
| `pkg/app/plugins/plan.go` | Modified | Capability-aware batch formation moves here (cold path); `chainEntry` gains `mutatesReq/Resp/Meta` + `effectiveParallel`; precomputed batches. |
| `pkg/app/plugins/chain.go` | Modified | `parallelBatch` rule change; keep `buildStageChain` fallback in parity. |
| `pkg/app/plugins/executor.go` | Modified | Single-writer body fold (req+resp); deterministic `[par][seq][par]` apply; ≤1 StopUpstream/batch guard. |
| `pkg/infra/plugins/modelallowlist/plugin.go` | Modified | Stop direct `Body` mutation → return `Result.RequestBody`. |
| `pkg/infra/plugins/tokenratelimit/downgrade.go` | Modified | Same — return body via `Result`. |
| All 8 `pkg/infra/plugins/*/plugin.go` | Modified | Implement capability methods. |
| `pkg/app/plugins/mocks/plugin_mock.go` | Modified | Regenerate via `make gen-mocks` (not hand-edited). |
| `executor_test.go`, `registry_test.go`, `plugin_runner_test.go` | Modified | Hand-written fakes gain capability methods; add lost-update/determinism/`-race` tests. |
| `.agents/AGENT.md` §14.2 | Modified | Update the parallel-batch invariant. |

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| `StagePlan` shape change touches the cached gateway aggregate. | Med | Keep `buildStageChain` fallback in parity; cover with plan unit tests. |
| Refactoring `model_allowlist`/`token_rate_limiter` changes single-plugin-batch behavior too. | Med | Update those plugins' tests to assert `Result.RequestBody`; functional composition test. |
| Determinism regressions from new tie-break. | Low | Total order (priority→slug→id); add determinism test. |
| Residual metadata race if a batch slips two metadata mutators. | Low | Plan enforces ≤1 metadata mutator/batch + force-sequential; `make test-race`. |
| Constraints: §11 no-comments (incl. Go doc comments), §10 hexagonal/one-use-case-per-file. | — | New planner code follows hexagonal layout; mocks regenerated, not hand-edited. |

## Rollback plan

The change is behavior-preserving for safe configs and centralized in the
executor/plan layer. Rollback = revert the capability methods, the plan-time
batch planner, the executor single-writer fold, and the two plugin refactors
(restoring direct `in.Request.Body` mutation), regenerate mocks, and restore the
AGENT.md §14.2 text. No data migration; no config schema change.

## Delivery note (PR budget)

Likely exceeds the **400-line** reviewer budget (AGENT.md §13): interface +
8 plugins + mock regen + plan/executor refactor + 2 plugin refactors + tests +
docs. Recommend **chained PRs** — e.g. (1) capability methods + mock/fakes
(no behavior change), (2) plugin refactors to `Result` bodies, (3) plan-time
capability-aware batching + executor single-writer fold + tests, (4) AGENT.md
§14.2. `sdd-tasks` will forecast the split.

## Success criteria

- [ ] Body mutators in a parallel batch no longer lose updates (regression test).
- [ ] At most one req-body / resp-body / metadata mutator and one StopUpstream
      per parallel batch; excess forced sequential at plan build + logged.
- [ ] `model_allowlist` and `token_rate_limiter` return bodies via `Result`; no
      direct `in.Request.Body` mutation remains.
- [ ] Deterministic ordering (priority → slug → id) verified by test.
- [ ] `make test-race` clean for parallel plugin execution.
- [ ] Mocks regenerated via `make gen-mocks`; AGENT.md §14.2 updated.
