# Delta for Plugin Executor (RUN-713)

Makes the plugin executor safe for request/response body and metadata mutation
in same-priority parallel batches. The executor becomes the single writer of the
body; batch formation is capability-aware at plan-build time. AGENT.md §14.2 is
updated to match. `buildStageChain` (no-plan fallback) MUST stay in parity with
`StagePlan`.

## ADDED Requirements

### Requirement: Plugin mutation capabilities

The `Plugin` interface MUST expose `MutatesRequestBody() bool`,
`MutatesResponseBody() bool`, and `MutatesMetadata() bool`. Every plugin MUST
declare them truthfully. The regenerated mockery mock and all hand-written test
fakes MUST implement them.

#### Scenario: Capabilities match the mutation matrix
- GIVEN the 8 production plugins
- WHEN their capability methods are read
- THEN req-body mutators are exactly `model_allowlist`, `token_rate_limiter`, `per_tool_rate_limiter`
- AND resp-body mutators are exactly `per_tool_rate_limiter`, `semantic_cache`, `tool_call_validation`
- AND `semantic_cache` and `token_rate_limiter` report `MutatesMetadata()==true`

### Requirement: Executor is the single writer of the body

Plugins MUST treat the context body as read-only and return transformed bodies
via `Result.RequestBody`/`Result.Body`; only the executor MUST assign
`req.Body`/`resp.Body`. `model_allowlist` and `token_rate_limiter` MUST stop
mutating `in.Request.Body` directly and instead return `Result.RequestBody`,
preserving observable behavior (model override / downgrade still applied).

#### Scenario: Direct-mutation rewrite survives a parallel batch
- GIVEN a body-mutating plugin co-scheduled with a read-only plugin in one parallel batch
- WHEN the batch runs and the executor folds results
- THEN the body rewrite MUST be applied to the outbound request (not lost)

#### Scenario: model_allowlist and token_rate_limiter via Result
- GIVEN a request whose model must be injected/substituted (`model_allowlist`) or downgraded (`token_rate_limiter`)
- WHEN the plugin runs through the new path
- THEN it MUST return the new body via `Result.RequestBody` and MUST NOT write `in.Request.Body`
- AND the override/downgrade MUST still be observable downstream

### Requirement: Capability-aware parallel batch formation

At `NewStagePlan` build time, a parallel batch MUST admit at most ONE
request-body mutator, at most ONE response-body mutator, at most ONE metadata
mutator, and at most ONE StopUpstream-capable plugin; any number of read-only
plugins MAY run in parallel alongside it. `effective_parallel` MUST equal
`policy.Parallel && capability allows`.

#### Scenario: Two body mutators are never co-scheduled
- GIVEN two request-body mutators at equal priority both requesting `parallel=true`
- WHEN the plan is built
- THEN the planner MUST split them into separate ordered sequential blocks

#### Scenario: Mutator runs parallel with read-only plugins
- GIVEN one body mutator and N read-only plugins at equal priority, all `parallel=true`
- WHEN the plan is built
- THEN all MUST remain in a single parallel batch

### Requirement: Deterministic ordering and body fold

Execution MUST follow `[par][seq][par]…` blocks ordered by priority, tie-broken
within equal priority by slug then id. The executor MUST fold the body
sequentially across blocks so a later block sees the previous block's output;
within a parallel batch the single mutator's `Result` MUST be applied after
`errgroup.Wait()`, before the next block.

#### Scenario: Deterministic fold across equal-priority plugins
- GIVEN multiple equal-priority plugins
- WHEN the plan orders and the executor folds them
- THEN ordering MUST be priority → slug → id and the result MUST be identical across runs

#### Scenario: No data races under -race
- GIVEN a parallel batch including metadata access with nested values
- WHEN run under `go test -race` / `make test-race`
- THEN no data race MUST be reported

### Requirement: Plan-time normalization, ValidateConfig unchanged

When config requests `parallel=true` on a plugin whose capability forbids safe
parallelism for that batch, `NewStagePlan` MUST force it sequential and log the
downgrade. Admin-write `ValidateConfig` MUST remain unchanged. `buildStageChain`
MUST apply the same capability rules as `StagePlan`.

#### Scenario: Unsafe parallel forced sequential and logged
- GIVEN a second body mutator configured `parallel=true` for a batch already holding one
- WHEN `NewStagePlan` builds the plan
- THEN the offending plugin MUST be forced sequential AND a log line MUST be emitted
- AND `ValidateConfig` MUST NOT reject the config

#### Scenario: Fallback chain parity
- GIVEN no precomputed plan (fallback path)
- WHEN `buildStageChain` forms batches
- THEN it MUST enforce the same ≤1-mutator and ordering rules as `StagePlan`
