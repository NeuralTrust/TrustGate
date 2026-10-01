# Design: MCP-wide placement for group-scoped policies (RUN-1746)

Inputs: [`proposal.md`](./proposal.md) (binding decisions), [`exploration.md`](./exploration.md), Linear RUN-1746.
Base audited: `origin/develop` @ `700068b1`. Binding conventions: `.agents/AGENTS.md`, `golang.mdc`, `go-comments.mdc`: doc comments on exported identifiers only, and no narrative comments.

> This page is longer than the usual 800-word budget. The orchestrator asked for every placement read site, the SQL, and per-file line estimates. Tables replace prose wherever they can.

## TrustGate (Go)

### Technical Approach

This design implements S1 + A1 + L1 from the exploration, with the proposal's decisions:

- **Storage**: a new column `policies.mcp_wide`, exclusive with `global` through a CHECK constraint.
- **Endpoint**: `POST|DELETE /v1/gateways/{gw}/policies/{id}/mcp-wide`, which mirrors `/global`.
- **Level**: MCP-wide takes the same wildcard consumer cell as global.

The change is mostly reads that learn a second flag. There are four write-side changes:

1. A relative-update repository setter per flag, so a promotion clears the other flag in one row write.
2. `Repository.Update` stops writing `global` and lands only while the stored flags still match the ones it read (an optimistic placement check, 409 otherwise).
3. `Scoper` gains the MCP-wide pair, guarded by the existing `LevelGuard`.
4. A protocol check: 422 when the plugin has no MCP support.

Nothing new is needed for cache invalidation, events or the proto. The flag rides in the snapshot's domain JSON. A reader that is not updated places the policy by its links alone: with none, which is what the console leaves after a promotion, it is a draft and runs nowhere.

### Architecture Decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| D1 | `Policy.MCPWide bool` with JSON tag `mcp_wide,omitempty`. `PolicyResponse.MCPWide` with JSON tag `mcp_wide`, always present | No `omitempty` on the domain field | The snapshot JSON of every existing policy stays byte-identical, so the config version does not churn across the fleet. The API field is always present, like `global`, so the console can rely on it. |
| D2 | New domain predicate `GatewayWide() = Global \|\| MCPWide`. `IsGlobal()` stays `p.Global` | Fold MCP-wide into `IsGlobal()` | Spec `policy-inert-scope` pins `IsGlobal()`. Every call site is decided one by one in the table below. |
| D3 | Domain mutators `SetGlobal(on)` and `SetMCPWide(on)`: promoting one flag clears the other, demoting clears only its own | Assign the flags inline in the scoper | The invariant then lives in one place in memory. The repository SQL mirrors it. |
| D4 | Keep the port's `SetGlobal`, widened so it also clears `mcp_wide` on promote. Add `SetMCPWide`. Both use relative SQL | A single `SetPlacement(enum)` that writes both columns absolutely | With an absolute write, `DELETE /global` racing `POST /mcp-wide` would wipe the MCP-wide flag. With the relative form, each verb touches only the flag it owns, and the CHECK can never fire. |
| D5 | `Repository.Update` writes neither `global` nor `mcp_wide`; it compares them (`AND global = $15 AND mcp_wide = $16`, bound to the flags the caller read). When no row matches, an `EXISTS` in the same transaction tells a missing row (`ErrNotFound`, 404) from a moved placement (`ErrPlacementChanged`, which wraps `ErrConflict`: 409, reload and retry). `Save` writes both. A 23514 on `policies_global_mcp_wide_check` maps to `ErrInvalidPlacement` | Leave `global = $5`; or stop writing the flags and keep whatever the row holds at write time | The `LevelGuard` approves a PUT on the placement the caller read. Writing `global` back silently undoes a concurrent promotion and, once the CHECK exists, turns a PUT racing a swap into a 23514 surfacing as a 500. Keeping the stored flags instead stores a state nobody checked: a disabled draft promoted while a stale PUT `{enabled:true}` lands ends as two enabled globals of one slug with no 409, and a stale PUT on a policy promoted in between can move a global onto groups another global holds. Comparing makes the write agree with the check. `UpdateInput` has no placement field, so nothing loses a capability. |
| D6 | Extend `Scoper` (`scoper.go`) with `SetMCPWide` and `UnsetMCPWide`. `NewScoper` gains `plugins appplugins.Registry` | A sibling `MCPWideScoper` file | Placement is one use case: the swap must know both flags, and find, no-op check, guard, cache, invalidation and signal are shared. A sibling would duplicate about 40 lines. |
| D7 | 422 through a new sentinel `ErrMCPWideUnsupported`, which wraps `ErrValidation` | Reuse `ErrInvalidMCPScope` | `httpio` already maps `ErrValidation` to 422, so no new mapping is needed. `ErrInvalidMCPScope` would print "invalid mcp_scope" for a policy whose scope is null. The check shares `pluginRunsOnMCP` with `validateMCPScopePlugin` (unknown slugs pass, as today). It also runs on a PUT that changes the slug of an MCP-wide policy, which would otherwise be a back door. |
| D8 | New handler file `mcp_wide_policy_handler.go` | Rename `GlobalPolicyHandler` into a placement handler | Renaming would churn the router, the DI module and swagger. |
| D9 | Load path: `everywhere` = global policies, `onMCP` = global ∪ MCP-wide (in repository order). MCP consumers and the Store read `onMCP`; LLM and A2A consumers read `everywhere` | A separate bucket composed after the globals | Same result with one `composePolicies` pass. LLM and A2A never see MCP-wide, so `inertPolicies` and `coalesceInert` stay unchanged. |
| D10 | L1: MCP-wide takes the cell (consumer=all) × groups × destination | L2: enumerate every MCP consumer | Occupancy stays a function of the row. The only lock change is reading the column. |
| D11 | Duplicates stay drafts: the duplicator copies the scope, not the placement | Copy `mcp_wide` | This is the existing contract (`TestDuplicator_Duplicate_OfAnOccupyingPolicySucceeds`). The swagger text is updated to say so. |
| D12 | No partial index on `mcp_wide` | Add one, mirroring `policies_global_idx` | No reader filters on the column; the `?mcp_wide=` list filter is out of scope. |
| D13 | `Rehydrate` keeps its signature | Add an `mcpWide` parameter | It has no production caller (`scanPolicy` and JSON decode fill the struct directly). Changing it would only churn tests. |

#### Every placement read, decided

| Site | Today | After |
|---|---|---|
| `domain/policy/level.go:225` `Occupancy` | `p.Global` nils consumers | `p.GatewayWide()` |
| `level.go:235` `Draft` | `!Global && no links` | `!Global && !MCPWide && no links` |
| `app/plugins/plan.go:90`, `chain.go:119` | `global: pol.IsGlobal()` | `pol.GatewayWide()`: plugin state is partitioned gateway-wide (decision TG3) |
| `app/consumer/data_finder.go:318` | `IsGlobal()` → globals, links skipped | `GatewayWide()` → links skipped. `IsGlobal()` → `everywhere`; both flags → `onMCP` |
| `app/consumer/associator.go:190` | Skip protocol check if global | `GatewayWide()` (decision TG2) |
| `app/policy/warnings.go:179` `inertUnsafeGlobalWarning` | `p.Global` | Unchanged: MCP-wide never reaches LLM |
| `warnings.go:182` orphan warning | Own predicate | `p.Draft()`, same text |
| `warnings.go:205` `reach` | `!p.Global` → attached only | `!p.GatewayWide()`, and `crosses := CrossesPlanes() && !p.MCPWide`, so MCP-wide drops non-MCP consumers |
| `warnings.go:352` `sameSlugRunsWhere` | `q.Global` → everywhere | New `mcpWide` flag. `reaches(c reachedConsumer)` = `global \|\| (mcpWide && c.mcp) \|\| has(c.id)` |
| `scoper.go:79,85,106` | Global only | Rewritten (see Interfaces) |
| `repository.go:96` Save / `:141` Update / `:346` scan | `global` | Save + `mcp_wide`. Update drops `global` and compares both flags (D5). Scan + `mcp_wide` |
| `level_lock.go:30,109` | `global` | + `p.mcp_wide`. **Critical**: without it an MCP-wide occupant looks like a draft and never conflicts |
| `repository.go:281,307` list filter, `list_policy_handler.go:109` | `?global=` | Unchanged (`?global=false` also lists MCP-wide) |
| `response/policy_response.go:71` | `global` | + `mcp_wide` |
| `updater.go` | — | On a slug change of an MCP-wide policy → `validateMCPWidePlugin` |
| `duplicator.go`, `creator.go` | No placement | Unchanged (both stay drafts) |
| `app/plugins/plugin.go:176` `RuntimeScope` doc | "Policy.Global" | "Policy.GatewayWide" |

### Data Flow

Promotion:

```
POST /policies/{id}/mcp-wide ─→ MCPWidePolicyHandler.SetMCPWide ─→ Scoper.SetMCPWide
   FindByID ─→ gateway match? (else 404) ─→ already MCPWide? return as is
   ─→ validateMCPWidePlugin (422) ─→ copy.SetMCPWide(true)        (copy.Global=false)
   ─→ LevelGuard.Check(copy) ─ advisory lock(gw,slug) + occupants (read mcp_wide)
        └─ conflict ─→ LevelConflict (409, wording unchanged)
        └─ free ─→ repo.SetMCPWide(true) in withMarkedTx            (outbox marker)
   ─→ existing.SetMCPWide(true) ─→ PolicyTTL cache Set ─→ GatewayData invalidation ─→ Signal
   ─→ 200 FromPolicyWithWarnings(p, warner.Overlaps(p))
```

Load, per gateway (`dataFinder.load`). The repository returns policies ordered by (priority, created_at, id):

```
loadPolicies ─→ everywhere = [Global]           onMCP = [Global ∪ MCPWide]   byConsumer = links of !GatewayWide
                     │                                 │
   LLM/A2A consumer ─┘ (inert path unchanged)          ├─→ MCP consumer c:
                                                       │     unscoped = composePolicies(onMCP.unscoped, attached.unscoped)
                                                       │     scoped   = mergeScoped(attached.scoped, onMCP.scoped)
                                                       │     PolicyPlan(unscoped), MCPPlans(unscoped, scoped)
                                                       └─→ StoreConsumer: onMCP.unscoped / onMCP.scoped
```

How the two lists compose for an MCP consumer:

- `composePolicies` takes the consumer-attached unscoped policies first, then the gateway-wide ones (global and MCP-wide) whose slug is not already taken. So a consumer's unscoped policy overrides an unscoped MCP-wide policy of the same slug.
- `mergeScoped` takes the consumer-attached scoped policies first, then the gateway-wide scoped ones, deduplicated by id. Scoped policies are additive.

Stage plans then sort by priority, slug and id. Per-user Store clones keep sharing `MCPPlans`, and a group-only scope lands in `anyDest`, so it matches every instance.

### File Changes

Estimates count added plus deleted lines.

| File | Action | What | Code | Test | Docs | Gen |
|---|---|---|---|---|---|---|
| `pkg/infra/database/migrations/20261001120000_add_policy_mcp_wide.go` | Create | Column + CHECK, idempotent up/down | 42 | | | |
| `pkg/domain/policy/policy.go` | Modify | Field, `GatewayWide`, `SetGlobal`/`SetMCPWide` mutators, exclusivity check in `Validate` | 28 | | | |
| `pkg/domain/policy/level.go` | Modify | `Occupancy`, `Draft` and their doc comments | 10 | | | |
| `pkg/domain/policy/errors.go` | Modify | `ErrInvalidPlacement`, `ErrPlacementChanged`, `ErrMCPWideUnsupported` | 9 | | | |
| `pkg/domain/policy/repository.go` | Modify | `SetMCPWide` port; `SetGlobal` doc | 5 | | | |
| `pkg/infra/repository/policy/repository.go` | Modify | Select/scan/Save; Update without `global` (parameters renumbered) plus the optimistic placement check; two setters; 23514 → `ErrInvalidPlacement` | 60 | | | |
| `pkg/infra/repository/policy/level_lock.go` | Modify | Read and scan `mcp_wide` | 2 | | | |
| `pkg/runtimeconfig/snapshot/adapters/policy_repository.go` | Modify | `SetMCPWide` → `ErrReadOnly` | 4 | | | |
| `pkg/app/policy/scoper.go` | Modify | Interface +2 methods, `plugins` dependency, `setMCPWide`, shared write/publish | 55 | | | |
| `pkg/app/policy/validate.go` | Modify | `pluginRunsOnMCP`, `validateMCPWidePlugin` | 14 | | | |
| `pkg/app/policy/updater.go` | Modify | Slug-change guard for MCP-wide | 6 | | | |
| `pkg/app/policy/warnings.go` | Modify | Orphan → `Draft()`, `reach`, `sameSlugRuns` | 20 | | | |
| `pkg/app/consumer/data_finder.go` | Modify | `loadPolicies` returns `{everywhere, onMCP, byConsumer}`; per-type pick; Store on `onMCP` | 30 | | | |
| `pkg/app/consumer/associator.go`, `pkg/app/plugins/{plan,chain,plugin}.go` | Modify | `GatewayWide()` + doc | 5 | | | |
| `pkg/api/handler/http/policy/mcp_wide_policy_handler.go` | Create | POST/DELETE + swagger annotations | 85 | | | |
| `pkg/api/handler/http/policy/{global,duplicate}_policy_handler.go` | Modify | Swagger text: swap, "neither global nor MCP-wide" | 5 | | | |
| `pkg/api/handler/http/policy/response/policy_response.go` | Modify | `MCPWide` + field doc | 4 | | | |
| `pkg/server/router/admin_router.go`, `pkg/container/modules/{policy,server_admin}.go` | Modify | Field, 2 routes, providers | 10 | | | |
| `pkg/domain/policy/{level,policy}_test.go` | Modify | Occupancy, Draft, predicate, mutators, Validate | | 75 | | |
| `pkg/app/policy/scoper_test.go` | Modify | 8 cases + the new `NewScoper` argument | | 150 | | |
| `pkg/app/policy/level_guard_test.go` | Modify | MCP-wide × MCP-wide, × global, disjoint, swap, unset not guarded | | 75 | | |
| `pkg/app/policy/{warnings,updater}_test.go` | Modify | No orphan warning, MCP-only reach, same-slug MCP-wide; slug 422 | | 95 | | |
| `pkg/app/consumer/data_finder_inert_test.go`, `data_finder_test.go` | Modify | LLM/A2A skip, MCP consumers, Store + clone with principal, links ignored, override | | 120 | | |
| `pkg/app/consumer/associator_test.go`, `pkg/app/plugins/executor_test.go` | Modify | Skip protocol check; gateway-wide `RuntimeScope` | | 35 | | |
| `pkg/infra/configsnapshot/codec_test.go`, `adapters_test.go` | Modify | `mcp_wide` round-trip; read-only | | 16 | | |
| `tests/functional/repositories/policy/{repository,level_lock}_test.go` | Modify | Swap SQL, CHECK, Update keeps placement, locked occupant reads the flag | | 90 | | |
| `tests/functional/mcp_wide_policy_test.go` | Create | Admin API + MCP runtime (OAuth stub) | | 170 | | |
| `docs/openapi_test.go` | Modify | New path, 409/422, `mcp_wide` property | | 25 | | |
| `docs/mcp-policy-scope.md` | Modify | Placement rows, level table, Admin API, Rollout | | | 50 | |
| `docs/{swagger.json,swagger.yaml,docs.go,openapi.json}` | Regenerate | `make docs` | | | | 540 |
| `pkg/domain/policy/mocks/policy_repository_mock.go`, `pkg/app/policy/mocks/policy_scoper_mock.go` | Regenerate | `go generate ./pkg/domain/policy/... ./pkg/app/policy/...` | | | | 170 |
| **Totals** | | | **≈366** | **≈851** | **≈50** | **≈710** |

The spec deltas from `sdd-spec` add about 150 lines (see Docs & specs). The total is about 1,400 hand-written lines plus about 710 generated ones, so this needs chained PRs. A cut that respects dependencies, for `sdd-tasks` to refine:

| Slice | Contents | Hand-written lines |
|---|---|---|
| (1) Storage | Migration, domain, repository/lock/stub, mocks, domain and repository tests | ≈315 |
| (2) Runtime | Load path, plan/chain, associator, warnings, with their tests | ≈275 |
| (3a) Use case | Scoper + validate + updater + DI, with their tests | ≈330 |
| (3b) HTTP | Handler/router/DTO, `make docs`, `openapi_test`, functional tests, doc | ≈345 + 540 generated |

Each slice is behaviour-neutral until the next one lands. The only exception is D5 in slice (1): a PUT racing `POST|DELETE /global` now fails with 409 instead of silently undoing the placement write. Nothing can set `mcp_wide` before slice (3b).

### Interfaces / Contracts

```go
// domain/policy
MCPWide bool `json:"mcp_wide,omitempty"`
func (p *Policy) GatewayWide() bool  { return p != nil && (p.Global || p.MCPWide) }
func (p *Policy) SetGlobal(on bool)  { p.Global = on; if on { p.MCPWide = false } }
func (p *Policy) SetMCPWide(on bool) { p.MCPWide = on; if on { p.Global = false } }
// Repository
SetGlobal(ctx, gatewayID, id, global bool) error   // promoting also clears mcp_wide
SetMCPWide(ctx, gatewayID, id, mcpWide bool) error // promoting also clears global
// app/policy
type Scoper interface { SetGlobal; UnsetGlobal; SetMCPWide; UnsetMCPWide } // same signature
func NewScoper(repo, levels LevelGuard, plugins appplugins.Registry, manager, publisher, logger, signaler) Scoper
```

```sql
-- migration up (down: DROP CONSTRAINT IF EXISTS …; DROP COLUMN IF EXISTS mcp_wide)
ALTER TABLE policies ADD COLUMN IF NOT EXISTS mcp_wide BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_global_mcp_wide_check;
ALTER TABLE policies ADD CONSTRAINT policies_global_mcp_wide_check CHECK (NOT (global AND mcp_wide));
-- setters (the right-hand side reads the old row)
UPDATE policies SET global   = $2::boolean, mcp_wide = mcp_wide AND NOT $2::boolean, updated_at = now() WHERE id = $1 AND gateway_id = $3;
UPDATE policies SET mcp_wide = $2::boolean, global   = global   AND NOT $2::boolean, updated_at = now() WHERE id = $1 AND gateway_id = $3;
```

Scoper semantics:

- `SetX` is a no-op when the flag is already set.
- Promotion is guarded once, with a copy carrying `SetX(true)`. The policy's own row is excluded from the occupants, so a global → MCP-wide swap never conflicts with itself.
- `UnsetX` is unguarded and a no-op when the flag is not set. So `DELETE /global` on an MCP-wide policy returns 200 with the policy unchanged.
- Every POST and DELETE on `/global` and `/mcp-wide` returns `PolicyResponse`, including `mcp_wide`. POST responses also carry `warnings`.
- The 409 error message stays `policy … already runs plugin … at level …`.

Swagger on the new POST documents:

- 200, 400, 401 and 404;
- 409: "already runs this plugin at one of the levels the policy would take on every MCP consumer";
- 422: "the plugin does not support MCP".

The DELETE documents 200, 400, 401 and 404.

### Docs & specs

- **`docs/mcp-policy-scope.md`**:
  - Consumer-dimension table (:106): placement now comes from `global`, `mcp_wide` and the consumer links.
  - "What reaches an LLM or A2A chain" (:120-135): add a row "MCP-wide, any scope → **No**", and the draft row gains "not MCP-wide".
  - :256: rewrite the `global` + scope row. The Store takes global and MCP-wide policies, and MCP-wide is the way to reach MCP (Store included) by group.
  - Add an `mcp_wide: true` row: a null scope means every MCP caller; links are ignored; plugin state is gateway-wide; api-key callers bypass `groups`; the same-plugin attachment double-run is a documented gap.
  - :259 orphan row: "not global and not MCP-wide".
  - Level table (:231): checked on promotion to either flag, not checked on unsetting either. MCP-wide against global with overlapping groups is a 409.
  - Admin API (:514): add the `/mcp-wide` rows and the swap note on `/global`.
  - Rollout: TrustGate before the console, the rollout SQL from the proposal, and rollback behaviour.
- **Spec deltas**, under `openspec/changes/mcp-wide-group-policies/specs/`, written in Spanish like the existing specs:
  - `policy-inert-scope`:
    - MODIFY "Lo que no llega por falta de consumer…" (:241): a draft also requires `mcp_wide=false`; `IsGlobal()` is unchanged.
    - MODIFY the consumer row of "La inercia es por dimensión" (:21).
    - ADD "MCP-wide nunca entra en una cadena LLM/A2A", with group-only inert-safe and destination scenarios.
  - `policy-level-uniqueness`:
    - MODIFY "LevelGuard en los cinco caminos" (:76-104): promotion includes `SetMCPWide`, and `UnsetMCPWide` is unguarded.
    - ADD scenarios: two MCP-wide policies on overlapping groups → 409; MCP-wide against global → 409; the swap is guarded once.
    - MODIFY "El conflicto sale como 409" (:152): the `/mcp-wide` handler is added.
  - `mcp-policy-scope`:
    - MODIFY "Validación en la Admin API" (:135-141): the orphan warning applies to drafts only; 422 on `/mcp-wide`.
    - MODIFY "`global` con scope" (:179-199): MCP-wide reaches MCP consumers and the Store only.
  - `mcp-policy-plan-selection`:
    - MODIFY "Anulación por slug acotada; Store" (:33-56): global and MCP-wide policies reach `StoreConsumer`. Scenarios: an MCP-wide group policy on a Store clone, and a consumer's unscoped policy overriding an unscoped MCP-wide policy.
  - ADD the capability `policy-mcp-wide-placement`: endpoints, swap, idempotent DELETE, response fields, gateway-wide plugin state, 422.

### Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit: domain | MCP-wide takes `(all, G, d)` and ignores its links; `Draft` is false for it; both flags set → `ErrInvalidPlacement`; mutators clear the other flag | Table tests in `level_test.go` and `policy_test.go` |
| Unit: use case | Set, swap from global, no-op, foreign gateway → 404, non-MCP plugin → 422 with no write, unset, `UnsetGlobal` on MCP-wide is a no-op; level 409s and an unguarded unset; PUT slug change → 422 | Repository mocks, `freeLevels`/`occupiedLevels`, `newScopedRegistryMock(t, ProtocolLLM)` |
| Unit: load | An inert-safe group-only MCP-wide policy is in the MCP consumer's `ScopedPolicies` and the Store's `MCPPlans`, and absent from LLM/A2A `Policies` and `PolicyPlan`; its links are ignored; an attached unscoped policy of the same slug overrides it; a Store clone (`InstanceOf`) with a member principal matches and a non-member does not | `loadInert` harness; `PlanFor(reg, tool, &identity.Principal{…groups})` |
| Unit: other | No "runs nowhere" warning; api-key warning only on MCP consumers; same-slug MCP-wide reaches MCP consumers only; associator skips the protocol check; `Scope.Global` is true for MCP-wide; codec round-trips `mcp_wide` | Existing harnesses |
| Integration (`PG_TEST_URL`) | Swap SQL in both directions; demotion keeps the other flag; raw `SET global=true, mcp_wide=true` → 23514, and `Save` with both flags → `ErrInvalidPlacement`; `Update` with stale flags → `ErrPlacementChanged` and nothing written, with matching flags it lands; the locked occupant reads `MCPWide` and its occupancy is non-empty | `tests/functional/repositories/policy` (migrations imported) |
| Functional (`functional` tag) | Admin API: set, unset, swap, idempotent DELETE, GET read-back, no orphan warning, 409 overlapping MCP-wide, 409 against global, disjoint groups coexist, 422 for `model_allowlist`. Runtime: `setupScopedOAuthConsumer` + a `tool_allowlist` deny-all policy for group Finanzas, **created and not promoted** → a Finanzas call is echoed (the draft contract); promoted → Finanzas blocked, Marketing echoed; a second MCP consumer created later is also blocked | New file `tests/functional/mcp_wide_policy_test.go`, reusing the helpers in `mcp_policy_scope_test.go` |
| Store | Same as the unit load row | `/store/mcp` has no functional harness (no test drives it with policies, and it needs platform-login tokens and a shelf install). The cheapest meaningful coverage is the unit test on `StoreConsumer.MCPPlans`, which is exactly what `resolveMCPConsumer` serves |
| OpenAPI | Path exists; POST has 409 and 422; DELETE exists; `PolicyResponse` has `mcp_wide` | `docs/openapi_test.go`, after `make docs` |

Before pushing, run `make test`, `go vet -tags functional ./...` and `make test-repositories`, then wait for the CI functional check.

### Migration / Rollout

- The migration is additive. Adding the column is metadata-only, and the CHECK scans a small table. No backfill.
- Ship TrustGate before the console.
- Rolling deploy with an old data plane: an old binary does not decode `mcp_wide` and places the policy by its links alone.
  - With no links, an MCP-wide policy is a draft there and runs nowhere (fail-closed).
  - With links, it runs on those consumers, as it did before the promotion. The console detaches every link on promotion, so this only happens to a policy promoted through the API with its links kept.
- Rollback: the down migration drops the column. A former MCP-wide policy is then placed by its links, as above.
  - Migrations only run up on boot. If the old admin binary runs on the migrated schema, its `POST /global` on a row that is still MCP-wide fails the CHECK and returns a 500.
  - To avoid that, run the down migration, or `DELETE /mcp-wide` those rows, before rolling back.
- The proposal's rollout SQL, which also covers `except_groups`, goes into the doc's Rollout section.

### Deviations and additions

No binding decision is reversed. These are additions the code requires:

1. **D5: `Repository.Update` stops writing `global` and checks the placement optimistically.** With the new CHECK, the current `global = $5` would turn a PUT racing `POST /mcp-wide` into a 500, and today the same race silently undoes a promotion. Not writing the flags is not enough: the guard decided on the placement the caller read, so `Update` compares both flags and answers `ErrPlacementChanged` (409) when they moved.
2. **D7: the 422 also applies on PUT.** A slug change on an MCP-wide policy to a plugin without MCP support is refused.
3. **D7 mechanism.** The proposal names `resolver.SupportedProtocols`, which is the consumer associator's port. `apppolicy` uses `appplugins.Registry.Get(slug).SupportedProtocols()`, the same source that `validateMCPScopePlugin` reads.
4. **Domain `Validate` rejects both flags set (`ErrInvalidPlacement`).** This backs the CHECK in memory.

### Open Questions

- [ ] Non-blocking: the plugin catalog descriptions of `rate_limiter` and `per_tool_rate_limiter` (`catalog_metadata.go:67,277`) say "gateway-wide for global policies". MCP-wide also counts gateway-wide. `token_rate_limiter` is LLM-only, so it can never be MCP-wide. Recommendation: a doc-only follow-up, kept out of this budget.


## app (console)

Worktree `/Users/edu/Neuraltrust/app-run1746`. `$P` = `app/[locale]/v2/features/policies`. The API contract is the one fixed in `proposal.md`.

### Technical approach

A third placement, `'mcp-wide'`, goes through the same channel as `global`. It needs one item field (`mcp_wide`), one more `PolicyScope` member and a flag writer that takes the placement as a parameter. *Groups* maps to `'mcp-wide'`. The sync reconciles all 3×3 transitions, failures are tagged with the placement the failed call wrote, and the actions turn the tag into copy that says what the gateway kept. The rest is read-back, the level mirror, validation and copy.

```
draft.requestsFrom ─policyScopeOf→ nextScope ┐
rawItem ─policyScopeOfItem→ previousScope ───┼→ PUT body (mcp_scope) → syncPolicyAssociations
                                             │   flag: POST|DELETE /global | /mcp-wide (retried)
                                             │   links: attach ∥ detach (allSettled, not retried)
                                             └→ PolicyAssociationError{failure, placement} → prefix → v2Gateway copy
```

### Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Item field | `mcp_wide?: boolean`; absent means false. `global` is never true at the same time. | Mirrors `/mcp-wide` the way `global` mirrors `/global`. Old payloads still read correctly. |
| Scope helpers (`lib/policyScopeOf.ts`) | `policyScopeOf`: `all`→`gateway-wide`, `group`→`mcp-wide`, `consumer`→`targeted`. New `policyScopeOfItem(item)`: `global` first, then `mcp_wide`, else `targeted`. New `isPromotedPolicy(item)`. `policyConsumerIdsOf` is unchanged. | One function per direction. Every `item.global` check inside `features/policies` that means "where it runs" uses them. |
| Flag writer | `setGlobal` and `writeGlobalFlag` become `writePlacementFlag(placement, enabled)`. A path map sends `gateway-wide`→`global` and `mcp-wide`→`mcp-wide`. It returns the parsed `PolicyResponse` (or `null`). The retry stays as is: 2 attempts, 250 ms apart, only for network errors, 5xx, 408 and 429. | Same retry and tagging for both flags. The return value is what makes the post-promotion item possible. |
| Error tag | `PolicyAssociationError` gets `placement?: 'gateway-wide' \| 'mcp-wide'` as an optional 4th constructor argument, so existing call sites compile. New pure helper `placementWriteFailureError(error, previousScope)`. | The gateway switches placement atomically, so a failed flag write leaves the **previous** placement. The copy follows from that. |
| Placement for the level check | `PolicyPlacement.mcpWide`. Wildcard consumer `*`, the same cell as `global`. | Matches TrustGate's L1. Never stricter than the gateway. |
| Validation | `isRequestsFromIncomplete(draft)` is true when `scopeShape==='supported'`, the choice is `group` and `groupKeys` is empty. `except_groups` alone counts as empty. | The screen can neither show nor edit `except_groups`. An unsupported scope is read-only, so the user could not fix it. |
| Coverage | `{kind:'mcp'}` → "All MCP applications and the MCP Store". No group list. | The card's scope line just above already names the groups. |

### `syncPolicyAssociations` transition matrix

Order: the PUT runs first. Then the flag write, sequential and retried. Then the links, in parallel and not retried. `prev` and `next` are the consumer id lists. In the "Copy" column, a slash separates the generic message from its level-conflict variant (the one used when the cause is a 409).

| prev → next | Calls | On failure the gateway holds | Copy |
|---|---|---|---|
| T→T | attach(next−prev) ∥ detach(prev−next) | partial links | `consumerSyncFailed` / `consumerAttachFailed` |
| T→GW | POST /global; links kept | targeted, old links (a draft on create) | `policyNotRunning` / `…LevelConflict` |
| T→MCP | POST /mcp-wide, then detach(prev) ∥ | promotion failed: targeted with the new scope. Detach failed: MCP-wide with leftover links, which are ignored at load. | `policyNotRunningMcp` / `…McpLevelConflict`; `consumerSyncFailed` |
| GW→T | DELETE /global, then attach ∥ detach | GW with the new scope; or partial links | `policyStillAllTraffic`; `consumerSyncFailed` |
| GW→GW | none | — | — |
| GW→MCP | POST /mcp-wide (clears `global`), then detach(prev) ∥ | promotion failed: GW with groups, which is the forbidden shape. Detach failed: MCP-wide with leftover links. | `policyStillAllTraffic`; `consumerSyncFailed` |
| MCP→T | DELETE /mcp-wide, then attach ∥ detach | MCP-wide with the PUT's group-less scope, so every MCP caller; or partial links | `policyStillMcpWide`; `consumerSyncFailed` |
| MCP→GW | POST /global (clears `mcp_wide`); links kept | MCP-wide with null scope, so every MCP caller | `policyStillMcpWide` |
| MCP→MCP | detach(prev) only | MCP-wide with leftover links | `consumerSyncFailed` |

Into MCP-wide, the link target is `[]`, so the existing diff code removes leftover links on the next save. The sync returns the flag response, or `null` when no flag was written. The previous scope is checked with `=== 'gateway-wide' | 'mcp-wide'`, so an unexpected client value behaves as `targeted`, the way a falsy `previousGlobal` did. A real level conflict on GW↔MCP is refused by the **PUT**, since both placements occupy `(*, G, d)`. On those transitions a 409 from the flag write can only come from a race.

### Actions and hooks

- **`updatePolicyAction`**
  - `previousGlobal: boolean` becomes `previousScope: PolicyScope`.
  - Promotion or demotion failure → `placementWriteFailureError(error, previousScope)`:
    - a 422 on the `mcp-wide` promotion → `policyMcpUnsupported`, whatever the previous placement. On `POST .../mcp-wide` the only validation failure is a plugin that does not run on MCP, so the copy never offers a retry.
    - previous GW → `policyStillAllTraffic`
    - previous MCP → `policyStillMcpWide`
    - previous T → not-running for `error.placement`, or its conflict variant when the cause is a 409
  - Consumer links that fail on a 409 keep the plain conflict copy.
  - A failed promotion into MCP-wide from GW or T, after a PUT that wrote `mcp_scope`, reads the policy back first. A 5xx does not say whether the promotion committed, so there are three branches:
    - **Not MCP-wide:** re-PUT the new scope with the previous `groups`/`except_groups` put back, so the new destinations stay; `null` when nothing is left. On success the copy is the rolled-back variant (`policyNotRunningMcpRolledBack` or `policyStillAllTrafficRolledBack`): the reload drops the group pick, so it asks for the groups again instead of a retry. If that PUT fails, the plain copy stands. If its response shows `mcp_wide: true`, the promotion committed after the read, so the new scope is re-PUT at once and the landed branch follows; if that re-PUT fails, `policyStillMcpWide`.
    - **Landed (`mcp_wide: true`):** no rollback. Finish the move by detaching the previous links. The save is a success, audited as usual; a failed detach answers `consumerSyncFailed`.
    - **GET failed:** no rollback. Global + groups is still gated, which is safer than an ungated MCP-wide policy.
  - Every swallowed failure on this path is logged with `logger.warn` (team, gateway, policy, status, error).
- **`usePolicyDraft`:** passes `previousScope: policyScopeOfItem(rawItem)` and `previousMcpScope: rawItem.mcp_scope ?? null`.
- **`createPolicyAction`**
  - Returns `promoted ?? created`. That is the post-promotion item, because TrustGate's POST returns `PolicyResponse`.
  - If the delete that follows a refused promotion fails, it answers `policyNotRunningLevelConflictError(cause, error.placement)`.
  - A 422 on the `mcp-wide` promotion deletes the new policy too. If the delete succeeds it answers `policyMcpRefused`, which is not a partial write; if not, `policyMcpUnsupported`.
  - A plain promotion failure answers `policyNotRunningError(error.placement)`.
- **Auto-attach:** `policy.global` becomes `isPromotedPolicy(policy)` at `features/consumers/components/ConsumerAddPolicyModal.tsx:134` and `features/applications/components/ApplicationPoliciesTab.tsx:298`, and the comment at `:128-130` is updated. No other consumer or application code changes.
- **`isPolicyNotRunningError`** stays keyed to `policyNotRunning*` only. After an MCP not-running failure, the modal's draft already matches what is stored (a group draft), so `CreatePolicyModal.tsx:185` must not reset it.

### Read-back and level check

- **`policyMapper.requestsFromOf`:** the order is `global` → **`mcp_wide`** → `consumer_ids` → groups → `consumer:[]`. MCP-wide reads as `group` with its keys, empty keys included.
  - `scopeShapeOf` needs no change: `consumer_ids` are not part of `mcp_scope`, so MCP-wide with leftover links stays `supported`. The next save detaches the links.
  - Update the doc comments at `:142-146` and `:157-164`.
- **`policyLevelConflict.ts`**
  - The short-circuit at `:45` becomes `!global && !mcpWide && consumerIds.length===0`.
  - `:51` uses `global || mcpWide` → `[ALL]`.
  - `placementOfItem` sets `mcpWide: item.mcp_wide === true`.
  - `placementOfDraft` sets `mcpWide: policyScopeOf(rf)==='mcp-wide' && !isRequestsFromIncomplete(draft)`. Choosing *Groups* before picking a group therefore shows no false conflict.
  - A group-only **item** without `mcp_wide` still occupies no level.

### Validation and copy

- **`PolicyRequestsFromSection.tsx`**
  - New `showErrors` prop. It passes `error={t('…groupsRequired')}` to `GroupMultiSelect`, which gets an `error?` prop forwarded to `MultiSelect`.
  - Adds a `groupsHelper` line under the Switch while *Groups* is selected.
  - Fixes the "Users" wording in the doc comment at `:56-62` to "Groups".
- **`PolicyCreateSidePanel`, `PolicyDetailSidePanel`, `CreatePolicyModal`:** add `isRequestsFromIncomplete` to the existing `submitAttempted` gate, next to `isNameValid`. Same handling: focus the Basics tab, set `hasError` on Basics, pass `showErrors`.
- **Security banner** (`PolicyDetailSidePanel.tsx:317-318`): switch on `policyScopeOf(draft.requestsFrom)` and add `securityBannerMcpWide`.
- **`PolicyDeleteModal.tsx:44-46`:** switch on `policyScopeOfItem`. MCP-wide uses `deleteDescriptionMcpWide` and requires typing DELETE, as global does.
- **List:** `listPoliciesAction` sets the scope with `policyScopeOfItem` and coverage `mcp`. `policyCoverageLabel` handles `mcp`. In `policyScopeSummary.formatPrincipal`, links are listed only when the policy is targeted, and the empty principal reads `allMcpTraffic` for MCP-wide. The `policies.constants.ts` switch gets `case 'mcp-wide': return 'cyan'`.
- **i18n (English only)**
  - `v2Gateway.apiErrors`: `policyNotRunningMcp`, `policyNotRunningMcpLevelConflict(Named)`, `policyStillMcpWide`, `policyMcpUnsupported`, `policyMcpRefused`, `policyNotRunningMcpRolledBack`, `policyStillAllTrafficRolledBack`.
  - `v2Policies`: `requestsFrom.{groupsRequired, groupsHelper}`, `groupsPlaceholder` changes from "All groups" to "Choose groups", plus `coverage.allMcp`, `scope.mcp-wide`, `detail.{securityBannerMcpWide, deleteDescriptionMcpWide}` and `scopeSummary.allMcpTraffic`.
- **Error prefixes:** `POLICY_NOT_RUNNING_MCP:`, `POLICY_NOT_RUNNING_MCP_CONFLICT:`, `POLICY_STILL_MCP_WIDE:`, `POLICY_MCP_UNSUPPORTED:`, plus `POLICY_MCP_REFUSED:` for the create whose policy was removed again.
  - None of them is a prefix of an existing one, because the colon differs, so the order of the checks does not matter.
  - Resolution happens next to `agentGatewayErrorMessages.ts:639-650`; the named variants at `:842-853`.
  - The first four are added to `isPolicyPartialWriteError`. `POLICY_MCP_REFUSED:` is not, because nothing was written.

### Testing (vitest)

| File | Cases |
|---|---|
| `__tests__/v2/policies/policyScopeOf.test.ts` | Flip `:20-22` (group → `mcp-wide`). Keep `:30-33`. Add `policyScopeOfItem`, `isPromotedPolicy` and `isRequestsFromIncomplete` (supported vs unsupported, `except_groups`-only). |
| `policyLevelConflict.test.ts` | Flip `:91-92`: a group draft takes `*\|eng\|*`. Keep `:30` (never-promoted draft) and reword its comment. Add: two MCP-wide policies with overlapping groups → conflict; disjoint groups → `null`; MCP-wide against global with the same groups → conflict; a group draft with no groups → nothing. |
| `syncPolicyAssociations.test.ts` | The five new rows of the matrix, with exact `{endpoint, method}` sequences. `/mcp-wide` promotion is retried and tagged `placement:'mcp-wide'`; the 409 is not retried; demotion is tagged. The promoted item is returned. `:147` changes `toBeUndefined` to `toBeNull`. |
| `createPolicyAction.test.ts` | A *Groups* draft runs the sync with `nextScope:'mcp-wide'` and returns the post-promotion item. MCP promotion failure → `policyNotRunningMcp`. Conflict, then a failed delete → `policyNotRunningMcpLevelConflict`. |
| `updatePolicyAction.test.ts` | `previousGlobal` → `previousScope` at `:57` and `:142`. MCP→T demotion → `policyStillMcpWide`. GW→MCP promotion → `policyStillAllTraffic`. T→MCP conflict → named MCP conflict. |
| `policyMapper.test.ts` | `mcp_wide`+groups → group, supported. `mcp_wide`+leftover `consumer_ids` → group, supported. `mcp_wide` with null scope → empty group. |
| `__tests__/v2/lib/agentGatewayErrorMessages.test.ts` | The three prefixes resolve. Named formatting. Partial-write is true for all three. `isPolicyNotRunningError` is false for the MCP ones. |
| `PolicyRequestsFromSection`, `PolicyCreateSidePanel`, `PolicyDetailSidePanel`, `CreatePolicyModal` | *Groups* with nothing picked: the create or update action is not called and the error is shown. |
| `__tests__/v2/features/policies/{PolicyInstanceCard,policyScopeSummary}.test.*` | `mcp` coverage label. Principal for MCP-wide. |

Run: `npx vitest run __tests__/v2/policies __tests__/v2/features/policies __tests__/v2/lib/agentGatewayErrorMessages.test.ts`, then `npm run lint`, `npm run typecheck` and `npm run test:unit`.

### Delivery: two PRs (estimates in changed lines)

The validation cannot ship after the *Groups* flip (see Deviations), so the cut is "engine", then "behaviour". Each PR is shippable alone.

| PR | Files (code / tests / i18n) | Total |
|---|---|---|
| **1. Engine. No UI behaviour change.** `policyScopeOf` is unchanged; `usePolicyDraft` passes `global ? 'gateway-wide' : 'targeted'`. | `types.ts` 8, `policies.constants.ts` 1, `policyContract.ts` 3, `syncPolicyAssociations.ts` 55, `policyWriteErrors.ts` 30, `agentGatewayErrorMessages.ts` 32, `createPolicyAction.ts` 10, `updatePolicyAction.ts` 26, `usePolicyDraft.ts` 2 → **code 167**. Tests: sync 105, errors 18, create 25, update 45 → **193**. `v2Gateway.json` **4**. | **~364** |
| **2. *Groups* promotes MCP-wide.** Includes validation, read-back, level check and copy. Needs TrustGate deployed first. | `policyScopeOf.ts` 24, `usePolicyDraft.ts` 2, `policyMapper.ts` 11, `policyLevelConflict.ts` 15, `PolicyRequestsFromSection.tsx` 16, `GroupMultiSelect.tsx` 4, `PolicyCreateSidePanel.tsx` 8, `PolicyDetailSidePanel.tsx` 14, `CreatePolicyModal.tsx` 8, `PolicyDeleteModal.tsx` 6, `listPoliciesAction.ts` 6, `policyCoverageLabel.ts` 4, `policyScopeSummary.ts` 4, `types.ts` 3, `ConsumerAddPolicyModal.tsx` 5, `ApplicationPoliciesTab.tsx` 2 → **code 132**. Tests **140**. `v2Policies.json` **9**. | **~281** |

PR 1 ships one visible fix on its own: *All traffic* created from a consumer or application modal is no longer attached, because `created.global` is now true.

### Deviations

1. **The suggested PR cut.** With *Groups* switched to MCP-wide and no validation, an empty *Groups* would promote a null scope. That runs on every MCP caller: an unsafe intermediate state. The validation therefore ships with the switch, in PR 2.
2. **"Four assertions flip" (exploration §9).** Only two do: `policyScopeOf.test.ts:20-22` and `policyLevelConflict.test.ts:91-92`.
   - `policyScopeOf.test.ts:30-33` stays, because the proposal keeps `policyConsumerIdsOf` returning `[]`.
   - `policyLevelConflict.test.ts:30` stays, because the draft contract is unchanged.

### Risks

- **GW→MCP after the PUT and before the promotion** briefly holds `global`+groups. If the promotion fails, it stays that way and runs on all LLM and A2A traffic for TrustGuard. The copy says "still all traffic, retry". The PUT-first order is the existing one.
- **Saving any change on an existing group-only draft promotes it.** This is intended, and the rollout SQL still applies.
- **The consumer and application tabs still offer MCP-wide policies for attach.** Those links are ignored at load, and the next save of the policy removes them. Listing them as applied is the follow-up.
- **The rollback race is narrowed, not closed.** The promotion can still commit after the restore's own write, which the restore response would not show. Closing it needs a precondition on TrustGate's PUT (`If-Match` or a version). Cross-repo follow-up.
- **The reverse direction is not covered.** A failed MCP→T demotion or MCP→GW promotion after the PUT leaves the policy MCP-wide with the PUT's group-less scope, so it runs for every MCP caller. The copy says "still MCP-wide, retry". The same read-back-and-restore pattern would fix it. Follow-up.
