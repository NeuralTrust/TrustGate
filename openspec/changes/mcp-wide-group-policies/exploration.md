# Exploration: mcp-wide-group-policies (RUN-1746)

SDD phase: **explore**. Branch `fix/run-1746-mcp-wide-group-policies` cut from `origin/develop` @ `700068b1` (HEAD == origin/develop at exploration time). Date: 2026-10-01.

## Exploration: TrustGate (Go)

### Current State

#### 1. Domain model: how placement is represented today

- `Policy` (`pkg/domain/policy/policy.go:24-41`) carries placement in two places only: `Global bool` (`json:"global"`, column `policies.global BOOLEAN NOT NULL DEFAULT FALSE`, partial index `policies_global_idx ON policies (gateway_id) WHERE global`, migration `20260603120000_collapse_policy_into_plugin.go:39,50`) and `ConsumerIDs`, which is **not** a column: it is the `consumer_policy` junction aggregated by `policySelectColumns` (`pkg/infra/repository/policy/repository.go:39-42`). `MCPScope` (`mcp_scope JSONB NULL`, migration `20260916120000_add_policy_mcp_scope.go`) narrows, it does not route.
- `IsGlobal()` returns `p.Global` (`policy.go:43-45`); spec `policy-inert-scope` pins that it MUST stay `p.Global` and MUST NOT derive from `len(ConsumerIDs)` (`openspec/specs/policy-inert-scope/spec.md:243`).
- **Draft contract**: `Policy.Draft()` = `!Global && len(ConsumerIDs)==0` (`pkg/domain/policy/level.go:234-236`). `creator.Create` can never set `global` nor attach (`pkg/app/policy/creator.go:80-102`), and `duplicator` copies scope but not placement (`pkg/app/policy/duplicator.go:73-85`), so every create/duplicate is born a draft.
- **Level (RUN-1621)**: `Level` is one cell `(consumer, group, destination)` with an explicit presence flag per dimension so the wildcard `all` is not the zero UUID (`level.go:25-49`). A policy occupies the cartesian product (`MCPScope.Occupancy`, `level.go:189-205`; `expandConsumers/Groups/Destinations`, `level.go:251-302`). `except_groups` is not part of the key. `Policy.Occupancy()` (`level.go:220-231`): disabled, tombstone (`{}`) and **draft** occupy nothing; **global** passes `consumerIDs=nil`, i.e. it occupies the wildcard consumer cell `consumer=all`.
- **Overlap is cell intersection, no subsumption** (`Overlaps`/`FirstOverlap`, `level.go:155-186`): `(all, G, ∅)` does **not** overlap `(X, G, ∅)`. That is what keeps the "consumer-scoped unscoped policy overrides the global of the same slug" rule (`composePolicies`, `pkg/app/consumer/data_finder.go:473-496`) from tripping the guard.
- 409 path: `ErrPolicyLevelConflict` wraps `commonerrors.ErrConflict` (`pkg/domain/policy/errors.go:40`); `LevelConflict(occupant, level)` builds the message (`errors.go:45-53`); `httpio.WriteError` maps `ErrConflict` → 409 with no special case.
- Consumer plane: `consumer.Type` ∈ `LLM|MCP|A2A` (`pkg/domain/consumer/consumer.go:25-30`), **mutable** on update (`pkg/app/consumer/updater.go:105-107`). The Store is a synthetic, non-persisted `TypeMCP` consumer with sentinel id `570e570e-…` (`pkg/domain/consumer/store.go:32,60-72`); it has no auths, so it is reachable only through platform login.

#### 2. Promotion API

- Routes: `POST|DELETE /v1/gateways/:gateway_id/policies/:id/global` (`pkg/server/router/admin_router.go:203-204`), under `RequireGatewayAccess(ResourcePolicies)` (`admin_router.go:197`). Handler struct field `GlobalPolicy` (`admin_router.go:93`, `pkg/container/modules/server_admin.go:93,172`), provider `policyhttp.NewGlobalPolicyHandler` (`pkg/container/modules/policy.go:104`).
- Handler `pkg/api/handler/http/policy/global_policy_handler.go:34-83`: no request body; `httpio.ParseGatewayScopedID[ids.PolicyKind]`; response `response.FromPolicyWithWarnings(p, overlapWarnings(...))` on POST (`:57`), plain `FromPolicy` on DELETE (`:82`). Swagger annotations at `:34-47` and `:60-72` (409 documented on POST only).
- Use case `apppolicy.Scoper{SetGlobal, UnsetGlobal}` (`pkg/app/policy/scoper.go:29-32`, wiring `modules/policy.go:75-79`). `setGlobal` (`scoper.go:71-92`): FindByID → gateway check → no-op if unchanged → `write` → set `PolicyTTLName` cache → `invalidation.GatewayData` → `signaler.Signal`. `write` (`scoper.go:98-108`) guards only the promotion (copy with `Global=true` into `LevelGuard.Check`); demotion is unguarded by design (spec `policy-level-uniqueness/spec.md:79-88`).
- Repo: `Repository.SetGlobal` (`pkg/domain/policy/repository.go:50`; pgx `repository.go:155-167`, inside `withMarkedTx` so the config-snapshot outbox marker commits with it; DB-less stub returns `ErrReadOnly`, `pkg/runtimeconfig/snapshot/adapters/policy_repository.go:73-75`). Only these two impls + mockery mocks implement it.
- Response DTO `PolicyResponse` (`pkg/api/handler/http/policy/response/policy_response.go:24-46`) echoes `global`, `consumer_ids`, `mcp_scope`, `warnings`. List filter `?global=` (`list_policy_handler.go:78,96`; SQL `repository.go:261,295`).
- OpenAPI: generated, never hand-edited — `make swagger` (swag → `docs/swagger.{json,yaml}`, `docs/docs.go`) + `make openapi` (`swagger2openapi` → `docs/openapi.json`), `make docs` runs both (`Makefile:150-164`). `docs/openapi_test.go:170-201` pins the 409 description on `/global` POST ("all-traffic level") and the draft wording on create.

#### 3. Load path and request-time evaluation

- `dataFinder.load` (`pkg/app/consumer/data_finder.go:101-153`), same code for Postgres and DB-less (DB-less binds the snapshot adapter to `policydomain.Repository`, `pkg/container/modules/core_data.go:66`; one `NewDataFinder`, `modules/consumer.go:89`).
- `loadPolicies` (`data_finder.go:304-327`): `IsGlobal()` → `globals` and `continue` (attachments of a global are ignored); else fan out per `ConsumerIDs`. A draft lands in neither bucket — that is the whole "runs nowhere" mechanism.
- `partitionScoped` (`data_finder.go:433-453`) splits into `unscoped | crossing (group-only) | mcpOnly (destination) | dormant`, `scoped` = the three scoped buckets in load order.
- Per consumer (`data_finder.go:122-140`): `unscoped = composePolicies(globals.unscoped, attached.unscoped)` (slug override among unscoped only), `scoped = mergeScoped(attached.scoped, globals.scoped)` (additive, dedup by id), then `plansFor` (`:174-183`):
  - MCP consumer (`c.Type == TypeMCP`): chain = unscoped; `MCPPlans = BuildPolicyPlans(unscoped, scoped)` (`buildMCPPlans`, `:162-167`).
  - LLM/A2A: `inertPolicies` (`:190-198`) = unscoped + `coalesceInert(inertSafeOnly(crossing))` (`:203-259`), compiled with `NewInertStagePlan`. **This is where "inert on LLM/A2A" lives**: destination and dormant never reach the crossing bucket; group-only reaches it only for an inert-safe plugin (today `trustguard`, `request_size_limiter`: `pkg/infra/plugins/trustguard/plugin.go:169`, `requestsize/plugin.go:66`; `tool_allowlist` opts out, `toolallowlist/plugin.go:82`).
- **Store** (`data_finder.go:142-149`): `data.StoreConsumer` gets **only** `globals.unscoped` / `globals.scoped` + `BuildPolicyPlans` over them. `/store/mcp` resolves to it in `resolveMCPConsumer` (`pkg/api/handler/http/mcp/mcp_handler.go:552-575`; bare fallback without policies at `:566-573` when `data.StoreConsumer` is nil). Per-user instances: `store.scoper` shallow-copies the RoutableConsumer (`pkg/app/store/scoper.go:100,135-138`) so the clones share `MCPPlans`; clones carry `InstanceOf` and `Registry.ScopeKey()` returns the shelf id (`pkg/domain/registry/registry.go:36-49`), which is what `targetOf` keys on (`pkg/app/consumer/policy_plans.go:343-349`). A group-only policy sits in `anyDest` and matches every destination, instances included.
- Group predicate on `tools/call`: `RPCDispatcher.callTool` (`pkg/app/mcp/rpc_dispatcher.go:194-262`) → `Resolve` → `planFor` (`:313-325`) → `PolicyPlans.PlanFor/Explain` (`policy_plans.go:286-321`) → `planWith` (`:383-422`) → `MCPScope.Matches` → `MatchesCaller` (`pkg/domain/policy/mcp_scope.go:159-183`). Caller projection `callerOf` (`policy_plans.go:446-454`): `principal.Groups()` from the token claim; **api-key callers are `PrincipalInert`** and match any `groups`. `tools/list`, prompts, resources and meta-tools run the unscoped chain only (`PreResponseDiscovery`, `pkg/app/mcp/plugin_runner.go:275-321`).
- Plugin state partition: chain/plan entries record `global: pol.IsGlobal()` (`pkg/app/plugins/plan.go:90`, `chain.go:119`) → `RuntimeScope.Global` (`executor.go:443-450`) → `Subject()` returns `("global", gatewayID)` or `("consumer", consumerID)` (`pkg/app/plugins/plugin.go:176-198`). Rate limiters key on it (`ratelimit/plugin.go:98`, `tokenratelimit/plugin.go:92`, `pertoolratelimit/plugin.go:180`).

#### 4. Warnings

`apppolicy.Warner` (`pkg/app/policy/warnings.go`), called by create/update/global handlers via `overlapWarnings` (`pkg/api/handler/http/policy/warnings.go:28-40`) and by attach (`association_handler.go:192-202`). GET does not compute warnings.
- `orphanWarning` "policy has no consumers and is not global: it runs nowhere" (`warnings.go:34`), emitted by `reachWarnings` with its **own predicate** `!p.Global && len(p.ConsumerIDs)==0` (`:182-184`), not `p.Draft()`.
- `inertUnsafeGlobalWarning` (`:43-46`, emitted `:179-180`) for global + group-only + non-inert-safe plugin.
- `reach` (`:199-228`): global → every consumer; else the attached ones; drops non-MCP when the scope does not cross. `apiKeyReach` (`:240-265`) names MCP consumers with an enabled api-key auth. `collisions` + `sameSlugRunsWhere` (`:297-361`): `sameSlugRuns{global bool, consumers}`; `reaches(consumerID)` has no notion of consumer type.
- Text asserted verbatim in `warnings_test.go:195` and functional `tests/functional/consumer_associations_test.go:405-420`.

#### 5. Level guard

- `LevelGuard.Check` (`pkg/app/policy/level_guard.go:72-86`): `taken := p.Occupancy()`; empty → write unguarded; else `LevelLock.WithSlugLocked(gateway, slug, exclude=p.ID)` → `firstConflict` (`:92-102`) intersects `taken` with each occupant's `Occupancy()`.
- Lock (`pkg/infra/repository/policy/level_lock.go:47-99`): `pg_advisory_xact_lock(hash(gateway, slug))` + `SELECT … FOR UPDATE` of enabled same-slug rows, columns `id, gateway_id, name, slug, enabled, global, mcp_scope, consumer_ids` (`lockedPolicyColumns`, `:30-33`; `scanLockedPolicy`, `:104-120`). The occupant set is computed from the row alone — **no consumer list is read**.
- Five guarded paths: create (`creator.go:92`), update incl. enable (`updater.go:176`), attach (`associator.go:164`, via `attachedTo` copy with `ConsumerIDs=[X]`, `:183-187`), promotion (`scoper.go:107`), duplicate (through create). Detach/demote unguarded.
- Consumer create/update/type change are **not** level writes today (no guard); they don't need one because the guard never enumerates consumers.

#### 6. Cache invalidation and config sync

- Promotion today: Postgres write inside `withMarkedTx` (outbox marker → snapshot recompile), `invalidation.GatewayData` → `InvalidateGatewayDataEvent` → subscriber drops consumer-data, policy, consumer, path caches for the gateway (`pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go:61-93`), plus `signaler.Signal` (debounced local recompile). Consumer create also invalidates the gateway (`pkg/app/consumer/creator.go:112-114`), so a new MCP consumer picks up gateway-wide policies on the next load.
- DB-less: the snapshot carries each policy as **domain JSON** (`snapshot.proto:77-79` `Policy{bytes json}`; `pkg/infra/configsnapshot/codec.go:88,156`), compiled from `Repository.List` → `scanPolicy` (`pkg/app/configsnapshot/compiler.go:371-372`). A new JSON-tagged field on `domain.Policy` flows with **no proto change**; the DP's `WithOnApplied` hook invalidates derived caches (`pkg/runtimeconfig/sync/worker.go:62-69`).
- **No new event type or invalidation is needed** for a new placement: reuse `withMarkedTx` + `invalidation.GatewayData` + `Signal` exactly as `setGlobal` does.

#### 7. Tests that cover the area (to extend)

| Area | Tests |
|---|---|
| Draft / occupancy | `pkg/domain/policy/level_test.go` — `TestPolicy_Occupancy` (:270), `TestPolicy_Occupancy_GlobalTakesTheAllTrafficLevel` (:364), `TestOverlaps` (:120), `TestLevelConflict` (:476) |
| Level guard + paths | `pkg/app/policy/level_guard_test.go` — `TestLevelGuard_Check_TwoGlobalsOfOnePluginCollide` (:274), `TestCreator_Create_CannotConflictBecauseEveryNewPolicyIsADraft` (:381), `TestScoper_SetGlobal_RefusesAnOccupiedAllTrafficLevel` (:450), `TestScoper_UnsetGlobal_IsNotGuarded` (:468), `TestDuplicator_Duplicate_OfAnOccupyingPolicySucceeds` (:494) |
| Promotion use case | `pkg/app/policy/scoper_test.go` (:31, :57, :83, :100) |
| Load path / Store | `pkg/app/consumer/data_finder_test.go` — `ComposesGlobalAndConsumerPolicies` (:63), `AppliesGlobalPoliciesToStoreConsumer` (:158), `StoreConsumerPartitionsGlobalPolicies` (:533), `MCPPlansAreMCPOnlyAndGlobalDestinationScopeNeverCrosses` (:594), `StoreConsumerPlansFromScopedGlobals` (:669); `data_finder_inert_test.go` (:163 group-only on own consumer, :342 coalescence); `data_finder_internal_test.go` (`partitionScoped`) |
| Plan selection / instances | `pkg/app/consumer/policy_plans_test.go` — `TestPolicyPlans_InstanceOfResolvesToTheShelfKey` (:202) |
| Warnings | `pkg/app/policy/warnings_test.go` — `PolicyWithoutConsumersRunsNowhere` (:195), `GlobalPolicyWithoutConsumersDoesNotWarn` (:206), `GlobalGroupScopedReachesEveryConsumerType` (:279), api-key set (:628-752) |
| Repo integration (`PG_TEST_URL`) | `tests/functional/repositories/policy/repository_test.go` — `TestRepository_GlobalFlag_RoundTripAndListByGateway` (:420); `level_lock_test.go` (:21, :75, :122, :157) |
| Snapshot | `pkg/infra/configsnapshot/codec_test.go` — `TestCodecRoundTripsPolicyMCPScope` (:166); `pkg/runtimeconfig/snapshot/adapters/adapters_test.go:313` (read-only `SetGlobal`) |
| OpenAPI | `docs/openapi_test.go:170` (409 on promotion) |
| Functional (tag `functional`) | `tests/functional/consumer_associations_test.go` — `TestPolicyGlobalScope_SetAndUnset` (:203), `…_CrossGatewayRejected` (:228), `…_SecondPromotionOfTheSamePluginRejected` (:379), `TestCreatePolicy_DuplicateOfARunningPluginIsCreatedAsADraft` (:405); `tests/functional/mcp_policy_scope_test.go` — `GroupScopedPolicySelectsMembers` (:483, OAuth stub minting `groups`), `PrincipalOnlyScopeCoversEveryRegistry` (:549), api-key inertness (:237, :297); helper `SetPolicyGlobal` (`tests/functional/common_test.go:216`). **No functional test drives `/store/mcp` with policies today**; Store coverage is unit-level (`data_finder_test.go`, `pkg/api/handler/http/mcp/store_dispatch_test.go`). |

#### 8. Docs and specs

- `docs/mcp-policy-scope.md`: placement table "What reaches an LLM or A2A chain" (`:120-135`, the draft row is `:126`), `global: true + scope` row ("This is how a scoped policy reaches the MCP Store", `:256`), orphan row (`:259`), Admin API table (`:514`), Rollout ("Deploy the data plane before the control plane", `:540-548`).
- Specs to amend by delta: `openspec/specs/policy-inert-scope/spec.md:241-249` (draft = no consumers and no `global`), `openspec/specs/policy-level-uniqueness/spec.md:79-88,100-104,152` (five guarded paths, `UnsetGlobal` unguarded, 409 on `/global`), `openspec/specs/mcp-policy-scope/spec.md:139-141,179-199` (orphan warning text; `global` + scope reaches the Store), `openspec/specs/mcp-policy-plan-selection/spec.md:33-56` (globals with scope reach `StoreConsumer`).

### Affected Areas

- `pkg/infra/database/migrations/<ts>_add_policy_mcp_wide.go` (new) — additive column + mutual-exclusion CHECK (+ optional partial index), template `20260916120000_add_policy_mcp_scope.go`.
- `pkg/domain/policy/policy.go` — new field (`MCPWide bool json:"mcp_wide,omitempty"`), predicate for "gateway-wide" placement and per-plane reach; keep `IsGlobal()` = `Global`.
- `pkg/domain/policy/level.go:220-236` — `Occupancy()` treats MCP-wide like global (wildcard consumer); `Draft()` false when MCP-wide.
- `pkg/domain/policy/repository.go:50` — new write port (`SetPlacement`/`SetMCPWide`); regen mocks.
- `pkg/infra/repository/policy/repository.go` (select columns `:39-42`, `scanPolicy` `:338-372`, new setter beside `:155-167`; `Update` `:124-138` should not write the new column) and `level_lock.go:30-33,104-120` (read the column for occupants).
- `pkg/runtimeconfig/snapshot/adapters/policy_repository.go:73` — read-only stub for the new port.
- `pkg/app/policy/scoper.go` — promote/demote MCP-wide, guarded promotion, atomic switch with `global`, MCP-protocol validation.
- `pkg/app/consumer/data_finder.go:111-149,304-327` — third bucket; MCP consumers and `StoreConsumer` take it, LLM/A2A skip it.
- `pkg/app/policy/warnings.go:172-228,325-361` — orphan predicate → `Draft()`, `reach` for MCP-wide = every MCP consumer, `sameSlugRuns` learns MCP-wide.
- `pkg/app/plugins/plan.go:90`, `chain.go:119` — only if MCP-wide state is to be gateway-wide (see open question 3).
- `pkg/app/consumer/associator.go:189-191` — attach to an MCP-wide policy (ignore / refuse / warn; see open question 2).
- `pkg/api/handler/http/policy/global_policy_handler.go` (or a new `mcp_wide_policy_handler.go`), `response/policy_response.go` (`mcp_wide`), optional `list_policy_handler.go` filter, `pkg/server/router/admin_router.go:93,203-204`, `pkg/container/modules/policy.go:75-79,104`, `modules/server_admin.go:93,172`.
- `docs/swagger.json`, `docs/swagger.yaml`, `docs/docs.go`, `docs/openapi.json` (regenerated with `make docs`), `docs/openapi_test.go`.
- `docs/mcp-policy-scope.md` (`:120-135`, `:256`, `:259`, `:514`, Rollout) and the four spec deltas above.
- Tests listed in §7.

### Approaches

Three independent choices: **storage**, **API shape**, **level model**.

#### Storage

1. **S1 — new boolean `mcp_wide`, mutually exclusive with `global`** — `ALTER TABLE policies ADD COLUMN IF NOT EXISTS mcp_wide BOOLEAN NOT NULL DEFAULT FALSE` + `CHECK (NOT (global AND mcp_wide))`; `Policy.MCPWide` with `json:"mcp_wide,omitempty"`.
   - Pros: additive, no backfill; every existing reader of `Global` keeps its meaning, so a reader that is not updated **fails closed** (sees a draft → runs nowhere, i.e. today's bug) instead of open. Old data plane during a rolling deploy, or a DP/CP code rollback with MCP-wide rows present: the policy runs nowhere, never on LLM/A2A. `omitempty` keeps the snapshot JSON byte-identical for every existing policy, so no fleet-wide config-version churn. `IsGlobal()` spec invariant untouched.
   - Cons: two booleans encode one three-valued placement; every placement read site must consider both (load, occupancy, draft, warnings, attach, runtime scope). CHECK forces the global↔MCP-wide switch to be one UPDATE.
   - Effort: Medium.
2. **S2 — reuse `global = true` + new column `plane` (`all|mcp`)** — "global restricted to MCP".
   - Pros: Store path, `Occupancy`, `Draft`, the global slug override and `RuntimeScope.Global` (gateway-wide state) work unchanged; smallest diff in the guard.
   - Cons: **fails open**. Every reader that ignores `plane` treats the row as all-traffic: `loadPolicies`/`plansFor` would compose it into every LLM/A2A chain unless split (`data_finder.go:127`), `reachWarnings`/`reach`/`sameSlugRunsWhere` treat it as reaching LLM, `associator.validatePolicyProtocol` skips it, `?global=true` lists it, and the console maps `global` → *All traffic*. An old DP during rollout or after a rollback runs it on **all LLM/A2A traffic for everyone** — exactly the shape the issue rejects ("App-only `global` + `groups`"). Breaks the meaning of the public `global` field.
   - Effort: Medium (smaller diff, larger blast radius).
3. **S3 — single enum `placement` (`attached|global|mcp`) replacing `global`** — API exposes `placement`, `global` kept as a derived/compat field.
   - Pros: one value, impossible states unrepresentable, natural switch.
   - Cons: backfill + dual-write of `global` for compatibility, touches the list filter, catalog descriptions, console contract and specs that pin `IsGlobal()`. Over-scoped for a fix.
   - Effort: High.

Rejected without a row: attaching to the Store sentinel consumer (`consumer_policy.consumer_id` has an FK to `consumers`, the Store is not persisted, and "Store only" is explicitly out of scope).

#### API shape

1. **A1 — dedicated resource `POST|DELETE /v1/gateways/{gw}/policies/{id}/mcp-wide`**, mirroring `/global`; same 200 `PolicyResponse` + `warnings`, 409 on level conflict, 404 cross-gateway.
   - Pros: symmetric with `/global`, self-describing in OpenAPI, no change to the `/global` contract or its `openapi_test` pin; the console calls one URL per placement.
   - Cons: one more route + handler pair; switching placement needs either two calls or "promotion clears the other placement" semantics.
   - Effort: Low.
2. **A2 — plane parameter `POST /global?plane=mcp`** (or body `{"plane":"mcp"}`), `DELETE /global` clears either.
   - Pros: one endpoint for "gateway-wide".
   - Cons: with S1 the URL says global while the body echoes `global:false, mcp_wide:true`; a parameter on a body-less POST is easy to drop, and a dropped `?plane=mcp` silently promotes to all-traffic (fail-open at the API layer); swagger must document two behaviours on one operation.
   - Effort: Low.
3. **A3 — `PUT /policies/{id}/placement {"placement":"global"|"mcp"|null}`**.
   - Pros: atomic switch by construction, one call for the console.
   - Cons: introduces a third style next to `/global`; `/global` would have to stay for compatibility.
   - Effort: Medium.

#### Level model (what an MCP-wide policy occupies)

1. **L1 — wildcard consumer, like global**: `Occupancy()` passes `consumerIDs=nil` when `MCPWide` → `(all, G, d)`.
   - Pros: zero change to `LevelGuard`/`LevelLock`; two MCP-wide of one plugin on overlapping groups → 409 (QA item); MCP-wide vs global with overlapping groups/destination → 409, which is a true conflict (both run on MCP for G); consumers created later or switched to MCP need no guard; consistent with the slug-override model.
   - Cons: an MCP-wide `(all, G)` and a same-plugin policy attached to MCP consumer X with `G` do **not** conflict and **both run** on X for members of G (scoped policies are additive, `mergeScoped`). This gap already exists today for `global` + `groups` vs an attachment.
   - Effort: Low.
2. **L2 — enumerate every MCP consumer (+ Store)**, as the issue words it: `(all, G, d) ∪ {(X, G, d) | X ∈ MCP consumers}`.
   - Pros: catches the double run above.
   - Cons: `Occupancy()` stops being a function of the row (needs the gateway's MCP consumer list inside the lock); consumer type change LLM→MCP and every attach become cross-slug level writes needing a guard; **false 409s**: an unscoped consumer policy `(X, ∅, ∅)` legitimately overrides an unscoped MCP-wide of the same slug (`composePolicies`), yet would now conflict — so the expansion has to be special-cased for unscoped; the Store cell is synthetic.
   - Effort: High.

### Recommendation

**S1 + A1 + L1.**

- Storage: `policies.mcp_wide BOOLEAN NOT NULL DEFAULT FALSE` with `CHECK (NOT (global AND mcp_wide))`; `Policy.MCPWide` (`json:"mcp_wide,omitempty"`); a domain predicate for the gateway-wide placement (e.g. `GatewayWide() = Global || MCPWide`) and `Draft() = !Global && !MCPWide && len(ConsumerIDs)==0`; `Occupancy()` nils consumers for either. Fails closed on every path not yet updated, on rollout and on rollback.
- API: `POST|DELETE /v1/gateways/{gw}/policies/{id}/mcp-wide` in the existing `Scoper` (or a sibling use case file). The promotion is guarded by `LevelGuard` with a copy carrying `MCPWide=true, Global=false`. Promoting either placement **clears the other in the same UPDATE**, so the console can switch *All traffic* ↔ *Users* without a window where the policy is a draft. The promotion refuses (422) a plugin without MCP support, reusing `validateMCPScopePlugin` (`pkg/app/policy/validate.go:88-99`), because for a nil-scope policy nothing else checks it. Repo write in `withMarkedTx`, then `invalidation.GatewayData` + `Signal` as in `setGlobal`. `Repository.Update` should stop writing placement columns, so a PUT cannot undo a concurrent promotion. The same lost-update race exists today for `global` at `repository.go:129`.
- Load: `loadPolicies` returns a third bucket (attachments ignored, as for global). MCP consumers compose it next to the globals: unscoped into `composePolicies`, which keeps the consumer slug override, and scoped into `mergeScoped`. `StoreConsumer` takes globals ∪ MCP-wide. LLM/A2A never see it, so the inert-safe opt-in becomes irrelevant to it, and `rate_limiter`/`tool_allowlist` by group also work MCP-wide. Merging should keep repository order (priority, created_at, id).
- Warnings: switch the orphan predicate to `p.Draft()`, and keep the text stable unless the app stops string-matching it. `reach` for MCP-wide returns every MCP consumer. `sameSlugRuns` gets an `mcpWide` flag, and `reaches` takes the `reachedConsumer` so it can test `c.mcp`. `inertUnsafeGlobalWarning` stays global-only. Optionally add one hint when `global` + group-only on an inert-safe plugin: "use MCP-wide to keep it off LLM/A2A".
- Level: L1, with the attachment double-run documented as a known gap shared with `global` + `groups`. A warning can cover it later if wanted.
- Docs/OpenAPI: annotations on the new handler, `make docs`, and an extra assertion in `docs/openapi_test.go:170`. Add an MCP-wide row to the table at `docs/mcp-policy-scope.md:120-135`, rewrite `:256`/`:259`/`:514`, and add the rollout query from the issue to Rollout.

### Risks

- **Api-key callers bypass the group gate on regular MCP consumers** (`callerOf`, `policy_plans.go:446-454`): an MCP-wide "Finance only" policy runs for every api-key caller of every MCP consumer that accepts one. The QA item "not for a non-member" holds only for token callers. The Store is unaffected (no api key). The `apiKeyReach` warning will name those consumers once `reach` covers MCP-wide.
- **Double execution with attachments (L1)**: MCP-wide `(all,G)` and a same-plugin, same-group policy attached to MCP consumer X both run on X. This is pre-existing for global + groups and not caught by the guard.
- **Plugin state partition**: with `IsGlobal()` unchanged, an MCP-wide `rate_limiter` keys its counter per consumer (`RuntimeScope.Subject`, `plugin.go:187-198`). That means one budget per MCP consumer plus one for the Store sentinel, not one gateway-wide budget like global. Decide in design (open question 3).
- **Orphan warning text is a cross-repo contract**: asserted in Go tests (`warnings_test.go:195`, `consumer_associations_test.go:416-419`) and probably string-matched by the console (`policyLevelConflict.ts`). Changing it needs both repos in lockstep.
- **Create still warns "runs nowhere"**: the console flow is create → promote, so the create response carries the orphan warning by contract. The console must surface the promotion response's warnings, not the create's, which is the same as the *All traffic* flow today.
- **Review budget**: migration + domain + repo + snapshot stub + use case + handler/route/DI + regenerated OpenAPI (4 files) + docs + specs + unit/integration/functional tests is well over 400 changed lines. Expect chained PRs. One possible split: (1) migration/domain/repo/load path with unit tests; (2) promotion API, warnings and OpenAPI; (3) functional tests and docs.
- **No functional Store harness**: QA item 2 (`/store/mcp`, per-user instance) needs either a new functional test with platform-login tokens carrying `groups` or reliance on unit tests (`data_finder_test.go` Store cases + `policy_plans_test.go:202`).
- **CI**: `make test` does not compile `functional`-tagged files; run `go vet -tags functional ./...` before push (per memory note) and wait for the CI functional check.

### Code vs issue

- *"Level guard: it occupies every MCP consumer × its groups × its destination"* — the code has no such enumeration for any placement. `global` occupies the single wildcard cell `consumer=all` (`level.go:224-226`), and wildcard does not subsume specific consumers (`level.go:162-186`). Enumerating would create false 409s against the unscoped consumer override and would need guards on consumer type changes (L2). L1 satisfies every QA item as written.
- *"`global` + `groups` runs on all LLM and A2A traffic for everyone"* — true only for inert-safe plugins (`trustguard`, `request_size_limiter`). For `rate_limiter`, `per_tool_rate_limiter` and `tool_allowlist`, `global` + `groups` is already MCP-only (`inertSafeOnly`, `data_finder.go:203-211`) and warns `inertUnsafeGlobalWarning`. The bug matters most for TrustGuard.
- *"Load path: MCP consumers and `data.StoreConsumer` take it in their scoped set"* — only if it has a scope. An MCP-wide policy with `mcp_scope: null` belongs in the unscoped chain, which also runs on `tools/list`/prompts. The design must state whether a nil scope is allowed on MCP-wide (open question 1).
- `Policy.Draft()` is at `level.go:234`, not `:231` (`:231` is the end of `Occupancy`). The other cited lines match (`data_finder.go:143`, `:304`, `docs/mcp-policy-scope.md:126`).
- Rollout SQL `p.mcp_scope ? 'groups'` misses drafts scoped by `except_groups` alone. Because of `omitempty` on `MCPScope.Groups` (`mcp_scope.go:38`), an empty `groups` never serializes, so the query is otherwise correct.
- Minor doc drift, not in scope: `docs/mcp-policy-scope.md:253` says reading back a dormant policy answers with a warning, but `GET` does not compute warnings (only create/update/global/attach do).

### Open questions

1. Does MCP-wide require a principal (`groups`/`except_groups`), or are `mcp_scope: null` ("all MCP traffic") and destination-only scopes allowed? A destination-only MCP-wide behaves exactly like `global` + destination. The recommendation is to allow any scope and refuse only plugins without MCP support.
2. Attachments on an MCP-wide policy: ignore them at load and in occupancy, as `global` does (`loadPolicies` `continue`)? Or refuse the attach/promotion (422/409)? Or ignore with a warning? This also decides whether `associator.validatePolicyProtocol` skips MCP-wide like global (`associator.go:190`).
3. Should plugin state of an MCP-wide policy be gateway-wide, like global (`RuntimeScope.Global`)? That would need a new predicate used at `plan.go:90`/`chain.go:119`. The alternative is per consumer, with the Store as its own partition.
4. Switch semantics: should `POST /mcp-wide` on a global policy (and vice versa) atomically swap (recommended), or answer 409/422 "demote first"?
5. Should the orphan warning text change to mention MCP-wide? Does the console string-match it, or the `global` field? This needs the app exploration.
6. Should L1's known gap (MCP-wide + same-plugin same-group attachment on an MCP consumer both run) get a non-blocking warning now, or stay documented only?
7. Should the list endpoint get an `?mcp_wide=` filter (`list_policy_handler.go:78`)? The issue does not ask for it, but the console's list view may need it to badge placement.
8. Rollout decision for the existing group-only drafts: promote them automatically (data migration) or per environment by hand, as the issue's checklist implies? The recommendation is no data migration and a documented manual decision.

### Ready for Proposal

Yes, for the TrustGate side. Tell the user: the recommended shape is a new `mcp_wide` column that is mutually exclusive with `global`, a dedicated `/mcp-wide` promotion endpoint, and occupancy mirroring global's wildcard consumer. It fails closed on rollout and rollback and needs no guard or invalidation machinery beyond what `/global` already uses. Open questions 1–4 should be settled before design. Question 5 must be settled jointly with the app exploration.

## Exploration: app (console)

Repo root: `/Users/edu/Neuraltrust/app-run1746`. `$P` = `app/[locale]/v2/features/policies`. Branch `fix/run-1746-mcp-wide-group-policies`, working tree clean.

### Current State

**1. The Requests from control and the form state**
- `$P/components/PolicyRequestsFromSection.tsx:91-101` draws three segments: `all` → "All traffic", `group` → "Groups", `consumer` → "Applications". The labels come from `messages/en/v2Policies.json:150-166` (`detail.requestsFrom.*`).
  - The **Groups** segment only shows when the plugin serves MCP (`supportsMCP`, :78, :96).
  - Switching segment clears the previous choice (`emptyRequestsFrom`, :40-44).
  - `except_groups` has no control; it is carried through untouched (:130-133).
  - The group selector's placeholder is "All groups" (`groupsPlaceholder`, json:158). So an empty group selection reads as "everyone".
- Types live in `$P/types.ts`:
  - `PolicyRequestsFrom` (:119-123).
  - `PolicyScope = 'gateway-wide' | 'targeted'` (:54).
  - `PolicyCoverage` (:56).
  - `PolicyScopeShape` (:140).
  - `PolicyDraft` (:149-165).
  - `AgentGatewayPolicyItem` (:26-43) has `global: boolean`, `consumer_ids?` and `mcp_scope?`. There is no placement field.
- `$P/lib/emptyPolicyDraft.ts:22` defaults a new policy to `{kind:'all'}`.

**2. How a Requests from choice becomes a placement**
- `$P/lib/policyScopeOf.ts:12-14`: `all` → `'gateway-wide'`; everything else, `group` included, → `'targeted'`.
- `$P/lib/policyScopeOf.ts:17-19`: `policyConsumerIdsOf` returns `[]` unless the choice is `consumer`.
- So **Groups** saves `global=false`, no consumer links, and `mcp_scope.groups` (which goes in the body via `mcpScopeFromDraft`, `$P/lib/policyMapper.ts:102-118`). That is a draft: it runs nowhere.

**3. Save flow, end to end** (server actions; there are no API routes)
- **Create:** `CreatePolicyModal` (:166) and `$P/hooks/usePolicyCreate.ts:43` call `$P/actions/createPolicyAction.ts`.
  1. Plan entitlement gate (:65-68).
  2. `buildPolicyWriteRequest` (:74) builds the body. It carries `mcp_scope` but never `global` or consumer ids (`$P/lib/policyContract.ts:11-39`).
  3. TrustGuard collector id is injected for guardrail policies (:84-88).
  4. `POST /v1/gateways/{gw}/policies` (:90-94).
  5. `syncPolicyAssociations` (:109-117) runs with `previousScope:'targeted'`, `nextScope: policyScopeOf(...)`, `nextConsumerIds: policyConsumerIdsOf(...)`.
  6. If the level check refuses the promotion, the new policy is deleted again (:130-138).
  7. Audit metadata records `scope: policyScopeOf(...)` (:176).
  8. It returns `created`, which is the **POST response, taken before promotion**, so `global` is always `false` in it.
- **Update:** `$P/hooks/usePolicyDraft.ts:95-105` passes `previousGlobal: rawItem.global` and `previousConsumerIds` into `$P/actions/updatePolicyAction.ts`.
  - The previous state is a boolean today (params :42-44, used at :105). A third placement cannot be expressed.
  - The PUT goes first (:83-87), then the sync (:100-109).
- **Association sync:** `$P/lib/syncPolicyAssociations.ts`.
  - `setGlobal` (:33-39) calls `POST`/`DELETE /policies/{id}/global`.
  - `attachConsumer`/`detachConsumer` (:41-55) call `/consumers/{cid}/policies/{id}`.
  - The global flag gets 2 attempts, 250 ms apart (:28-31). Only network errors, 5xx, 408 and 429 are retried (:69-74).
  - Errors are tagged `PolicyAssociationError('promotion'|'demotion'|'consumer-links')` (`$P/lib/policyWriteErrors.ts:18-31`).
  - Order of calls:
    - next is gateway-wide → promote only. **Existing consumer links are kept** (:137-143).
    - otherwise → demote if it was global, then attach and detach the difference in parallel (:145-167).
- **Admin API client:** `app/[locale]/v2/lib/agentGatewayClient.ts`.
  - Base URL is `AGENTGATEWAY_URL` (:17).
  - Auth is an HS256 JWT `{tenant_id,user_id,user_email}` signed with `AGENTGATEWAY_JWT_SECRET`, 5-minute lifetime, cached (:57-139).
  - Non-2xx responses throw `AgentGatewayApiError(status, message)`, preferring `body.message` over `body.error` (:161-187).
  - **The response's `warnings[]` is never read anywhere in the console.** So "the API no longer warns runs nowhere" can only be checked on the TrustGate side.
- **409 handling:**
  - `isPolicyLevelConflict` matches the status *and* the wording `level already occupied` / `already runs plugin .+ at level` (`$P/lib/policyWriteErrors.ts:63-70`). The occupant's name is pulled out at :73-76.
  - Error messages use string prefixes: `POLICY_NOT_RUNNING:`, `POLICY_NOT_RUNNING_CONFLICT:`, `POLICY_STILL_ALL_TRAFFIC:`, `POLICY_LEVEL_CONFLICT:` (`app/[locale]/v2/lib/agentGatewayErrorMessages.ts:171-197`, resolved at :638-650 and :843-853).
  - Partial writes are detected by `isPolicyPartialWriteError` (:911-921) and `isPolicyNotRunningError` (:933-938).
  - The copy in `messages/en/v2Gateway.json:123-126` (`apiErrors.policyNotRunning`, `policyStillAllTraffic`, …) is specific to "all traffic".
  - `CreatePolicyModal.tsx:185-187` resets the draft to `consumer:[]` after a not-running error.

**4. Read-back and list views**
- `$P/lib/policyMapper.ts:165-178` (`requestsFromOf`) checks in this order:
  1. `global` → `all`
  2. `consumer_ids` → `consumer`
  3. groups or except_groups → `group`
  4. otherwise `consumer:[]`
- So a group-only draft already reads back as **Groups** with its groups (tested in `__tests__/v2/policies/PolicyRequestsFromSection.test.tsx:279-315`).
- `scopeShapeOf` (:152-155, doc :142-146) rebuilds the scope from the draft and compares. `global` + `groups` comes back `unsupported` → the scope is shown read-only (`$P/components/PolicyDetailSidePanel.tsx:199-203`, :~535-560) and the PUT leaves `mcp_scope` out (:246).
- `$P/actions/listPoliciesAction.ts:55-67`: row `scope` is `global ? 'gateway-wide' : 'targeted'`, and coverage is `all` or `{targeted, count: consumer_ids.length}`. A group-only draft therefore shows **"0 applications"** (`$P/lib/policyCoverageLabel.ts:15-20`, `$P/components/PolicyInstanceCard.tsx:64,95`). The scope line shows the group names (`$P/lib/policyScopeSummary.ts:77-104`). There is no explicit "runs nowhere" badge.
- `$P/constants/policies.constants.ts:15-20` has an exhaustive `switch` over `PolicyScope`, so TypeScript will flag a new member.
- Other "how wide is this policy" displays key off `global` only:
  - Security banner: `$P/components/PolicyDetailSidePanel.tsx:317-318`.
  - Delete confirmation: `$P/components/PolicyDeleteModal.tsx:44-46`. A group policy reads "affects 0 applications".

**5. Client-side copy of TrustGate's level check**
- `$P/lib/policyLevelConflict.ts`:
  - `PolicyPlacement {enabled, global, consumerIds, scope}` (:14-21).
  - `policyLevels` returns no levels when `!global && consumerIds.length===0` (:45). **This is the "group-only runs nowhere" line**, with the matching doc at :34-40.
  - Levels are keyed `consumer|group|destination`, with `*` for "any" (:51-67).
  - `placementOfItem` (:71-73) and `placementOfDraft` (`global: kind==='all'`, :81-88; doc :76-80).
- It is used in `PolicyCreateSidePanel.tsx:92-95` and `PolicyDetailSidePanel.tsx:305-315`, and blocks Save while it reports a conflict.

**6. Other screens that treat `global` as "applies automatically"**
About 31 call sites across 15 files, including:
- `features/consumers/lib/buildConsumerPolicyLabels.ts:4-36`
- `features/consumers/lib/attachablePoliciesForConsumer.ts:16-18`
- `features/consumers/lib/cloneConsumerPolicies.ts:12-17`
- `features/consumers/components/ConsumerPoliciesTab.tsx:64-82`
- `features/consumers/components/ConsumerAddPolicyModal.tsx:131-149`
- `features/applications/lib/applicationPolicies.ts:16-98`
- `features/applications/components/ApplicationPoliciesTab.tsx:76-82, 295-305`

Both "create from a consumer or application" flows attach the created policy unless `policy.global`. Because `created.global` is always `false`, this happens for every new policy, whatever Requests from says.

**7. API types**
All hand-written: `$P/types.ts` and `$P/lib/policyContract.ts`. No OpenAPI codegen exists (nothing in `package.json`). A new field or endpoint is a manual edit in those two files plus the endpoint string in `syncPolicyAssociations.ts`.

**8. i18n and feature flags**
- v2 copy is English only: `messages/en/v2Policies.json`, `messages/en/v2Gateway.json`. There is no `messages/es/v2Policies.json`.
- No feature flags in `features/policies`.
- No `docs/v2/SDD.md` update needed: no new module or pattern (`.cursor/rules/v2-sdd-maintenance.mdc`).

**9. Tests and scripts**
- Scripts (`package.json`): `npm run lint` (next lint), `npm run typecheck` (next typegen + tsc), `npm run test:unit` (vitest run). Single file: `npx vitest run <file>`.
- Test files under `__tests__/v2/policies/`:
  - `policyScopeOf.test.ts`: :18-22 asserts group → `targeted`; :30-33 asserts group → `[]`. **Both flip.**
  - `policyLevelConflict.test.ts`: :29-30 asserts group-only takes no level; :91-92 asserts a group draft has 0 levels. **Both flip.**
  - `policyMapper.test.ts`: group read-back :250-261; `global`+groups unsupported :295-300; round-trip :373-421.
  - `syncPolicyAssociations.test.ts`: the transition matrix and endpoint/method assertions (:41-128+).
  - `createPolicyAction.test.ts`: :107-119 sync arguments; :160-260 partial writes and 409.
  - `updatePolicyAction.test.ts`: `previousGlobal` at :57 and :142.
  - `PolicyRequestsFromSection.test.tsx`: label 'Groups' at :148; group-only at :279-315.
  - `PolicyCreateSidePanel.test.tsx:97-120` and `PolicyDetailSidePanel.test.tsx:203-222`: conflict callout.
- Also `__tests__/v2/lib/agentGatewayErrorMessages.test.ts` and `__tests__/v2/policies/policyApiErrorMessages.test.ts`.

**10. TrustGate contract (confirmed, not explored)**
- Routes: `POST`/`DELETE /:id/global` (`pkg/server/router/admin_router.go:203-204`).
- Both return `PolicyResponse` with `warnings[]`; `POST` can answer 409 (`pkg/api/handler/http/policy/global_policy_handler.go:34-83`).
- `scoper.setGlobal` returns early when the flag already has the requested value (`pkg/app/policy/scoper.go:79`). Only promotion is checked against the level guard (:98-108).
- `loadPolicies` skips consumer links for a global policy (`pkg/app/consumer/data_finder.go:316-318`).

### Affected Areas
- `$P/types.ts`: add the read field (`mcp_wide?: boolean` or a placement enum), add `'mcp-wide'` to `PolicyScope`, optionally add `{kind:'mcp'}` to `PolicyCoverage`.
- `$P/lib/policyScopeOf.ts`: `group` → `'mcp-wide'`; update the doc.
- `$P/lib/syncPolicyAssociations.ts`: reconcile three placements, generalise `writeGlobalFlag` to a placement writer, detach links when moving to MCP-wide, tag the failure with its placement, and return the promote response.
- `$P/actions/createPolicyAction.ts` and `$P/actions/updatePolicyAction.ts`: change the previous-state parameter from a boolean to the full scope, handle the new partial-write copy, return the post-promotion item.
- `$P/hooks/usePolicyDraft.ts:102`: derive the previous scope from `rawItem`. Also decide whether an existing group-only draft can be made dirty so it can be saved (:64-67).
- `$P/lib/policyMapper.ts:165-178` (and doc :142-146, :157-164): MCP-wide → `group`; decide how MCP-wide plus consumer links reads back.
- `$P/lib/policyLevelConflict.ts:14-88`: add `mcpWide` to the placement, remove the :45 short-circuit for it, add an MCP-wide consumer key, update the draft and item placements.
- `$P/actions/listPoliciesAction.ts:55-67`, `$P/lib/policyCoverageLabel.ts`, `$P/constants/policies.constants.ts:15-20`: row scope, coverage and badge.
- `$P/components/PolicyRequestsFromSection.tsx`: helper text under Groups ("MCP traffic only, every MCP application and the MCP Store"); decide on requiring at least one group; fix the stale "Users" doc at :56.
- `$P/components/PolicyDetailSidePanel.tsx:317-318`, `$P/components/PolicyDeleteModal.tsx:44-46`: MCP-wide variants of the banner and delete text.
- `$P/lib/policyWriteErrors.ts`, `app/[locale]/v2/lib/agentGatewayErrorMessages.ts` (:8-30 key union, :160-197, :638-650, :911-938): new prefixes such as `POLICY_NOT_RUNNING_MCP:` and `POLICY_STILL_MCP_WIDE:`, or a placement inside the existing ones.
- `messages/en/v2Policies.json` (requestsFrom :150-166, coverage :52-55), `messages/en/v2Gateway.json` (apiErrors :123-126).
- Optional, depending on Open question 7: `features/consumers/lib/{buildConsumerPolicyLabels,attachablePoliciesForConsumer,cloneConsumerPolicies}.ts`, `features/applications/lib/applicationPolicies.ts`, `ConsumerPoliciesTab.tsx`, `ConsumerAddPolicyModal.tsx:131-149`, `ApplicationPoliciesTab.tsx:295-305`. A small predicate would cover them: "applies automatically" = `global || (mcp_wide && protocol==='MCP')`.
- Tests to extend: every file listed under Current State §9.

### Approaches
1. **(a) A plane parameter on `POST .../policies/{id}/global`** (`{plane:"mcp"}` or `?plane=mcp`)
   - Console change: `setGlobal(gw,id,claims,enabled,plane?)` sends a body on POST; the retry logic is reused as is. Switching between All traffic and Groups could be **one call**, but only if TrustGate makes "promote to the other plane" an atomic move. Today `setGlobal` returns early at `scoper.go:79`, so that would have to change.
   - Pros: smallest diff (about 5–10 lines in sync); one switch call means one fewer partial-failure state.
   - Cons: what does `DELETE /global` clear, and what does `global` mean on read? If MCP-wide reads back as `global:true`, all ~31 call sites become wrong: they show it as All traffic, list it on LLM applications (`globalPoliciesForPlanes`), and `requestsFromOf` sends it to `all`. Any reading of `global` that isn't strictly gateway-wide breaks every other API client too. The Swagger text on `/global` ("all-traffic level") would also need rewording.
   - Effort: Low on the write path; Medium overall (the read field is still needed).
2. **(b) A dedicated `POST`/`DELETE .../policies/{id}/mcp-wide`**, with a read field `mcp_wide: boolean` (or `placement`) and `global` staying `false` for MCP-wide.
   - Console change: generalise `writeGlobalFlag` to `writePlacementFlag(path)` (about 10–20 lines); otherwise identical to `/global`. All traffic ↔ Groups is `DELETE /global` + `POST /mcp-wide` (two calls) unless TrustGate makes either promotion clear the other in the same transaction.
   - Pros: the read field mirrors the endpoint the way `global` mirrors `/global`; every existing `item.global` call site and every other `/global` client stays correct without an audit; an absent field (older TrustGate) safely means `false`.
   - Cons: one more partial-failure state on All traffic ↔ Groups if the switch isn't atomic (demoted but not promoted means it runs nowhere; the reverse leaves `global`+groups).
   - Effort: Low on the write path; Medium overall.
3. **How the client-side level check models MCP-wide** (independent of 1 and 2)
   - 3a, recommended: a symbolic consumer key (`mcp:*|group|dest`). It catches the QA case (two MCP-wide policies on overlapping groups → 409) with no false positives. It misses MCP-wide against a consumer-attached MCP consumer; that is acceptable, because the file states the gateway stays the judge (`policyLevelConflict.ts:9-12`).
   - 3b: expand to the gateway's MCP consumer ids. More exact, but needs consumer types loaded on the Policies screen, which they are not today (`useGatewayConsumers` only loads on demand).

### Recommendation
- The URL shape costs the console about the same either way (±10 lines). Prefer **(b)** for read/write symmetry and zero risk to `/global` and its existing callers.
- Whichever shape is chosen, the console needs:
  - a separate read field, with `global` keeping the meaning "gateway-wide only";
  - promotion into one placement to replace the other atomically (one row update, one level-guard check), so each transition into a promoted placement is a single call;
  - MCP-wide to **win over consumer links** in `loadPolicies`, as `global` does at `data_finder.go:316-318`.
- Console plan (sketch, about 180–250 lines of code plus 200–300 lines of tests; likely over the 400-line review budget, so consider two PRs: (1) save path, read-back and level check; (2) list, copy and the consumer/application screens):
  1. `policyScopeOf`: `group` → `'mcp-wide'`.
  2. `syncPolicyAssociations` transitions:
     - into MCP-wide: promote MCP-wide (or demote global first if not atomic), then detach every previous consumer.
     - into gateway-wide: promote global (or demote MCP-wide first if not atomic).
     - into targeted: demote whichever is set, then attach and detach.
  3. Replace `previousGlobal` with `previousScope`, derived from the item.
  4. Have create return the post-promotion `PolicyResponse`, so the consumer and application create flows skip the attach for any promoted placement.
  5. `requestsFromOf`: `mcp_wide` → `group`.
  6. `PolicyPlacement.mcpWide` plus the 3a key.
  7. Coverage `{kind:'mcp'}`, an MCP-wide badge, partial-write copy and helper text.
  8. Tests: flip the four assertions in policyScopeOf and policyLevelConflict, and add the sync transition matrix.

### Risks
- **The PUT and the association writes are not atomic.**
  - All traffic → Groups: the PUT writes the groups while the policy is still global. If the demotion fails, it stays `global`+groups, the exact shape RUN-1621 forbids; for inert-safe plugins such as TrustGuard (the modal's default type, `CreatePolicyModal.tsx:33`) that runs on all LLM/A2A traffic for everyone.
  - Groups → All traffic: for a moment it is MCP-wide with scope `null`, which means every MCP caller.
  - Mitigation: the atomic switch on TrustGate, plus "still MCP-wide" copy.
- **Create from a consumer or application** attaches the new policy because `created.global` is always `false`. This already happens for All traffic (harmless only because global ignores links). For MCP-wide it is harmful unless MCP-wide also wins over links at load.
- **Applications → Groups must detach every previous consumer.** Otherwise the policy keeps running on those consumers' LLM plane for everyone.
- **Groups with nothing selected**: today that is an inert draft. As MCP-wide with `null` scope it becomes every MCP caller, and the "All groups" placeholder invites it. Decide: require at least one group (client check, plus a TrustGate 422?) or accept "MCP only, everyone".
- **Existing group-only drafts open as Groups with Save disabled** (nothing has changed), so the console cannot promote them without a dirty-on-placement-mismatch rule and a callout. Otherwise only the rollout SQL can fix them.
- **Deploy order**: the console must ship after TrustGate. An old TrustGate answers 404 on the new endpoint, which surfaces as `policyNotRunning`. An old console reads an MCP-wide policy as a group draft; switching it to Applications there would attach consumers without demoting it.
- **The client-side check must never be stricter than TrustGate's.** If MCP-wide and global with the same groups are different levels on the gateway, the console must not report a clash.
- **TrustGate's 409 wording must stay recognisable** (`already runs plugin .+ at level`), or the console's matcher at `policyWriteErrors.ts:63-70` falls back to the plan-limit copy.

### Ready for Proposal
Yes. The console scope is clear and fully mapped. Before design, the orchestrator should get TrustGate's answers to Open questions 1–5; they decide how the sync matrix and the level check are written.

### Open questions
1. What is the read field: `mcp_wide: bool` or `placement: "gateway"|"mcp"|null`? And does `global` stay `false` for an MCP-wide policy? The console needs yes.
2. When one placement is promoted while the other is set, does TrustGate switch atomically, answer 409, or answer 422? Same question for `DELETE` under shape (a).
3. Load precedence: does MCP-wide ignore consumer links the way `global` does? Is attaching a consumer to an MCP-wide policy refused?
4. Is MCP-wide allowed with `mcp_scope` `null`, or with only `except_groups`? Or is it 422?
5. What exact levels does MCP-wide take? Does it clash with global on the same groups, and with a consumer-attached MCP consumer on the same groups? Does it keep the 409 wording?
6. Do the promote and demote responses return `PolicyResponse` with the new field, so create can return the post-promotion item?
7. Product: is it in scope for RUN-1746 that the consumer and application Policies tabs list MCP-wide policies as applied, and not detachable, on MCP consumers? Or is that a follow-up?
8. The UI label is **"Groups"** (`messages/en/v2Policies.json:153`, tests at `PolicyRequestsFromSection.test.tsx:148`), while the issue says "Users" and the component doc at :56 says "labelled Users". Which one stays?
9. Existing group-only drafts: add a console affordance (dirty plus a callout), or rely on the rollout SQL only?
10. Should Groups stay offered in `CreatePolicyModal` when it is opened from a consumer or application, whose intent is to attach?
11. Where the issue doesn't quite match the code:
    - **Label**: covered in Q8.
    - **`global` + groups**: the issue says it runs on all LLM/A2A traffic for everyone. That is only true for plugins that opt in with `ScopeInertSafe` (`pkg/app/plugins/plugin.go:47-69`; for example TrustGuard and requestsize, but not tool_allowlist, per `warnings.go` `inertUnsafeGlobalWarning`). The rejection still stands.
    - **The "runs nowhere" warning**: the issue lists it in QA, but the console never reads `warnings[]`, so it can only be checked against the API.
