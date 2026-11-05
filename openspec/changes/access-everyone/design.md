# Design: Everyone and bulk Assign / Remove on Access › Groups

Inputs: [`proposal.md`](./proposal.md), [`exploration.md`](./exploration.md),
specs `store-everyone-access`, `access-everyone-models`, `access-bulk-assign`.
Base: TrustGate `origin/develop` @ `30ce3c07`, app `origin/develop` @ `96debc67`.
Paths without a prefix are TrustGate; `app/` paths are in the console.

## TrustGate

### Technical Approach

Everyone is a fourth Store-access object next to grants and policies, built
the same way end to end: domain type, Postgres table with an outbox marker,
service with `signal()`, admin handler, snapshot field, data-plane reader.
Evaluation changes in exactly two places: the grant `Set` (all grant decisions
already go through it) and the mode resolver.

### Architecture Decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| T1 | `Set` becomes Everyone-aware: `Index(grants).WithEveryone(everyone, policies)`; `CodeAllows`, `InstanceAllows`, `AnyInstanceAllows` keep their signatures and also answer true for an Everyone grant when the groups reach it | Expand the caller's groups with a reserved key at each call site; a reserved key inside `store_grants` | Decision calls stay untouched; only the loading lines change. Every site passes `StoreGroups()` (no `Groups()` call in `pkg/app/store` or `store_tool.go`), so a group key reaches Everyone through its own group only. A reserved key in `store_grants` would be stripped by console saves that PUT full lists. |
| T1b | One request-scoped loader `loadStoreAccess(ctx, gw)` reads grants, policies and Everyone once and returns `{Level(query), Set}`; sites that today call `ResolveMode` then `loadGrantSet` use it | Resolver and loader each read what they need | Today a curated decision reads policies (resolver) and grants (loader); with Everyone that would become five reads on the control plane. The bundle makes it three, one more than today, for scoper, connect, configure and search; the rarer install path keeps separate loads. On data planes all are in-memory snapshot reads. |
| T1c | The approver keeps a plain `Set` (no Everyone) | Everyone-aware approver | Approving must write an explicit grant; if Everyone already covers the server, the approval still records it, so removing it from Everyone later does not take away what an admin approved. |
| T2 | Reach lives in the domain: `(*Everyone).Reaches(groups, *PolicySet)` = some group not excluded and without an own `none` policy | Compute reach in the app layer | One rule for grants and mode; unit-testable without I/O. Needs `(*PolicySet).GroupMode(key)`. |
| T3 | Level rule is a domain function `ResolveLevel(policies, everyone, subject, groups, fallback)`; `modeResolver.Resolve` calls it | Patch `PolicySet.Mode` | `Mode` returns `""` to mean "fall back"; the new rule needs the fallback inside `max`. Keeping `Mode` unchanged keeps its tests and callers. |
| T4 | Read failures: policies → curated (unchanged) and Everyone unreachable; Everyone → treated as absent and logged | Fail the request | Everyone only adds, so ignoring it never widens access; reach needs the policies, so without them it fails closed. |
| T5 | Snapshot: `repeated StoreEveryone store_everyone = 18`, `bytes json = 1`, like grants and policies | A JSON field inside the gateway | Same codec path; an old data plane ignores the unknown field, which is the documented hybrid risk. |
| T6 | `PUT …/store/everyone` with an empty body deletes; `curated` without grants and `none` → 422 (`ErrValidation`) | Separate `DELETE` | Mirrors `PUT access-policies` with empty mode. |
| T7 | Grant validation reuses the grant service's catalog/registry checks; registry deletion also prunes Everyone's instance grants, as a dependent cleaner next to the grants one (`pkg/app/registry/deleter.go:42-60`) | Accept any code | Same guarantees as grants (`pkg/app/store/grants.go:76-103`), and a deleted registry cannot leave Everyone invalid. |
| T8 | `store_everyone.gateway_id` references `gateways(id) ON DELETE CASCADE`, like `store_access_policies` | No FK | Same lifecycle as policies. |

### Data Flow

    console save ──PUT store/everyone──▶ EveryoneService ──▶ store_everyone (+outbox)
                                              │ signal()
                                              ▼
                              configsnapshot compiler ──▶ DP snapshot reader
                                                               │
    request ─▶ ResolveMode(policies, everyone) ─▶ level        │
            └▶ loadStoreAccess(grants, policies, everyone) ─▶ Set.WithEveryone ─▶ decisions

### File Changes

| File | Action | Description |
|---|---|---|
| `pkg/domain/storeaccess/everyone.go` (+ test) | Create | `Everyone`, `EveryoneGrant`, validation, `Reaches`, `ResolveLevel`, `EveryoneReader`, `EveryoneRepository` |
| `pkg/domain/storeaccess/policy.go` | Modify | `GroupMode(key)` |
| `pkg/domain/storeaccess/grant.go` | Modify | `WithEveryone`; three `*Allows` methods consult it |
| `pkg/infra/database/migrations/2026110…_add_store_everyone.go` | Create | `store_everyone(gateway_id PK, mode, grants jsonb, excluded_groups jsonb, timestamps)` |
| `pkg/infra/repository/storeaccess/everyone_repository.go` | Create | upsert / delete / get / bulk list with outbox marker |
| `pkg/app/store/everyone.go` (+ test) | Create | `EveryoneService.Get/Set`, validation via grant checks, `signal()` |
| `pkg/app/store/mode.go` | Modify | resolver takes an `EveryoneReader`; `Resolve` uses `ResolveLevel` |
| `pkg/app/store/installer.go`, `scoper.go`, `principal_connect.go`, `principal_configure.go`, `pkg/app/mcp/store_tool.go` | Modify | `loadStoreAccess` bundle (T1b); approver keeps `loadGrantSet` (T1c) |
| `pkg/app/registry/deleter.go`, `pkg/container/modules/*` | Modify | Everyone dependent cleaner (T7) |
| `pkg/api/handler/http/store/everyone_handler.go`, `request/dto.go` | Create/Modify | `GET|PUT /v1/gateways/:gateway_id/store/everyone`, swagger |
| `pkg/server/router/admin_router.go` | Modify | routes under the existing `RequireGatewayAccess(ResourceRegistries)` group |
| `pkg/container/modules/store.go`, `mcp.go`, `core_data.go`, `control_config_sync.go`, `server_admin.go` | Modify | wiring (CP repository, DP snapshot reader) |
| `pkg/infra/configsnapshot/proto/snapshot.proto`, `codec.go`, `pkg/app/configsnapshot/compiler.go`, `pkg/runtimeconfig/snapshot/readmodel/snapshot.go`, `adapters/store_grant_reader.go` | Modify | field 18 end to end; adapter also implements `EveryoneReader` |
| `docs/*` | Regenerate | `make docs`, in its own commit |

### Interfaces

```go
type Everyone struct {
    GatewayID      ids.GatewayID
    Mode           string          // open | curated
    Grants         []EveryoneGrant // code-level when RegistryID is nil
    ExcludedGroups []string
    CreatedAt, UpdatedAt time.Time
}

type EveryoneGrant struct {
    CatalogCode string
    RegistryID  ids.RegistryID
}

type EveryoneReader interface {
    GetEveryone(ctx context.Context, gatewayID ids.GatewayID) (*Everyone, error) // nil, nil when absent
}

func (e *Everyone) Reaches(groups []string, policies *PolicySet) bool
func ResolveLevel(p *PolicySet, e *Everyone, subject string, groups []string, fallback string) string
func (s *Set) WithEveryone(e *Everyone, policies *PolicySet) *Set
```

Wire: `{"mode":"curated","grants":[{"catalog_code":"github"},{"catalog_code":"snowflake","registry_id":"…"}],"excluded_groups":["Contractors"]}`.

### Testing

| Layer | What | How |
|---|---|---|
| Unit (domain) | `Reaches`, `ResolveLevel` truth table (own / group / fallback × reached / not), `Set` with and without Everyone | table tests; "no Everyone = old result" for every row |
| Unit (app) | service validation (`none`, `curated` without grants, bad registry), loaders, resolver failure modes | fakes for readers |
| Handler | GET/PUT/delete, 422s | `httptest`, like `policies_handler_test.go` |
| Snapshot | codec round trip with field 18; compiler bulk + per-gateway | existing codec/compiler tests |
| Functional | group key of excluded group, external-IdP-like token, DB-less DP install without approval | `tests/functional`, `-tags functional` (`go vet -tags functional` before push) |

## Console (app)

### Technical Approach

Models Everyone is the existing `ALL` row plus an exclusion list. One pure
module owns the rule "does group G pass Everyone / is G key-eligible" and every
site that decides eligibility calls it. A new `AccessEveryone` record holds the
MCP part, the exclusions and the push state; saving it writes Prisma first and
then the gateway. Bulk actions are server actions that compute a plan purely,
then execute it.

### Architecture Decisions

| # | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| C1 | `AccessEveryone` (one per team + gateway) and `AccessEveryoneExclusion(everyoneId, groupId)` with `onDelete: Cascade` on the group | `excludedGroupIds String[]` | A deleted group leaves no dangling id; joins stay typed. |
| C2 | Pure module `llm-store/lib/llmStoreEveryone.ts`: `passesEveryone`, `eligibleGroupIds(rows, { groupIds, excluded })`, `groupsLosingEligibility(before, after)` | Inline checks per site | Spec requires one rule everywhere; tests stay pure. |
| C3 | Planner: group key → `[own row if ALL/SELECTED, ALL row if passes]`; legacy keys add the `ALL` row only when the owner has a passing group; personal keys never | A synthetic row per group; a new `EVERYONE` scope | Decided in proposal: the `ALL` row already has a consumer at level `all`. |
| C4 | `setLlmStoreAccessAction` refuses `scope: 'ALL'` (`llmStoreAccessInput.ts:53`); only `saveEveryoneAccessAction` writes it | Gate server logic on the team flag | Decided: the flag only hides the UI. |
| C5 | Push = `pushEveryoneMcp(teamId, gatewayId)`: drop items whose catalog code or registry no longer exists, map exclusion ids → `groupGrantKey`, PUT or DELETE `store/everyone` through `agentGatewayRequest({ teamId, userId: system actor })`, store `mcpAppliedHash` / `mcpError` | Push inside the Models reconcile | The reconcile returns early for hybrid gateways (`reconcileLlmStoreGateway.ts:328`) and when there are no access rows (`hasNothingToReconcile`, `:266-270`); MCP Everyone must work in both cases, so the push runs outside them. Dropping stale items keeps one deleted server from blocking every later push. |
| C6 | Re-push trigger: `reconcileTeam` (`scheduleLlmStoreReconcile.ts:15-63`) also calls `pushEveryoneMcp` for every team gateway that has an `AccessEveryone`, hybrid included, skipping when the hash is unchanged; so does the boot sweep (`reconcileAllLlmStoreGateways.ts`), which today walks SaaS gateways only. Renames that do not schedule the reconcile today get it: the Entra sync without membership changes (`syncEntraDirectoryGroups.ts:335`) and the mapped-group cache upsert when `displayName` changes (`sso/failedGroupMembershipCache.ts:250-268`) | A dedicated job | Every other group write path already schedules this reconcile (SCIM, Okta, Google, NT create/delete). The boot sweep makes a push lost to a restart during the debounce converge. NT groups are keyed `nt:<uuid>`, so only groups without `externalId` change key on rename. |
| C10 | Model access approvals compute the user's base without the `ALL` row (`llmStoreAccessRequestActions.ts:201-213` → `planLlmStoreApprovalAccess`) | Keep the default as inherited | An approval writes the user's own row for the personal key, which never receives Everyone; counting the `ALL` row would mark the request satisfied while the key still lacks the models. |
| C7 | Bulk = pure planners (`planBulkModels`, `planBulkMcp`) + executors; Models in one `$transaction` then one reconcile; MCP reads policies and grants fresh, writes one policy per changed group and one grant per changed server | Loop over the existing per-group actions | Per-server writes (M, not N × M) and per-group, per-section results. |
| C8 | Contract by `DirectoryGroup.id` (`excludedGroupIds`, `groupIds`); ids → keys on the server | Keys from the browser | Key → id is ambiguous (`displayName` not unique). |
| C9 | Confirmation reuses `LLM_STORE_KEY_REVOCATION_CONFIRMATION_ERROR` with `{ keys, groups }`; bulk also returns narrowed groups | A new error per case | One client path. |

### Data Flow

    Manage Everyone ─▶ saveEveryoneAccessAction
        ├─ eligibility before/after ─▶ confirm needed? ─▶ refuse with counts
        ├─ $transaction: AccessEveryone + exclusions + ALL row
        ├─ revoke confirmed keys (audit each)
        ├─ pushEveryoneMcp ─▶ TrustGate store/everyone ─▶ mcpAppliedHash | mcpError
        └─ scheduleLlmStoreReconcile ─▶ planner links group keys to llm-store:all

### File Changes

| File | Action | Description |
|---|---|---|
| `prisma/schema.prisma`, `prisma/migrations/2026110…_access_everyone/` | Create/Modify | `AccessEveryone`, `AccessEveryoneExclusion` |
| `llm-store/lib/llmStoreEveryone.ts` (+ tests) | Create | the shared rule (C2) |
| `llm-store/lib/planLlmStoreReconcile.ts` | Modify | input `everyoneExcludedGroupIds`; `desiredRowsForKey`, `desiredRowsForOwner`, `reachableRowsForOwner` |
| `llm-store/lib/reconcileLlmStoreGateway.ts` | Modify | load exclusions into the plan input |
| `llm-store/lib/llmStoreKeys.ts`, `revokeIneligibleKeys.ts`, `llmStoreKeyOptions.ts`, `llmStoreEffectiveModels.ts`, `llmStoreReach.ts`, `llmStoreInheritance.ts` | Modify | call the shared rule |
| `llm-store/actions/llmStoreAccessActions.ts`, `llmStoreGroupLimitsActions.ts`, `llmStoreAccessInput.ts`, `analytics/actions/getAnalyticsKeyCostAction.ts`, `portal/actions/getPortalModelsAction.ts` | Modify | shared rule; refuse `ALL` scope; `groupLosesModels` via before/after |
| `access/actions/everyoneActions.ts` | Create | `getEveryoneAccessAction`, `saveEveryoneAccessAction` |
| `access/lib/everyoneGateway.ts` | Create | `pushEveryoneMcp` |
| `llm-store/lib/scheduleLlmStoreReconcile.ts`, `reconcileAllLlmStoreGateways.ts`, `server/lib/directoryGroups/syncEntraDirectoryGroups.ts`, `server/lib/sso/failedGroupMembershipCache.ts` | Modify | re-push triggers and boot sweep (C6) |
| `llm-store/actions/llmStoreAccessRequestActions.ts` | Modify | approval base without the `ALL` row (C10) |
| `access/hooks/useLlmStoreAccessDraft.ts`, `access/components/GroupAccessSidePanel.tsx`, `LlmStoreAccessSection.tsx` | Modify | client copies of the eligibility rule (key dialog, "can have keys") |
| `access/actions/groupBulkActions.ts`, `access/lib/groupBulkPlan.ts` (+ tests) | Create | bulk Assign / Remove (C7) |
| `access/actions/updateResourceAccessAction.ts`, `storeAccessPolicyActions.ts` | Modify | audit `mcp_store_grant.updated`, `mcp_store_access_policy.updated` |
| `app/constants/audit.ts` | Modify | three new events |
| `lib/reads/v2Readers.ts`, `app/api/teams/[teamId]/reads/[reader]/route.ts` | Modify | `everyone-access` reader |
| `access/types.ts`, `access/hooks/useEveryoneAccess.ts`, `useGroupBulkAssign.ts`, mocks, flag | Modify/Delete | front wiring, on the front branch, last |

### Interfaces

```ts
type EveryoneSave = {
  teamId: string; gatewayId: string
  mcpMode: 'all' | 'selected'; mcps: EveryoneMcp[]           // selected + [] removes the MCP object
  modelsMode: 'all' | 'selected' | 'none'; models: LlmStoreRegistrySelection[]
  excludedGroupIds: string[]
  confirmKeyRevocation?: boolean
}
type EveryoneView = EveryoneSave & { mcpApplied: boolean; mcpError?: string; hybrid: boolean }

type BulkSectionResult = 'applied' | 'skipped' | 'failed'
type BulkResult = { groups: { groupId: string; mcp?: BulkSectionResult; models?: BulkSectionResult; error?: string }[] }
```

### Testing

| Layer | What | How |
|---|---|---|
| Pure | planner: no `ALL` row = today's plan (existing fixtures unchanged), Everyone-only group, excluded, own NONE, legacy reach, personal keys | vitest, `planLlmStoreReconcile.test.ts` fixtures |
| Pure | shared rule; bulk planners (Assign table, narrowing, Remove of last item, skips) | vitest |
| Action | save: confirm counts, hybrid refusal of Models, push failure leaves `mcpApplied=false`; bulk partial failure; `ALL` refused by generic write | vitest with mocked gateway client and Prisma |
| Manual / local | full flow against a local TrustGate | recipe in memory "Local console QA" |

## Migration / Rollout

One PR per repo (see `tasks.md`):

1. TrustGate PR → `develop` → DEV; promote to production EU and US.
2. App PR (shared rule, planner, Everyone save and push, audit, bulk) → `develop` once TrustGate runs in DEV; promote after TrustGate is in production. With no `ALL` rows and no Everyone records, nothing changes until the flagged UI is used. Against an older TrustGate the push reports "not applied".
3. Front wiring on the front branch; flag on per team; flag removed later.

Rollback: see `proposal.md` (clear Everyone through the confirmation before rolling back code).

## Open Questions

- [ ] Minimum TrustGate version for the hybrid warning: set at release; if Topology heartbeats expose the data-plane version, show the warning only for older planes.
- [ ] PR slicing (TrustGate likely two chained PRs: storage/API, then evaluation/snapshot): decided in `tasks.md`.
