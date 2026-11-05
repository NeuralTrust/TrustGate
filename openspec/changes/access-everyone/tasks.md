# Tasks: Everyone and bulk Assign / Remove on Access › Groups

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1,400 TrustGate (+ regenerated docs) · ~2,600 app |
| 400-line budget risk | High |
| Chained PRs recommended | No — owner chose one PR per repo |
| Suggested split | PR TrustGate → PR app; front wiring is a third PR on the front branch (pending coordination) |
| Delivery strategy | exception-ok |
| Chain strategy | size-exception |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: High

Each PR carries the `size:exception` label and is built as reviewable commits,
one per work unit below. `make docs` goes in its own commit.

### Starting point and gates

- TrustGate: this branch (`feat/eng-3054-access-everyone`, from `origin/develop`); first commit = this openspec folder. Public repo: neutral PR text, no customer names or production numbers.
- App: new worktree from `origin/develop` on `feat/eng-3054-access-everyone`; never the detached front-branch checkout.
- The app PR merges to `develop` only after TrustGate `store/everyone` runs in DEV.
- The app promote to `main` waits for TrustGate in production EU and US. Both promotes need the owner's approval.
- Phase 8 (front branch) is pending coordination with the front-branch author: they wire it, or they agree to a rebase, or a new branch is cut from theirs.

### Suggested Work Units

| Unit | Goal | PR | Notes |
|------|------|----|-------|
| T1 | `store/everyone` storage + admin API | TrustGate | base `develop`; unit + handler tests |
| T2 | Evaluation: level rule, Everyone-aware `Set`, loaders | TrustGate | unit tests incl. "no Everyone = today" |
| T3 | Snapshot field + DP reader + registry cleaner | TrustGate | codec/compiler tests, functional |
| A1 | Prisma + shared rule + planner + every eligibility site | app | base `develop`; pure tests; no visible change |
| A2 | Everyone save, push, triggers, boot sweep, reader | app | needs TrustGate deployed to exercise the push |
| A3 | MCP audit events on existing writes | app | independent |
| A4 | Bulk Assign / Remove | app | needs A1 |
| F | Front wiring, flag removal | front branch | after the app PR merges |

## Phase 1 (TrustGate · T1): storage and API

- [x] 1.1 Create `pkg/domain/storeaccess/everyone.go`: `Everyone`, `EveryoneGrant`, `Validate()` (mode `open|curated`, `curated` needs grants, groups trimmed and de-duplicated), `EveryoneReader`, `EveryoneRepository` with `go:generate` mockery.
- [x] 1.2 Add `(*PolicySet).GroupMode(key) (string, bool)` in `policy.go`.
- [x] 1.3 Create migration `pkg/infra/database/migrations/2026110…_add_store_everyone.go`: `store_everyone(gateway_id UUID PK REFERENCES gateways(id) ON DELETE CASCADE, mode TEXT, grants JSONB, excluded_groups JSONB, created_at, updated_at)`.
- [x] 1.4 Create `pkg/infra/repository/storeaccess/everyone_repository.go`: `GetEveryone`, `UpsertEveryone`, `DeleteEveryone`, `ListEveryone(page,size)`, each write through `withMarkedTx`.
- [x] 1.5 Create `pkg/app/store/everyone.go`: `EveryoneService.Get/Set` (empty → delete), grant checks shared with `grants.go:76-103`, `signal()`.
- [x] 1.6 Create `pkg/api/handler/http/store/everyone_handler.go` + `request.SetEveryone` DTO + swagger; routes `GET|PUT /v1/gateways/:gateway_id/store/everyone` in `admin_router.go`; wiring in `modules/store.go`, `server_admin.go`.
- [x] 1.7 Tests: `everyone_test.go` (validation table), `pkg/app/store/everyone_test.go` (set, delete, 422s, signal), `everyone_handler_test.go`.

## Phase 2 (TrustGate · T2): evaluation

- [ ] 2.1 `everyone.go`: `(*Everyone).Reaches(groups, *PolicySet)` and `ResolveLevel(p, e, subject, groups, fallback)`.
- [ ] 2.2 `grant.go`: `(*Set).WithEveryone(e, policies)`; `CodeAllows`, `InstanceAllows`, `AnyInstanceAllows` consult it.
- [ ] 2.3 `mode.go`: resolver takes an `EveryoneReader`; `Resolve` uses `ResolveLevel`; policy failure → curated and Everyone unreachable; Everyone failure → absent + warn.
- [ ] 2.4 Add `loadStoreAccess(ctx, gw)` returning `{Level(query), Set}` (one read each of grants, policies, Everyone); use it in `scoper.go`, `principal_connect.go`, `principal_configure.go`, `store_tool.go` search; the install path (`store_tool` mode + `installer.grantSet`) may keep two loads; approver keeps `loadGrantSet`.
- [ ] 2.5 Wire the `EveryoneReader` into every `NewModeResolver` and loader (`store.go:214,226,240`, `mcp.go:400,517`). `mcp.go` runs on the data plane too, whose reader only arrives in 3.3: make the dependency optional or land 2.5 with 3.3, then run `pkg/container` tests for both planes.
- [ ] 2.6 Tests: `ResolveLevel` truth table (own / explicit group / fallback × reached / not reached / no Everyone); `Reaches` (excluded + passing, group key, group on `none`, no groups); `Set` with and without Everyone (code, instance, any-instance); installer under `curated` installs an Everyone server without a pending request; existing `mode_resolver_test.go` unchanged and green.

## Phase 3 (TrustGate · T3): data planes and cleanup

- [ ] 3.1 `snapshot.proto` field 18 `repeated StoreEveryone store_everyone`; regenerate; `codec.go` encode/decode.
- [ ] 3.2 `compiler.go`: `WithStoreEveryone`, bulk list + per-gateway read, `appendGatewayData`; `control_config_sync.go` wiring.
- [ ] 3.3 `readmodel/snapshot.go` + `adapters/store_grant_reader.go` implement `EveryoneReader`; wire in `core_data.go`.
- [ ] 3.4 Registry deletion: Everyone dependent cleaner that drops instance grants of the deleted registry (`registry/deleter.go`), wired next to the grants cleaner; when the result is `curated` with no grants it deletes the object (an upsert would be refused).
- [ ] 3.5 Tests: codec round trip, compiler bulk/per-gateway, adapter on unloaded snapshot (= no Everyone), cleaner.
- [ ] 3.6 Functional (`-tags functional`): DB-less DP — group key of an excluded group, user in excluded + passing group, install without approval; `go vet -tags functional ./...`.
- [ ] 3.7 `make docs` in its own commit; `make test`; clean-comments on touched Go (check it keeps doc comments).

## Phase 4 (app · A1): shared rule and planner

- [ ] 4.1 Prisma: `AccessEveryone` (team, gateway, `mcpMode`, `mcpItems Json`, `mcpAppliedHash?`, `mcpAppliedAt?`, `mcpError?`, `updatedById?`, timestamps, `@@unique([teamId, gatewayId])`) and `AccessEveryoneExclusion(everyoneId, groupId)` with cascades; migration folder; `npx prisma validate`.
- [ ] 4.2 Create `llm-store/lib/llmStoreEveryone.ts`: `passesEveryone`, `eligibleGroupIds(rows, { groupIds, excluded })`, `groupsLosingEligibility(before, after)`; store helper to read exclusions.
- [ ] 4.3 Planner: input `everyoneExcludedGroupIds` + group ids; `desiredRowsForKey` (group key → own row and `ALL` row when passing; personal keys never), `desiredRowsForOwner` (legacy reach rule), `reachableRowsForOwner`; `reconcileLlmStoreGateway.ts` loads them.
- [ ] 4.4 Switch every eligibility site to the shared rule: `llmStoreKeys.ts`, `revokeIneligibleKeys.ts` (snapshot + `stillIneligible`), `llmStoreKeyOptions.ts`, `llmStoreEffectiveModels.ts`, `llmStoreReach.ts`, `llmStoreInheritance.ts`, `llmStoreGroupLimitsActions.ts`, `getAnalyticsKeyCostAction.ts`, `getPortalModelsAction.ts`, `llmStoreAccessActions.ts` (key counts, admin key creation, `groupLosesModels` via before/after).
- [ ] 4.5 Client copies: `useLlmStoreAccessDraft.ts`, `GroupAccessSidePanel.tsx`, `LlmStoreAccessSection.tsx`.
- [ ] 4.6 `llmStoreAccessInput.ts`: the generic write refuses `scope: 'ALL'`, set and clear alike. No script or seed writes it; `llmStoreAccessActions.test.ts` (lines ~73-456) and `access/llmStoreModels.test.ts:124` use it and move to `GROUP` or assert the refusal.
- [ ] 4.7 Approvals: `llmStoreAccessRequestActions.ts` computes the base without the `ALL` row.
- [ ] 4.8 Tests without an `ALL` row (planner, keys, sweep, inheritance) pass with no edits: that is the invariance spec.
- [ ] 4.9 Tests that use `allRow` / `defaultRow` (planner `legacy key links` block and group-key cases, `llmStoreInheritance` user cases) change on purpose: list each by name with old → new expectation in the PR description, per `access-everyone-models`.
- [ ] 4.10 New cases: Everyone-only group linked and eligible, excluded, own NONE, union with own row, legacy user in no group, personal key never linked; sweep keeps Everyone-only keys; generic `ALL` write refused; approval base.

## Phase 5 (app · A2): Everyone save and push

- [ ] 5.1 Create `access/lib/everyoneGateway.ts` `pushEveryoneMcp(teamId, gatewayId)`: drop stale items, map ids → `groupGrantKey`, PUT/DELETE with the system actor, store hash / error.
- [ ] 5.2 Create `access/actions/everyoneActions.ts`: `getEveryoneAccessAction` (READ_ONLY, `mcpApplied`, `hybrid`), `saveEveryoneAccessAction` (ADMIN, zod, gateway match, revocation confirm with counts, one `$transaction` for Everyone + exclusions + `ALL` row, revoke + audit keys, push, `scheduleLlmStoreReconcile`, `access_everyone.updated`; hybrid refuses Models).
- [ ] 5.3 Triggers: `reconcileTeam` pushes for every gateway with `AccessEveryone` (hybrid included, outside the per-gateway early returns); boot sweep does the same; Entra rename and `failedGroupMembershipCache` rename schedule the reconcile.
- [ ] 5.4 Reader `everyone-access` in `v2Readers.ts` and the reads route.
- [ ] 5.5 Tests: save confirm counts, hybrid refusal, push failure → `mcpApplied=false` then retry converges, a 404 / unknown route from an older TrustGate → not applied (no throw), stale item dropped, rename re-push, hash skip.

## Phase 6 (app · A3): MCP audit

- [ ] 6.1 `app/constants/audit.ts`: `MCP_STORE_GRANT_UPDATED`, `MCP_STORE_ACCESS_POLICY_UPDATED`, `ACCESS_EVERYONE_UPDATED`.
- [ ] 6.2 Log them from `updateResourceAccessAction.ts` and `setStoreAccessPolicyAction` with before → after metadata and readable descriptions.
- [ ] 6.3 Tests for both actions.

## Phase 7 (app · A4): bulk Assign / Remove

- [ ] 7.1 Create `access/lib/groupBulkPlan.ts`: `planBulkModels`, `planBulkMcp` (Assign table, narrowing detection, Remove with skips and last-item rule).
- [ ] 7.2 Create `access/actions/groupBulkActions.ts`: `bulkAssignGroupAccessAction`, `bulkRemoveGroupAccessAction` (ADMIN, zod by group id, confirmation for narrowing / None / Replace / Remove / key revocation, Models in one `$transaction` + one reconcile, MCP fresh read + per-group policy and per-server grant writes, per-group per-section results, audit per group).
- [ ] 7.3 Tests: planner tables; partial MCP failure with Models applied; retry converges; narrowing refused without confirm.
- [ ] 7.4 `npm run lint`, `npm run build:local`, vitest; local QA against a local TrustGate (recipe "Local console QA").

## Phase 8 (front branch · F): wiring

- [ ] 8.1 Rebase the front branch on `develop`; switch types to group ids; hooks call the new actions and reader; show `mcpApplied` and the hybrid warning; remove mocks.
- [ ] 8.2 Remove `ACCESS_EVERYONE_ENABLED` once QA in DEV passes.
- [ ] 8.3 Follow-up issue: Playwright scenarios in `e2e-tests`.
