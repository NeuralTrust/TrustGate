# Tasks: MCP-wide placement for group-scoped policies (RUN-1746)

Inputs: `proposal.md` (binding), `design.md` (D1–D13 and the app matrix), `exploration.md`, Linear RUN-1746. TrustGate paths start at the repo root. App paths: `$P` = `app/[locale]/v2/features/policies`, `$T` = `__tests__/v2/policies`. Spec deltas go in `openspec/changes/mcp-wide-group-policies/specs/<capability>/spec.md`, written in Spanish like `openspec/specs/*`.

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | Hand-written ≈1,770: TrustGate ≈1,110 (T1 295, T2 255, T3 255, T4 305) and app ≈660 (A1 365, A2 295). Generated ≈710: swagger/openapi ≈540 in T4, mocks ≈170. openspec deltas ≈170, outside the budget. |
| 400-line budget risk | High in total. Every slice is ≤ ≈305 hand-written lines. |
| Chained PRs recommended | Yes |
| Suggested split | TrustGate T1 → T2 → T3 → T4. App A1 runs in parallel with T1, then A2, which deploys after T4. |
| Delivery strategy | ask-on-risk |
| Chain strategy | single-pr per repo with `size:exception` (decided by Edu, 2026-10-01). One commit per slice on the existing branch. |

Decision needed before apply: No (resolved: one PR per repo, `size:exception`)
Chained PRs recommended: Yes
Chain strategy: single-pr
400-line budget risk: High

How to measure the budget (this excludes openspec/ and generated files, as ENG-1618 did):
- TrustGate: `git diff --shortstat <parent> -- pkg tests docs ':!docs/swagger.*' ':!docs/docs.go' ':!docs/openapi.json' ':!**/mocks/**'`
- app: `git diff --shortstat <parent> -- app __tests__ messages`

### Test trims against the design (≈851 → ≈685 lines)

- `level_guard_test.go`, 75 → 45. Dropped the guard cases for MCP-wide × global and for disjoint groups: the guard only intersects `Occupancy()`, and T1.8 already proves those. Kept: refused by an overlapping occupant, swap guarded once, unset not guarded.
- `scoper_test.go`, 150 → 110. One transition table replaces a function per case.
- Functional, 170 → 130. The 422, 409-against-global and disjoint cases stay at unit level (T1.8, T3.6). Kept: admin read-back, no orphan warning, the 409 wording, and runtime member / non-member / draft.
- Domain 75 → 60, warnings 75 → 60, repository integration 90 → 85.

### Suggested Work Units

| Unit | Repo | Goal | Branch | PR base | Hand / gen |
|------|------|------|--------|---------|------------|
| T1 | TrustGate | Storage: column + CHECK, domain field and predicates, setters; `Update` stops writing `global` | `fix/run-1746-mcp-wide-group-policies` (exists) | `develop` | ≈295 / ≈55 |
| T2 | TrustGate | Runtime: load path, plugin state, associator, warnings | same branch (commit) | `develop` | ≈255 / 0 |
| T3 | TrustGate | Use case: `SetMCPWide`/`UnsetMCPWide`, 422, PUT slug guard | same branch (commit) | `develop` | ≈255 / ≈115 |
| T4 | TrustGate | HTTP `/mcp-wide`, `mcp_wide` field, OpenAPI, functional tests, docs | same branch (commit) | `develop` | ≈305 / ≈540 |
| A1 | app | Engine: 3-placement sync, placement-tagged errors, `previousScope`, post-promotion create. No UI change. | `fix/run-1746-mcp-wide-group-policies` (exists) | `develop` | ≈365 / 0 |
| A2 | app | *Groups* promotes MCP-wide: validation, read-back, level mirror, copy | same branch (commit) | `develop` | ≈295 / 0 |

Why each slice ships on its own:
- Nothing can set `mcp_wide` before T4 exists. D5 in T1 only closes a lost update: a PUT racing `POST|DELETE /global` now gets a 409 instead of undoing it.
- A1 never produces `'mcp-wide'`, because `policyScopeOf` does not change there.
- A2 merges only after T4 is deployed and R.1 has run.

PR rules:
- Titles are bare, e.g. `fix: … (RUN-1746)`.
- Bodies include the Chain Context section.
- Two PRs, one per repo, both labelled `size:exception`. The app PR carries `Fixes RUN-1746`; the TrustGate PR says `Part of RUN-1746`. The app PR merges only after the TrustGate PR is deployed and R.1 has run.

### Verification blocks

- **VG** (every TrustGate slice):
  - `go build ./...`, `go vet ./...`, `make lint` and `make test-race` (the hook runs `make test`).
  - `go vet -tags functional ./tests/...` when `tests/` changes.
  - Run clean-comments on the touched Go files. Swagger annotations stay.
  - Wait for the CI `functional-tests` check.
  - Run generators with `PATH="$HOME/go/bin:$PATH"`.
- **VR** (repository tests): CI runs them with `PG_TEST_URL`. To run them locally, use a disposable container only:
  1. `docker run -d --rm --name run1746-pg -p 55446:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine`
  2. `PG_TEST_URL='postgres://postgres:postgres@localhost:55446/postgres?sslmode=disable' make test-repositories`
- **VA** (every app slice): `npx vitest run <slice tests>`, `npm run lint`, `npm run typecheck`, `npm run test:unit`, then `npm run build:local` before pushing.

## Phase T1: Storage (TrustGate, base `develop`)

- [x] T1.1 Create `pkg/infra/database/migrations/20261001120000_add_policy_mcp_wide.go`: column `mcp_wide` plus `policies_global_mcp_wide_check`, idempotent up and down.
- [x] T1.2 `pkg/domain/policy/policy.go`: add `MCPWide` (`mcp_wide,omitempty`), `GatewayWide()` and the `SetGlobal`/`SetMCPWide` mutators. `Validate` returns `ErrInvalidPlacement` (new, in `errors.go`) when both flags are set.
- [x] T1.3 `pkg/domain/policy/level.go`: `Occupancy` uses `GatewayWide()`. `Draft` also requires `!MCPWide`. Update the doc comments.
- [x] T1.4 `pkg/domain/policy/repository.go`: add the `SetMCPWide` port and update the `SetGlobal` doc. Run `go generate ./pkg/domain/policy/...`.
- [x] T1.5 `pkg/infra/repository/policy/repository.go`: `mcp_wide` in select, scan and Save. `Update` drops `global` and compares both flags, answering `ErrPlacementChanged` (409) when they moved (D5). `SetGlobal` and the new `SetMCPWide` use the relative SQL from the design. `mapPgError` maps the CHECK's 23514 to `ErrInvalidPlacement`.
- [x] T1.6 `pkg/infra/repository/policy/level_lock.go`: read and scan `p.mcp_wide`.
- [x] T1.7 `pkg/runtimeconfig/snapshot/adapters/policy_repository.go`: `SetMCPWide` returns `ErrReadOnly`.
- [x] T1.8 Test `pkg/domain/policy/{level,policy}_test.go`:
  - MCP-wide occupies `(all,G,d)` and ignores its links.
  - It overlaps a global of the same groups.
  - `Draft` is false for it.
  - The mutators clear the other flag; both flags set → `ErrInvalidPlacement`.
- [x] T1.9 Test `tests/functional/repositories/policy/repository_test.go`:
  - The swap works in both directions.
  - A demotion keeps the other flag.
  - Setting both flags in raw SQL → 23514.
  - A stale `Update` fails with `ErrPlacementChanged` and writes nothing; one whose flags still match lands.
- [x] T1.10 Test `tests/functional/repositories/policy/level_lock_test.go`: a locked MCP-wide occupant has `MCPWide` set and a non-empty `Occupancy()`.
- [x] T1.11 Test `pkg/infra/configsnapshot/codec_test.go`: `mcp_wide` round-trips and is absent when false. Test `pkg/runtimeconfig/snapshot/adapters/adapters_test.go`: `SetMCPWide` is read-only.
- [x] T1.12 Run VG and VR. Commit the change folder as a separate `docs` commit (decision 2).

## Phase T2: Runtime (TrustGate, base T1)

- [ ] T2.1 `pkg/app/consumer/data_finder.go`: `loadPolicies` returns `{everywhere, onMCP, byConsumer}` and skips links for `GatewayWide()`. MCP consumers and `StoreConsumer` read `onMCP`; LLM and A2A read `everywhere`.
- [ ] T2.2 `pkg/app/plugins/plan.go:90` and `chain.go:119` use `pol.GatewayWide()`. Update the `plugin.go:176` doc. `pkg/app/consumer/associator.go:190` uses `GatewayWide()`. Doc lines that name the global flag as the source of gateway-wide state say "gateway-wide placement (global or MCP-wide)": `pkg/app/plugins/catalog_metadata.go` (~:540 and ~:836, the informational `scope` field) and `pkg/infra/plugins/ratelimit/config.go:30`.
- [ ] T2.3 `pkg/app/policy/warnings.go`:
  - The orphan warning uses `p.Draft()`.
  - `reach` drops non-MCP consumers for MCP-wide.
  - Add `sameSlugRuns.mcpWide` and `reaches(reachedConsumer)`.
- [ ] T2.4 Test `pkg/app/consumer/data_finder_inert_test.go`: an inert-safe, group-only MCP-wide policy is absent from LLM/A2A `Policies` and `PolicyPlan`.
- [ ] T2.5 Test `pkg/app/consumer/data_finder_test.go`:
  - The policy is in every MCP consumer's `ScopedPolicies`.
  - Its links are ignored.
  - An attached unscoped policy of the same slug overrides it.
  - In `StoreConsumer.MCPPlans`, including an `InstanceOf` clone, a member matches and a non-member does not.
- [ ] T2.6 Test `pkg/app/policy/warnings_test.go`:
  - No "runs nowhere" warning for MCP-wide; a draft still gets it.
  - The api-key warning names MCP consumers only.
  - A same-slug MCP-wide policy collides on MCP consumers only.
- [ ] T2.7 Test `pkg/app/consumer/associator_test.go`: the protocol check is skipped. Test `pkg/app/plugins/executor_test.go`: `Scope.Global` is true for MCP-wide.
- [ ] T2.8 Spec deltas:
  - `specs/policy-inert-scope/spec.md`: a draft requires `mcp_wide=false`; ADD "MCP-wide nunca entra en una cadena LLM/A2A".
  - `specs/mcp-policy-plan-selection/spec.md`: the Store takes MCP-wide policies.
- [ ] T2.9 Run VG.

## Phase T3: Use case (TrustGate, base T2)

- [ ] T3.1 `pkg/domain/policy/errors.go`: add `ErrMCPWideUnsupported`, wrapping `ErrValidation`.
- [ ] T3.2 `pkg/app/policy/validate.go`: `pluginRunsOnMCP`, shared with `validateMCPScopePlugin`, and `validateMCPWidePlugin`.
- [ ] T3.3 `pkg/app/policy/scoper.go`:
  - Add `SetMCPWide`/`UnsetMCPWide` through a shared flag write.
  - `NewScoper` takes `appplugins.Registry`.
  - `setGlobal` uses `existing.SetGlobal(...)` and `promoted.SetGlobal(true)` instead of assigning the fields, so the cached copy drops `MCPWide` the way the row does.
  - Close the scoper's read-before-lock race, found in the T1 review. The sequence: the scoper reads a disabled draft and the guard skips the lock. A PUT `{enabled:true}` then commits, and `SetGlobal(true)` lands on the now-enabled row unchecked. The fix: make the promotion conditional on the row the guard read. Preferred: `SetGlobal`/`SetMCPWide` also match the read row's `updated_at`, and a mismatch returns `ErrPlacementChanged` (409). Taking the slug lock and re-reading inside it also works if it is cheaper. Add a repository test (stale promotion → `ErrPlacementChanged`, row unchanged) and a scoper table row.
  - Run `go generate ./pkg/app/policy/...`.
- [ ] T3.4 `pkg/app/policy/updater.go`: a slug change on an MCP-wide policy runs `validateMCPWidePlugin`.
- [ ] T3.5 `pkg/container/modules/policy.go`: wire the new `NewScoper` argument.
- [ ] T3.6 Test `pkg/app/policy/scoper_test.go` (table):
  - set, swap from global (`Global` cleared), no-op
  - foreign gateway → `ErrNotFound`
  - non-MCP plugin → 422 with no write
  - unset; `UnsetGlobal` on an MCP-wide policy is a no-op
- [ ] T3.7 Test `pkg/app/policy/level_guard_test.go`:
  - An overlapping MCP-wide occupant refuses `SetMCPWide` with `ErrPolicyLevelConflict`, and nothing is written.
  - The swap is guarded once.
  - `UnsetMCPWide` is not guarded.
- [ ] T3.8 Test `pkg/app/policy/updater_test.go`: a PUT that changes the slug to a non-MCP plugin → `ErrMCPWideUnsupported`, no write.
- [ ] T3.9 Spec delta `specs/policy-level-uniqueness/spec.md`:
  - MCP-wide takes the global cell.
  - `SetMCPWide` is guarded and `UnsetMCPWide` is not.
  - Add the 409 scenarios.
- [ ] T3.10 Run VG.

## Phase T4: HTTP, OpenAPI, docs (TrustGate, base T3)

- [ ] T4.1 Create `pkg/api/handler/http/policy/mcp_wide_policy_handler.go`: POST and DELETE with swagger annotations. POST also documents 409 and 422.
- [ ] T4.2 `pkg/api/handler/http/policy/response/policy_response.go`: `MCPWide` with tag `mcp_wide`, always present.
- [ ] T4.3 Swagger text: `global_policy_handler.go` (the swap) and `duplicate_policy_handler.go` ("neither global nor MCP-wide").
- [ ] T4.4 `pkg/server/router/admin_router.go` (field and 2 routes) and `pkg/container/modules/{policy,server_admin}.go`. `admin_router_wiring_test.go` must pass.
- [ ] T4.5 Run `make docs`. Test `docs/openapi_test.go`: the path, POST 409 and 422, DELETE, and `mcp_wide` in `PolicyResponse`.
- [ ] T4.6 `tests/functional/common_test.go`: add a `SetPolicyMCPWide` helper.
- [ ] T4.7 Test `tests/functional/mcp_wide_policy_test.go`, admin API:
  - POST returns `mcp_wide=true`, `global=false` and no orphan warning.
  - GET reads it back.
  - The `/global` swap works; DELETE is idempotent.
  - Overlapping groups → 409 with `already runs plugin`.
- [ ] T4.8 Same file, runtime (`tool_allowlist` deny-all for Finanzas):
  - Created but not promoted → Finanzas is echoed.
  - Promoted → Finanzas is blocked and Marketing is echoed.
  - An MCP consumer created afterwards is blocked too.
- [ ] T4.9 `docs/mcp-policy-scope.md`:
  - placement and level tables, the `:256` and `:259` rows, and an `mcp_wide` row
  - Admin API table
  - Rollout section. An old binary, or one rolled back, places an MCP-wide policy by its links alone: with none it runs nowhere; with links it runs on those consumers, as before the promotion. The console detaches links on promotion.
- [ ] T4.10 Spec delta `specs/mcp-policy-scope/spec.md`: the orphan warning applies to drafts only; 422. Create `specs/policy-mcp-wide-placement/spec.md`.
- [ ] T4.11 Run VG.

## Phase A1: Engine (app, base `develop`, parallel with T1)

- [x] A1.1 `$P/types.ts`: `mcp_wide?` and `'mcp-wide'` in `PolicyScope`. Also `$P/lib/policyContract.ts`, and `'mcp-wide'` → cyan in `$P/constants/policies.constants.ts`.
- [x] A1.2 `$P/lib/syncPolicyAssociations.ts`:
  - `writePlacementFlag` returns `PolicyResponse | null`.
  - Implement the 3×3 matrix from the design.
  - Moving into MCP-wide detaches every link.
- [x] A1.3 `$P/lib/policyWriteErrors.ts`: optional `placement` on `PolicyAssociationError`, plus `placementWriteFailureError`.
- [x] A1.4 `app/[locale]/v2/lib/agentGatewayErrorMessages.ts`: the three `POLICY_*MCP*` prefixes and their named variants, added to `isPolicyPartialWriteError`. Add the keys to `messages/en/v2Gateway.json`.
- [x] A1.5 `$P/actions/createPolicyAction.ts` returns `promoted ?? created`. `$P/actions/updatePolicyAction.ts` takes `previousScope`. `$P/hooks/usePolicyDraft.ts` passes `global ? 'gateway-wide' : 'targeted'`.
- [x] A1.6 Test `$T/syncPolicyAssociations.test.ts`:
  - five new rows, with exact `{endpoint, method}` sequences
  - `/mcp-wide` is retried and tagged; a 409 is not retried
  - the promoted item is returned; `:147` becomes `toBeNull`
- [x] A1.7 Test `$T/{createPolicyAction,updatePolicyAction}.test.ts` and `__tests__/v2/lib/agentGatewayErrorMessages.test.ts`: the cases listed in the design.
- [x] A1.8 Run VA.

## Phase A2: Groups promotes MCP-wide (app, base A1, deploy after T4)

- [ ] A2.1 `$P/lib/policyScopeOf.ts`:
  - `group` → `'mcp-wide'`.
  - Add `policyScopeOfItem`, `isPromotedPolicy` and `isRequestsFromIncomplete`.
  - `$P/hooks/usePolicyDraft.ts` passes `policyScopeOfItem(rawItem)`.
- [ ] A2.2 `$P/lib/policyMapper.ts` `requestsFromOf`: check `global`, then `mcp_wide`, then links, then groups. Update the doc comments at `:142-164`.
- [ ] A2.3 `$P/lib/policyLevelConflict.ts`: an MCP-wide placement uses consumer key `*`. A draft takes that cell only when its group choice is complete.
- [ ] A2.4 Groups validation:
  - `PolicyRequestsFromSection.tsx`: `showErrors` and the helper line; fix the "Users" doc.
  - `GroupMultiSelect.tsx`: `error?` prop.
  - Submit gate in `PolicyCreateSidePanel.tsx`, `PolicyDetailSidePanel.tsx` and `CreatePolicyModal.tsx`.
- [ ] A2.5 Copy:
  - security banner, `PolicyDeleteModal.tsx`
  - `listPoliciesAction.ts`, `policyCoverageLabel.ts`, `policyScopeSummary.ts`
  - `messages/en/v2Policies.json`
- [ ] A2.6 Auto-attach uses `isPromotedPolicy` in `features/consumers/components/ConsumerAddPolicyModal.tsx:134` and `features/applications/components/ApplicationPoliciesTab.tsx:298`.
- [ ] A2.7 Tests:
  - `$T/policyScopeOf.test.ts`: flip `:20-22`, keep `:30-33`.
  - `$T/policyLevelConflict.test.ts`: flip `:91-92`, keep `:30`; add overlap, disjoint, against global, and empty groups.
  - `$T/policyMapper.test.ts`.
- [ ] A2.8 Test `$T/{PolicyRequestsFromSection,PolicyCreateSidePanel,PolicyDetailSidePanel,CreatePolicyModal}.test.tsx`: *Groups* with nothing picked blocks the save and shows the error. Also `__tests__/v2/features/policies/{PolicyInstanceCard,policyScopeSummary}.test.*`.
- [ ] A2.9 Run VA.

## Phase R: Rollout (manual, per environment)

- [ ] R.1 After T1's migration is deployed and before A2 is deployed, run the proposal's query read-only on dev, prod and prod-us. Record the drafts and the promote decision on RUN-1746.
- [ ] R.2 Once T4 and A2 are on dev, check QA 1, 2 and 6 in the console:
  - an OAuth member and a non-member on an MCP consumer
  - the same on `/store/mcp`, with a shelf instance

## QA mapping

| QA item | Tasks | Manual / env only |
|---------|-------|-------------------|
| 1 *Groups* + G runs on MCP `tools/call` for members only | T2.5, T4.8, A1.6, A2.1 | R.2, console end to end |
| 2 Same on the Store, including a per-user shelf instance | T2.5 (`/store/mcp` has no functional harness) | R.2 |
| 3 Never in an LLM/A2A chain | T2.4, T2.7 | — |
| 4 No `runs nowhere` warning | T2.6, T4.7 | API only: the console never reads `warnings[]` |
| 5 Two MCP-wide on overlapping groups → 409 | T1.8, T1.10, T3.7, T4.7, A2.7 | — |
| 6 Reopening shows *Groups* with its groups | T4.7, A2.2, A2.7 | R.2 |
| 7 A policy never promoted still runs nowhere | T1.8, T2.6, T4.8, A2.7 | — |
| 8 Rollout query run and decision recorded | — | R.1 only |
