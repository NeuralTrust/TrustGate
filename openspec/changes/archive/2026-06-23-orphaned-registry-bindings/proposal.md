# Proposal: Fix orphaned registry-deletion guard (ENG-882)

## Intent

Notion registry (gateway 2, workspace `e72e2453-…`, dev) cannot be deleted: backend returns `registry: resource has dependents` (409) though no consumer in gateway 2 routes to it. **The reporter's "orphaned consumer↔registry bindings" hypothesis is not the blocker.** Evidence: `ErrHasDependents` for a registry comes from exactly two sites — `ensureNotInFallbackChain` (`pkg/infra/repository/registry/repository.go:144-159`) and `mapPgDeleteError` (`:368-375`). The guard runs `SELECT EXISTS(... consumers WHERE fallback->'chain' @> to_jsonb($1))` with **no `gateway_id` and no `active` filter**, so any consumer in any gateway, active or not, whose fallback chain JSON contains the registry UUID blocks deletion — invisible in gateway 2's UI. `consumer_registry.registry_id` is `ON DELETE CASCADE` (migration `20260611150000`); the same-gateway trigger (`20260622120000`) is BEFORE INSERT only, so pre-existing cross-gateway junction rows are never cleaned.

## Scope

### In Scope
- Scope `ensureNotInFallbackChain` to the registry's own gateway and active consumers: pass `gatewayID` and add `WHERE gateway_id = $2 AND active = TRUE`.
- Cleanup migration (timestamp after `20260622120000`) deleting cross-gateway/orphaned `consumer_registry` rows globally (consumer's gateway ≠ registry's gateway); idempotent up, best-effort down.
- Regression tests: create→attach→delete-consumer→delete-registry; guard ignores cross-gateway/inactive consumers.

### Out of Scope
- Dashboard "associated consumers" copy (lives in `app` repo).
- Making `role_registry.registry_id` `ON DELETE CASCADE` (separate product decision).
- One-off targeted DELETE: dev control-plane Postgres is not queryable from here, so we ship a defensive migration covering all plausible causes instead.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- None (bug fix; no existing spec captures registry-deletion dependency semantics).

## Approach

Approach 1 from exploration: fix the false-positive at the source (gateway+active scoping of the dependency guard) and align stored data with the same-gateway trigger via a filtered cleanup migration. Assumption stated explicitly: dev DB cannot be inspected here, so the migration is defensive rather than targeted.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/repository/registry/repository.go` | Modified | Scope guard to gateway + active; thread `gatewayID` into `ensureNotInFallbackChain`. |
| `pkg/infra/database/migrations/` | New | Cleanup migration for cross-gateway/orphaned `consumer_registry` rows. |
| `pkg/infra/repository/registry/*_test.go` | New/Modified | Guard + delete regression coverage. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Cleanup DELETE removes valid bindings | Med | Filter strictly: only rows where consumer.gateway_id ≠ registry.gateway_id. |
| Real dev blocker differs from guard | Low | Migration also clears cross-gateway data; guard fix covers the false-positive. |
| Registry deletable while inactive consumer references it | Low | Accepted per QA intent (inactive = non-routable). |

## Rollback Plan

Revert the guard change (restores prior unscoped query). Migration `Down` is best-effort and additive-safe; deleted orphaned rows are non-routable, so rollback needs no data restore.

## Dependencies

- Migrations `20260611150000` (cascade) and `20260622120000` (same-gateway trigger) already applied.

## Success Criteria

- [ ] Orphaned cross-gateway Notion bindings removed in gateway 2 / workspace.
- [ ] Notion registry deletable from the dashboard.
- [ ] Deleting a consumer removes its `consumer_registry` rows (DB-verified via cascade).
- [ ] Guard no longer counts inactive or cross-gateway consumers.
- [ ] Regression: create consumer → attach registry → delete consumer → registry deletable.
