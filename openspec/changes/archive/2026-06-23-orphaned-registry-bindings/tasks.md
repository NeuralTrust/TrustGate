# Tasks: Fix orphaned registry-deletion guard (ENG-882)

<!-- ENG-882 -->

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~180 (guard ~12, migration ~45, migration test ~38, functional tests ~85) |
| Files changed | 4 (1 modified prod, 1 new migration, 1 new unit test, 1 modified functional test) |
| 400-line budget risk | Low |
| Chained PRs recommended | No |
| Suggested split | Single PR |
| Delivery strategy | single-pr |
| Chain strategy | size-exception (not needed; well under budget) |

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: pending
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Guard scoping + functional regression | PR 1 | Self-contained; tests included |
| 2 | Cleanup migration + unit test | PR 1 | Same PR; small, independent commit |

Both work units fit comfortably in one ~180-line PR. Phases stay as separate commits for review focus.

## Phase 1: Scope the dependency guard + regression coverage

- [x] 1.1 In `pkg/infra/repository/registry/repository.go`, change `ensureNotInFallbackChain` signature to `(ctx, tx, gatewayID ids.GatewayID, id ids.RegistryID)` and add `gateway_id = $2 AND active = TRUE` to the `SELECT EXISTS` subquery; bind `gatewayID` as `$2` (design Change 1). [Spec: guard scoped to gateway; ignores inactive]
- [x] 1.2 Update the single call site in `Delete` (`repository.go:130`) to `ensureNotInFallbackChain(ctx, tx, gatewayID, id)`; confirm no other callers. [Spec: active same-gateway still blocks]
- [x] 1.3 In `tests/functional/repositories/consumer/repository_test.go`, add `conn *database.Connection` to `fixture` and set `conn: conn` in `setupRepo`. [Harness for 1.5]
- [x] 1.4 Add `TestRepository_DeleteRegistry_IgnoresCrossGatewayFallbackConsumer`: seed cross-gateway consumer w/ fallback chain → `Delete` succeeds. [Spec: cross-gateway no-block; E2E orphan repro]
- [x] 1.5 Add `TestRepository_DeleteRegistry_IgnoresInactiveConsumer`: seed same-gateway consumer, set `active = FALSE`, `Delete` succeeds. [Spec: inactive ignored]
- [x] 1.6 Add `TestRepository_DeleteRegistry_BlockedByActiveSameGatewayConsumer`: active same-gateway fallback ref → `Delete` returns `registrydomain.ErrHasDependents`. [Spec: active same-gateway still blocks]
- [x] 1.7 Run `go test -race -tags functional ./tests/functional/repositories/consumer/...` (PG_TEST_URL set); existing tests stay green. [Validation plan]

## Phase 2: Cleanup migration + unit test

- [x] 2.1 Create `pkg/infra/database/migrations/20260623120000_cleanup_cross_gateway_consumer_registry.go` exactly per design Change 2: package-level `cleanupCrossGatewayConsumerRegistryDDL` (`DELETE ... USING consumers c, registries r ... c.gateway_id <> r.gateway_id`), `init()` registering `Up` (Exec DDL) and no-op `Down`. License header only, no code comments (`.agents/AGENT.md` §11). [Spec: cross-gateway rows cleaned; idempotent; same-gateway preserved]
- [x] 2.2 Create `..._cleanup_cross_gateway_consumer_registry_test.go` (`package migrations`): `TestCleanupCrossGatewayConsumerRegistryDeletesOnlyCrossGatewayRows` asserting all required DDL fragments are present (design Change 3). [Spec: DELETE scoped to cross-gateway]
- [x] 2.3 Run `go test ./pkg/infra/database/migrations/...`, `go vet ./...`, and `golangci-lint run` on touched packages — all clean. [Validation plan]
