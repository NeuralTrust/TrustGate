# Technical Design: Fix orphaned registry-deletion guard (ENG-882)

## Context

A registry cannot be deleted — TrustGate returns `registry: resource has dependents`
(HTTP 409 `has_dependents`) even when no consumer visible in the registry's
gateway routes to it. Per the confirmed root cause (see `proposal.md` /
`exploration.md`), the 409 originates in `ensureNotInFallbackChain`
(`pkg/infra/repository/registry/repository.go:144-159`): its `SELECT EXISTS`
over `consumers` has **no `gateway_id` filter and no `active` filter**, so a
consumer in any gateway, active or not, whose `fallback->'chain'` JSON contains
the registry UUID blocks the delete. Separately, cross-gateway
`consumer_registry` rows could have been created before the same-gateway INSERT
trigger (`20260622120000_enforce_junction_same_gateway.go`) landed; that trigger
is INSERT-only and never cleans pre-existing rows.

This design specifies two production changes (guard scoping + a cleanup
migration) and their regression coverage. It does not change error-mapping,
the dashboard copy, or `role_registry` cascade semantics (all out of scope per
the proposal).

## Goals / Non-Goals

**Goals**
- Stop the dependency guard from counting cross-gateway or inactive consumers.
- Remove pre-existing cross-gateway `consumer_registry` rows defensively, so
  stored data agrees with the same-gateway trigger.
- Add regression coverage proving the guard ignores cross-gateway/inactive
  consumers while still blocking active same-gateway ones.

**Non-Goals**
- Dashboard "associated consumers" copy (lives in the `app` repo).
- Making `role_registry.registry_id` `ON DELETE CASCADE` (separate product call).
- A targeted one-off DELETE for a specific workspace; dev Postgres is not
  queryable from here, so the migration is global-but-tightly-filtered.

## Decisions

### Decision 1 — Scope the guard to active, same-gateway consumers

Thread the registry's `gatewayID` (already in scope in `Delete`) into
`ensureNotInFallbackChain` and add `gateway_id = $2 AND active = TRUE` to the
`consumers` subquery. This fixes the false-positive at its source.

- **Alternatives rejected:**
  - *Data-cleanup migration only* — does not stop recurrence; an inactive or
    cross-gateway fallback reference would block deletion again, failing the QA
    criterion "guard no longer counts cross-gateway/soft-deleted consumers".
  - *Drop the guard entirely and rely on FK cascade* — the guard exists because
    `fallback->'chain'` is a JSONB reference with no FK; removing it would let a
    registry be deleted while a live, same-gateway consumer still routes to it on
    failover. Keep the guard, just scope it.
- **Rationale:** `Delete` already receives `gatewayID ids.GatewayID`; `consumers`
  has both `gateway_id UUID` and `active BOOLEAN NOT NULL DEFAULT TRUE`
  (confirmed in `20260528113134_create_initial_schema.go:62,69`). Inactive
  consumers are non-routable, so they are not real dependents.

### Decision 2 — Defensive, tightly-filtered cleanup migration

Add an in-code Go migration (timestamp `20260623120000`, strictly after
`20260622120000`) whose `Up` deletes only `consumer_registry` rows whose
consumer and registry live in **different** gateways. `Down` is a no-op.

- **Alternatives rejected:**
  - *Targeted DELETE by workspace/registry UUID* — dev control-plane Postgres is
    not reachable from here, and hard-coding IDs is brittle and non-portable.
  - *Cascade-based cleanup* — `consumer_registry.registry_id` is already
    `ON DELETE CASCADE` (`20260611150000`); cascade only fires on registry
    deletion and never removes a cross-gateway row whose registry still exists.
- **Rationale on `Down` being a no-op (documented here, NOT in code per
  `.agents/AGENT.md` §11):** the deleted rows are cross-gateway junction rows
  that are invalid by the `20260622120000` same-gateway invariant and are
  non-routable. They cannot be faithfully reconstructed (the migration does not
  record which rows it removed), and resurrecting them would re-introduce the
  exact invalid state the same-gateway trigger forbids. A best-effort no-op
  `Down` (returning `nil`) is therefore correct and safe — matching the
  best-effort `Down` precedent of `20260615100000_move_weight_to_consumer_registry.go`.

### Decision 3 — Test strategy mirrors existing patterns

- **Cleanup migration:** a pure string-assertion unit test in `package migrations`,
  mirroring `20260622120000_enforce_junction_same_gateway_test.go` (no PG). A
  behavioral PG test of the cleanup is intentionally **not** added: after
  `20260622120000` the same-gateway BEFORE-INSERT trigger forbids inserting any
  cross-gateway `consumer_registry` row, so a functional test cannot reproduce
  the offending data through normal inserts. The string test asserts the DELETE
  is filtered to `c.gateway_id <> r.gateway_id`.
- **Guard:** a functional PG test (`//go:build functional`, `PG_TEST_URL`) added
  to the existing consumer functional suite, which already seeds gateways,
  registries, and consumers with fallback chains and exercises `f.be.Delete`
  (see `TestRepository_DeleteBackend_FailsWhenReferencedByFallbackChain`).

## File-change table

| File | Action | Description |
|------|--------|-------------|
| `pkg/infra/repository/registry/repository.go` | Modify | Add `gatewayID ids.GatewayID` param to `ensureNotInFallbackChain`; add `gateway_id = $2 AND active = TRUE` to the subquery; update the single call site in `Delete`. |
| `pkg/infra/database/migrations/20260623120000_cleanup_cross_gateway_consumer_registry.go` | Create | Cleanup migration: `Up` deletes cross-gateway `consumer_registry` rows; `Down` no-op. |
| `pkg/infra/database/migrations/20260623120000_cleanup_cross_gateway_consumer_registry_test.go` | Create | String-assertion unit test for the cleanup DDL (mirrors `20260622120000_..._test.go`). |
| `tests/functional/repositories/consumer/repository_test.go` | Modify | Add `conn` to the `fixture`; add guard regression tests (cross-gateway ignored, inactive ignored, active same-gateway still blocks). |

## Change 1 — Guard scoping (`repository.go`)

### New signature and SQL

```go
func ensureNotInFallbackChain(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID, id ids.RegistryID) error {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM consumers
			 WHERE gateway_id = $2
			   AND active = TRUE
			   AND fallback IS NOT NULL
			   AND fallback->'chain' @> to_jsonb($1::text)
		)`
	var referenced bool
	if err := tx.QueryRow(ctx, query, id.String(), gatewayID).Scan(&referenced); err != nil {
		return fmt.Errorf("registry repository: fallback-chain check: %w", err)
	}
	if referenced {
		return domain.ErrHasDependents
	}
	return nil
}
```

`gatewayID` binds directly as `$2` (a `uuid`), consistent with the existing
`tx.Exec(ctx, query, id, gatewayID)` in `Delete`, which already passes
`ids.RegistryID` / `ids.GatewayID` directly to pgx. `id.String()` continues to
feed the JSONB containment check as text.

### Updated call site in `Delete` (`repository.go:130`)

```go
func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) error {
	const query = `DELETE FROM registries WHERE id = $1 AND gateway_id = $2`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		if err := ensureNotInFallbackChain(ctx, tx, gatewayID, id); err != nil {
			return err
		}
		cmd, err := tx.Exec(ctx, query, id, gatewayID)
		if err != nil {
			return mapPgDeleteError(err)
		}
		if cmd.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}
```

No other call sites: `ensureNotInFallbackChain` is unexported and called only
from `Delete` (grep-confirmed). No import changes (the function already lives in
`package registry`, which imports `ids` and `pgx`).

## Change 2 — Cleanup migration (full file content)

`pkg/infra/database/migrations/20260623120000_cleanup_cross_gateway_consumer_registry.go`

```go
// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package migrations

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

const cleanupCrossGatewayConsumerRegistryDDL = `
	DELETE FROM consumer_registry cr
	USING consumers c, registries r
	WHERE cr.consumer_id = c.id
	  AND cr.registry_id = r.id
	  AND c.gateway_id <> r.gateway_id;`

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260623120000_cleanup_cross_gateway_consumer_registry",
		Name: "delete cross-gateway consumer_registry rows",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, cleanupCrossGatewayConsumerRegistryDDL)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			return nil
		},
	})
}
```

Notes:
- The DDL is hoisted to a package-level const (`cleanupCrossGatewayConsumerRegistryDDL`)
  so the unit test can assert on it, exactly as `20260622120000` exposes
  `enforceJunctionSameGatewayDDL`.
- The `DELETE ... USING` join is restricted to `c.gateway_id <> r.gateway_id`, so
  only rows whose consumer and registry are in different gateways are removed;
  valid same-gateway bindings are untouched. The statement is idempotent
  (re-running deletes nothing once clean) and runs inside the runner's single tx.
- No code comments (per `.agents/AGENT.md` §11) — rationale for the no-op `Down`
  lives in Decision 2 above.

## Change 3 — Cleanup migration unit test (full file content)

`pkg/infra/database/migrations/20260623120000_cleanup_cross_gateway_consumer_registry_test.go`

```go
// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package migrations

import (
	"strings"
	"testing"
)

func TestCleanupCrossGatewayConsumerRegistryDeletesOnlyCrossGatewayRows(t *testing.T) {
	t.Parallel()

	required := []string{
		"DELETE FROM consumer_registry",
		"USING consumers c, registries r",
		"cr.consumer_id = c.id",
		"cr.registry_id = r.id",
		"c.gateway_id <> r.gateway_id",
	}
	for _, frag := range required {
		if !strings.Contains(cleanupCrossGatewayConsumerRegistryDDL, frag) {
			t.Fatalf("cleanup DDL missing required fragment %q", frag)
		}
	}
}
```

This mirrors `20260622120000_enforce_junction_same_gateway_test.go`: a fast,
PG-free guard that the DELETE stays scoped to cross-gateway rows. If a future
reviewer wants behavioral proof, note that the same-gateway INSERT trigger
(`20260622120000`) prevents seeding cross-gateway rows through normal inserts,
so a meaningful functional test would have to bypass the trigger
(`ALTER TABLE ... DISABLE TRIGGER`) — deliberately omitted to keep the suite
honest to production constraints.

## Change 4 — Guard regression tests (functional, PG)

Added to `tests/functional/repositories/consumer/repository_test.go`
(`//go:build functional`, gated on `PG_TEST_URL`). The cross-gateway fallback
reference is seedable through `repo.Save` because `consumer.Save` writes the
`fallback` JSONB verbatim and does not validate chain entries against the
consumer's gateway (confirmed: `TestRepository_DeleteBackend_FailsWhenReferencedByFallbackChain`
saves a fallback chain to a registry that is not even attached).

### Harness tweak

Add the connection to the fixture so a test can flip `active`:

```go
type fixture struct {
	repo  *repo.Repository
	gw    *gatewayrepo.Repository
	be    *registryrepo.Repository
	roles *rolerepo.Repository
	conn  *database.Connection
}
```

Set `conn: conn` in `setupRepo`'s returned fixture (the `conn` is already built
there). No other harness change; the existing `TRUNCATE ... CASCADE` cleanup
already covers `consumers`, `registries`, `gateways`, and `consumer_registry`.

### Test: cross-gateway fallback consumer is ignored

```go
func TestRepository_DeleteRegistry_IgnoresCrossGatewayFallbackConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwReg := seedGateway(t, f.gw, "gw-reg")
	gwOther := seedGateway(t, f.gw, "gw-other")
	regID := seedRegistry(t, f.be, gwReg, "victim-reg")
	otherReg := seedRegistry(t, f.be, gwOther, "other-pool")

	c := validConsumer(t, gwOther, "cross-gw-consumer", otherReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := f.be.Delete(ctx, gwReg, regID); err != nil {
		t.Fatalf("Delete: %v, want success (cross-gateway consumer must not block)", err)
	}
}
```

### Test: inactive same-gateway consumer is ignored

```go
func TestRepository_DeleteRegistry_IgnoresInactiveConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-inactive")
	poolReg := seedRegistry(t, f.be, gwID, "inactive-pool")
	regID := seedRegistry(t, f.be, gwID, "inactive-victim")

	c := validConsumer(t, gwID, "inactive-consumer", poolReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := f.conn.Pool.Exec(ctx, "UPDATE consumers SET active = FALSE WHERE id = $1", c.ID); err != nil {
		t.Fatalf("deactivate consumer: %v", err)
	}

	if err := f.be.Delete(ctx, gwID, regID); err != nil {
		t.Fatalf("Delete: %v, want success (inactive consumer must not block)", err)
	}
}
```

### Test: active same-gateway consumer still blocks

```go
func TestRepository_DeleteRegistry_BlockedByActiveSameGatewayConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "gw-block")
	poolReg := seedRegistry(t, f.be, gwID, "block-pool")
	regID := seedRegistry(t, f.be, gwID, "block-victim")

	c := validConsumer(t, gwID, "active-consumer", poolReg)
	c.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    registrydomain.Registries{regID},
	}
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	err := f.be.Delete(ctx, gwID, regID)
	if !errors.Is(err, registrydomain.ErrHasDependents) {
		t.Fatalf("err = %v, want registrydomain.ErrHasDependents", err)
	}
}
```

(The third case overlaps with the existing
`TestRepository_DeleteBackend_FailsWhenReferencedByFallbackChain`; keep it
explicit as the same-gateway counterpart to the two new ignore-cases, or fold it
into a table test at the implementer's discretion.)

## Sequence: registry delete after the fix

```
Handler.Delete(gatewayID, id)
  └─ deleter.Delete: FindByID → assert existing.GatewayID == gatewayID
       └─ repo.Delete(ctx, gatewayID, id)   [WithTx]
            ├─ ensureNotInFallbackChain(ctx, tx, gatewayID, id)
            │     SELECT EXISTS(consumers
            │        WHERE gateway_id = $gatewayID   ← NEW: same-gateway only
            │          AND active = TRUE             ← NEW: routable only
            │          AND fallback->'chain' @> to_jsonb($id))
            │     ├─ exists  → return ErrHasDependents → 409 has_dependents
            │     └─ none    → continue
            └─ DELETE FROM registries WHERE id=$id AND gateway_id=$gatewayID
                 ├─ FK 23503 → mapPgDeleteError → ErrHasDependents (role_registry RESTRICT)
                 ├─ 0 rows   → ErrNotFound
                 └─ ok       → committed; consumer_registry rows cascade-deleted
```

## Migration ordering & application

`20260623120000` sorts strictly after `20260622120000` (same-gateway trigger) and
`20260611150000` (cascade), so by the time it runs the trigger already prevents
new cross-gateway rows and the cascade FK is in place. The functional suites call
`database.NewMigrationsManager(pool).ApplyPending(ctx)` in `setupRepo`, so the new
migration is auto-applied for all PG-backed tests; the runner wraps `Up`/`Down`
each in a single tx (`.agents/AGENT.md` §7).

## Validation plan

- `go vet ./...` and `golangci-lint run` clean on the touched packages.
- `go test ./pkg/infra/database/migrations/...` (unit, no PG) → cleanup DDL test passes.
- `go test -race -tags functional ./tests/functional/repositories/consumer/...`
  with `PG_TEST_URL` set → the three guard tests pass; existing tests stay green.
- Manual/dev: after deploy + migration, the previously-stuck registry deletes
  successfully from the dashboard.

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Cleanup DELETE removes valid bindings | Low | Strictly filtered to `c.gateway_id <> r.gateway_id`; idempotent. |
| Registry deletable while an inactive consumer references it | Low | Accepted per QA intent — inactive consumers are non-routable. |
| `gatewayID` bind type mismatch in the guard query | Very low | Same value/type is already bound as `$2` in `Delete`'s `DELETE`. |
| Real dev blocker is a `role_registry` RESTRICT FK, not the guard | Low | Out of scope by proposal; `mapPgDeleteError` still surfaces it as `ErrHasDependents`, and the guard fix + cleanup cover the documented false-positive. |

## Open Questions

None blocking. Confirmed by inspection in the worktree:
- `consumers.active` (`BOOLEAN NOT NULL DEFAULT TRUE`) and `consumers.gateway_id`
  both exist (`20260528113134_create_initial_schema.go`).
- `ensureNotInFallbackChain` has exactly one caller (`Delete`).
- The migration test harness for `20260622120000` is a PG-free string-assertion
  unit test; the cleanup migration follows the same shape.
- `consumer.Save` persists the `fallback` JSONB without cross-gateway validation,
  so the cross-gateway guard test is seedable through the repository API.
```
