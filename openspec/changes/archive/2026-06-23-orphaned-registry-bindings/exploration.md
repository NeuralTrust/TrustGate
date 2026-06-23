# Exploration: orphaned consumer↔registry bindings block registry deletion (ENG-882)

## Summary

A registry (Notion, gateway 2, dev) cannot be deleted — the backend returns
`registry: resource has dependents` (HTTP 409 `has_dependents`) even though no
consumer visible in that gateway routes to it. The registry-deletion dependency
guard is **not scoped to the registry's own gateway** and **does not exclude
inactive / non-routing consumers**, and `consumer_registry` could hold
cross-gateway rows created before the same-gateway trigger landed. The result:
leftover/cross-gateway references make a registry look like it "has dependents".

## Registry deletion flow (handler → use case → repository)

1. **Handler** — `pkg/api/handler/http/registry/delete_registry_handler.go:46-55`
   parses `gateway_id` + `id` and calls `deleter.Delete(ctx, gatewayID, id)`.
2. **Use case** — `pkg/app/registry/deleter.go:54-68`
   - `repo.FindByID` then checks `existing.GatewayID == gatewayID` (404 otherwise).
   - calls `repo.Delete(ctx, gatewayID, id)`.
   - It does **no** dependency counting itself.
3. **Repository** — `pkg/infra/repository/registry/repository.go:126-159`
   - `Delete` runs inside `WithTx`. First it calls the guard
     `ensureNotInFallbackChain(ctx, tx, id)`, then `DELETE FROM registries
     WHERE id = $1 AND gateway_id = $2`.
   - FK violations on the `DELETE` are mapped by `mapPgDeleteError`
     (`repository.go:368-375`): pg code `23503` → `domain.ErrHasDependents`.
4. **Error mapping** — `pkg/api/handler/http/helpers/errors.go:53-54` maps
   `commonerrors.ErrHasDependents` → 409 `has_dependents`. The user-facing
   "associated consumers" string is produced by the dashboard (`app` repo), not
   TrustGate.

### The guard itself — the prime suspect

```146:159:pkg/infra/repository/registry/repository.go
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM consumers
			 WHERE fallback IS NOT NULL
			   AND fallback->'chain' @> to_jsonb($1::text)
		)`
	var referenced bool
	if err := tx.QueryRow(ctx, query, id.String()).Scan(&referenced); err != nil {
		return fmt.Errorf("registry repository: fallback-chain check: %w", err)
	}
	if referenced {
		return domain.ErrHasDependents
	}
	return nil
```

Problems with this guard:
- **No `gateway_id` filter** — it scans `consumers` across *every* gateway. A
  consumer in another gateway whose `fallback.chain` JSON contains this
  registry's UUID blocks the delete, even though it is invisible in gateway 2.
- **No `active = TRUE` filter** — a deactivated ("soft-deleted" in QA language;
  there is no real soft-delete, only `consumers.active=false`) consumer still
  blocks deletion. Inactive consumers are not routable
  (`pkg/app/consumer/consumer_data.go:140`) so they should not count as dependents.
- It only inspects `fallback->'chain'`; `model_policies` / `lb_config` inline
  references are *not* checked here (they rely on the FK), so the guard is both
  too broad (cross-gateway/inactive) and inconsistent.

`ErrHasDependents` for a registry is produced in exactly two places (confirmed
by grep): this guard and `mapPgDeleteError`. There is no separate
`consumer_registry` COUNT query.

## The `consumer_registry` junction schema

Created as `consumer_backend` in `20260528113134_create_initial_schema.go:79-84`,
renamed to `consumer_registry` (`backend_id` → `registry_id`) in
`20260603100000_rename_backends_to_registries.go`. Columns:

- `consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE`
- `registry_id UUID` — FK changed to `ON DELETE CASCADE` by
  `20260611150000_consumer_registry_cascade_on_registry_delete.go:30-32`
  (was `ON DELETE RESTRICT`).
- `weight INT NOT NULL DEFAULT 1` — added `20260615100000_move_weight_to_consumer_registry.go`,
  clamped to 1..100 by `20260615110000_clamp_consumer_registry_weight.go`.
- PK `(consumer_id, registry_id)`; index on `registry_id`.

Triggers on the junction:
- `consumer_registry_mode_guard` (`20260610090000`) — BEFORE INSERT, rejects a
  registry binding on a `role_based` consumer (`AG409`).
- `consumer_registry_gateway_guard` (`20260622120000_enforce_junction_same_gateway.go:58-60`)
  — BEFORE INSERT, rejects a binding whose consumer and registry are in
  different gateways (`AG422`). **INSERT-only** — it does not retroactively
  clean pre-existing cross-gateway rows.

Key consequence: because `consumer_id` and (after `20260611150000`)
`registry_id` are both `ON DELETE CASCADE`, neither deleting a consumer nor
deleting a registry should FK-violate on `consumer_registry`. The remaining
RESTRICT path to registries is `role_registry.registry_id`
(`20260610090000_add_roles_and_routing_mode.go:60-61`).

## Consumer deletion flow — hard delete + cascade

- App: `pkg/app/consumer/deleter.go:54-68` — `FindByID`, gateway check, then
  `repo.Delete`. Hard delete; there is **no soft-delete**. `active=false` is a
  routing flag only (set via `updater.go:104-105`), not a delete.
- Repo: `pkg/infra/repository/consumer/repository.go:397-409` —
  `DELETE FROM consumers WHERE id=$1 AND gateway_id=$2`. The `consumer_id`
  CASCADE FK removes the consumer's `consumer_registry` (and `consumer_role`,
  `consumer_auth`, `consumer_policy`) rows automatically.

So the QA criterion "deleting a consumer removes its binding rows" already holds
*for same-gateway rows via cascade*. The orphan risk is **cross-gateway**
`consumer_registry` rows (creatable before the `20260622` trigger): the binding
references a registry in a different gateway than the consumer, so it is not
surfaced in either gateway's UI but still exists in the table.

## Associate / dissociate

- `pkg/app/consumer/associator.go:81-111` — `AttachRegistry` validates
  consumer+registry are in the same gateway and type-match, then
  `repo.AttachRegistry`. `DetachRegistry` delegates to
  `repo.DetachRegistryIfUnreferenced` (only detaches if no fallback/model_policies/
  lb_config still references it).
- Repo junction writes: `repository.go:258-334`. Pre-June-22 attach paths did
  not enforce same-gateway, which is how cross-gateway rows can exist in dev.

## Migration conventions (for the eventual fix)

- In-code Go migrations under `pkg/infra/database/migrations/`, named
  `<unix_ts>_<snake>.go`, each registering via `init()` →
  `database.RegisterMigration{ID, Name, Up, Down}` with `Up`/`Down` taking
  `(ctx, pgx.Tx)`. The runner wraps each in a single tx (`.agents/AGENT.md` §7).
- Data-cleanup precedent: `20260615100000_move_weight_to_consumer_registry.go`
  runs DML inside the migration tx (UPDATE/ALTER), with a best-effort `Down`.
- New migration timestamp must sort after `20260622120000`. No code comments
  except `//go:*` and the license header (`.agents/AGENT.md` §11).

## Root-cause hypothesis

The registry "has dependents" decision is computed without scoping to the
registry's gateway and without excluding inactive consumers:

1. **Primary (code):** `ensureNotInFallbackChain`
   (`pkg/infra/repository/registry/repository.go:144-159`) scans **all**
   consumers (any gateway, active or not) for a `fallback.chain` reference. A
   cross-gateway or deactivated consumer referencing the Notion UUID returns
   `ErrHasDependents`, so the delete fails although gateway 2's UI shows nothing.
2. **Data:** cross-gateway / orphaned `consumer_registry` rows for Notion exist
   in dev (insertable before the `20260622` same-gateway trigger). These need a
   one-off cleanup, and — if the dev DB has not actually applied the
   `20260611150000` cascade (or via `role_registry` RESTRICT) — they can also
   raise the FK violation that `mapPgDeleteError` turns into `ErrHasDependents`.

**First design step must be to confirm the exact blocker in dev at the DB
level** (does the fallback-chain guard match a row? is there a cross-gateway
`consumer_registry` / `role_registry` row? is `consumer_registry_registry_id_fkey`
actually `ON DELETE CASCADE` in dev?), because that determines whether the fix is
guard-scoping, data-cleanup, FK-cascade, or all three.

## Affected files

- `pkg/infra/repository/registry/repository.go` — guard (`ensureNotInFallbackChain`
  144-159), `Delete` (126-142), `mapPgDeleteError` (368-375). **Main fix site.**
- `pkg/app/registry/deleter.go` — registry delete use case (no scoping today).
- `pkg/infra/repository/consumer/repository.go` — junction writes / cascade-backed
  consumer delete (397-409); detach logic (290-334).
- `pkg/infra/database/migrations/` — add a cleanup migration (delete cross-gateway /
  orphaned `consumer_registry` rows; optionally `role_registry`); reference
  `20260611150000` (cascade) and `20260622120000` (same-gateway trigger).
- `pkg/api/handler/http/helpers/errors.go:53-54` — 409 mapping (no change, context).
- `app` repo (dashboard) — owns the "associated consumers" copy (out of scope here).

## Approaches

1. **Gateway-scope + active-filter the guard, plus a cleanup migration** — make
   `ensureNotInFallbackChain` (and any FK-backed dependency notion) only count
   *active, same-gateway* consumers; add a migration deleting cross-gateway /
   orphaned `consumer_registry` rows for the affected workspace.
   - Pros: fixes the false-positive at the source; matches every QA criterion;
     low blast radius.
   - Cons: must verify the real dev blocker first; need to decide whether to also
     scope `role_registry`.
   - Effort: Medium.

2. **Data-cleanup migration only** — just delete the orphaned Notion bindings.
   - Pros: unblocks the immediate ticket fastest.
   - Cons: does not stop recurrence; cross-gateway/inactive references will block
     again; fails the "guard no longer counts cross-gateway/soft-deleted" criterion.
   - Effort: Low.

3. **Make `role_registry.registry_id` ON DELETE CASCADE + scope guard** — extend
   the cascade pattern of `20260611150000` to `role_registry` and scope the
   fallback guard.
   - Pros: removes the last RESTRICT FK to registries.
   - Cons: cascade-deleting role↔registry links on registry delete may be
     surprising for role-based routing; needs product confirmation.
   - Effort: Medium.

## Recommendation

Approach **1**. Confirm the precise dev blocker at the DB level first, then
(a) scope the registry dependency guard to active, same-gateway consumers and
(b) ship a one-off cleanup migration for the orphaned/cross-gateway Notion
bindings. Keep `role_registry` cascade as a separate decision pending product
input.

## Risks

- Acting before confirming the real blocker (guard vs FK vs data) could fix the
  wrong layer.
- A global `DELETE` cleanup migration must be tightly filtered (by gateway and by
  "consumer in a different gateway than the registry") to avoid removing valid
  bindings.
- Changing dependency semantics could let a registry be deleted while an inactive
  consumer still references it — acceptable per the QA intent, but the dashboard
  copy/UX should stay consistent.

## Ready for Proposal

Yes — root cause and fix sites are identified. The proposal should require a
DB-level confirmation of the dev blocker as task 0, then guard-scoping + a
filtered cleanup migration, with regression coverage for the
create→attach→delete-consumer→delete-registry path.
