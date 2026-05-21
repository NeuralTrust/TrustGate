# Release notes — Service entity deprecation

**Status**: ready to ship
**Type**: breaking change

## Summary

The `Service` entity is removed. `ForwardingRule` now references `Upstream` directly via a new `upstream_id` foreign key. A one-shot data migration (`20240007_drop_services_and_link_rules_to_upstreams`) runs automatically on startup to migrate existing data.

## Breaking changes

### Admin API

- **Removed**: `POST/GET/PUT/DELETE /api/v1/gateways/{gateway_id}/services` and `GET /api/v1/gateways/{gateway_id}/services/{service_id}`. All `/services` routes return 404.
- **Changed**: The `/rules` endpoints now expect and return `upstream_id` instead of `service_id`.

  | Endpoint | Old field | New field |
  |---|---|---|
  | `POST /api/v1/gateways/{gateway_id}/rules` | `"service_id": "<uuid>"` (required) | `"upstream_id": "<uuid>"` (required) |
  | `PUT /api/v1/gateways/{gateway_id}/rules/{rule_id}` | `"service_id"` (optional) | `"upstream_id"` (optional) |
  | `GET /api/v1/gateways/{gateway_id}/rules` (list response) | `"service_id"` per rule | `"upstream_id"` per rule |

  Clients that send `service_id` will get HTTP 400 (`upstream_id is required`).

- **Changed**: The new cross-gateway validation. Creating a rule whose `upstream_id` points to an `Upstream` owned by a different gateway returns HTTP 400 (`Upstream not found`) — same response as a non-existent upstream, by design (no information leak).

### Observability

- **Renamed Prometheus label**: `service` → `upstream` on the `trustgate_detailed_latency_ms` and `trustgate_upstream_latency_ms` histograms. Update dashboards and alerts that group/filter by `service{...}`.
- **Renamed Fiber response header**: `Service-Id` → `Upstream-Id` (internal constant `ServiceIDKey` → `UpstreamIDKey`, value changes from `"service_id"` to `"upstream_id"`).
- **Removed audit event types**: `service.created`, `service.updated`, `service.deleted`. The `target.type=service` value is also gone. No more `service.*` events on the audit stream.

### Configuration

- **New env var**: `DB_MIGRATION_TIMEOUT` (default `5m`). Caps how long the startup migration phase may run. Increase if your `forwarding_rules`/`services` tables are large. Format: any Go duration (`30s`, `10m`, `1h`).

## Migration

### What runs on startup

The migration is transactional and runs once (advisory lock prevents concurrent execution from multiple replicas):

1. Add `upstream_id UUID` to `forwarding_rules` (nullable for now).
2. Relink rules whose service was of type `upstream`: copy `services.upstream_id` into `forwarding_rules.upstream_id`.
3. Synthesize one new `Upstream` per `services` row of type `endpoint` (name `svc-migrated-<service_uuid>`, algorithm `round-robin`, single target with the service's `host/port/protocol/path/headers/credentials`); point the affected rules at the synthesized upstream.
4. Assert that no row in `forwarding_rules` has `upstream_id IS NULL`. On failure: `fmt.Errorf("orphan rules detected: %d", n)`, transaction rolls back, app **fails to start**.
5. `ALTER COLUMN upstream_id SET NOT NULL`, drop the `service_id` column (FK cascades), add a new FK on `upstream_id`.
6. Drop the `services` table.

### Operator pre-flight checklist

Before deploying:

1. **Backup the DB**. The `Down` migration is best-effort but you should not rely on it for production rollback. Take a snapshot.
2. **Hunt orphan rules** (rules referencing a service that no longer exists):

   ```sql
   SELECT fr.id AS rule_id, fr.service_id, fr.gateway_id, fr.path
   FROM forwarding_rules fr
   LEFT JOIN services s ON s.id = fr.service_id
   WHERE s.id IS NULL;
   ```

   If this returns rows: **fix them before deploying**. Options:
   - Delete the orphan rules: `DELETE FROM forwarding_rules WHERE id IN (...);`
   - Or re-create the missing services if the rules are still desired.

   If you skip this check, the migration will abort during startup with `orphan rules detected: N` and the app will not start.

3. **Estimate migration time**. Rough rule of thumb: ~5s per 10k `forwarding_rules` rows on commodity Postgres. Set `DB_MIGRATION_TIMEOUT` to ~3× the estimate. If you have >500k rules, prefer running the migration manually during a maintenance window:
   - Stand up a temporary container with `DB_MIGRATION_TIMEOUT=30m` against the prod DB,
   - or extract the SQL from `pkg/infra/migrations/20240007_*.go` and run it through `psql` inside a `BEGIN; ... COMMIT;` block.
4. **Audit your dashboards**. Search for `service{` or `service_id` label references in Grafana, Loki, Prometheus alert rules; rename to `upstream` / `upstream_id`.
5. **Audit external API clients**. Every caller that posts/updates rules must switch the JSON key.

### Post-deploy verification

```sql
-- 1. services table is gone
SELECT to_regclass('public.services');  -- NULL means dropped

-- 2. forwarding_rules has upstream_id, NOT service_id
SELECT column_name FROM information_schema.columns
WHERE table_name = 'forwarding_rules' AND column_name IN ('service_id','upstream_id');
-- expect a single row: upstream_id

-- 3. no orphan upstream references
SELECT fr.id AS rule_id, fr.upstream_id, fr.gateway_id
FROM forwarding_rules fr
LEFT JOIN upstreams u ON u.id = fr.upstream_id
WHERE u.id IS NULL;
-- expect 0 rows

-- 4. count synthesized upstreams (one per endpoint-type service from before)
SELECT count(*) FROM upstreams WHERE name LIKE 'svc-migrated-%';
```

## Rollback

If the migration completes but you need to revert:

- The `Down` migration recreates the `services` table schema, re-adds `service_id` to `forwarding_rules`, and reverse-maps each rule's `upstream_id` back to a `service_id`. Synthesized upstreams (the `svc-migrated-*` ones) remain — they are now indistinguishable from normal upstreams.
- This is best-effort; **prefer restoring from the pre-deploy snapshot** for true rollback parity.
