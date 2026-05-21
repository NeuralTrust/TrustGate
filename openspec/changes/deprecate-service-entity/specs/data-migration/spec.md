# Spec: data-migration

## Purpose

One-shot Postgres migration that rewires `forwarding_rules` to `upstreams` and drops the `services` table without data loss for tenants with either `type='upstream'` or `type='endpoint'` services in production.

## Requirements

### Requirement: Migration MUST move every rule to an upstream without data loss

A new migration `20240007_drop_services_and_link_rules_to_upstreams` MUST run inside a single GORM transaction (provided by `MigrationsManager.ApplyPending`) and execute these ordered steps:

1. `ALTER TABLE forwarding_rules ADD COLUMN upstream_id UUID`.
2. For every service row S where `type='upstream'`: `UPDATE forwarding_rules SET upstream_id = S.upstream_id WHERE service_id = S.id`.
3. For every service row S where `type='endpoint'`: INSERT a synthesized upstream U with `gateway_id=S.gateway_id`, `name='svc-migrated-' || S.id`, `algorithm='round-robin'`, `targets=[{id, host:S.host, port:S.port, protocol:S.protocol, path:S.path, headers:S.headers, credentials:S.credentials}]`; then `UPDATE forwarding_rules SET upstream_id = U.id WHERE service_id = S.id`.
4. Assert `SELECT COUNT(*) FROM forwarding_rules WHERE upstream_id IS NULL` returns 0; otherwise the transaction MUST ROLLBACK with an explicit error `orphan rules detected: N`.
5. `ALTER TABLE forwarding_rules ALTER COLUMN upstream_id SET NOT NULL`, drop the FK on `service_id`, drop the column `service_id`, then add FK `upstream_id REFERENCES upstreams(id) ON DELETE CASCADE`.
6. `DROP INDEX IF EXISTS idx_gateway_service_name; DROP TABLE services;`.

#### Scenario: Endpoint service migrated

- GIVEN service S with `type=endpoint, host=h, port=443, protocol=https` and rule R with `service_id=S.id`
- WHEN migration runs
- THEN a new upstream U exists in `S.gateway_id` with one target `{host:h, port:443, protocol:https}`, `R.upstream_id=U.id`, and the `services` table is dropped

#### Scenario: Upstream-type service relinked

- GIVEN service S with `type=upstream, upstream_id=U.id` and rule R with `service_id=S.id`
- WHEN migration runs
- THEN `R.upstream_id=U.id` and no new upstream is synthesized for S

#### Scenario: Orphan rule blocks migration

- GIVEN a rule R with `service_id` pointing to a non-existent service row
- WHEN migration runs
- THEN the migration ROLLS BACK with error `orphan rules detected: N` and no schema changes persist

#### Scenario: Idempotent re-run

- WHEN the migration has already been applied (recorded in `public.migration_version`)
- THEN `MigrationsManager.ApplyPending` skips it and the system boots normally

### Requirement: Migration MUST complete within elevated startup timeout

The system MUST NOT abort the migration with the current 30-second startup timeout when the tenant has up to 10,000 endpoint services. The migration runtime budget MUST be configurable via env (default 5 minutes).

#### Scenario: Large dataset

- GIVEN a database with 1,000 endpoint services and 5,000 rules
- WHEN the server boots
- THEN the migration completes within 5 minutes and the server reaches healthy state

### Requirement: Down migration MUST restore service_id link (best-effort)

The `Down` function MUST recreate the `services` table (schema only), restore `forwarding_rules.service_id` (nullable) and populate it via reverse map from the existing `upstream_id`. Synthesized upstreams (those created in step 3) are NOT collapsed back; this is documented as a one-way migration for endpoint-type services.

#### Scenario: Down after Up

- GIVEN the Up migration has been applied
- WHEN `Down` runs
- THEN `services` table exists with type='upstream' rows reverse-mapped, `forwarding_rules.service_id` is populated, `forwarding_rules.upstream_id` is dropped, and synthesized upstreams remain in place
