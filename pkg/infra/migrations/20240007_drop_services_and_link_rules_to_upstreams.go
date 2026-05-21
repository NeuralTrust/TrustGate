package migrations

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

// 20240007_drop_services_and_link_rules_to_upstreams rewires forwarding_rules
// directly to upstreams and drops the services table.
//
// Up steps (single transaction provided by MigrationsManager.ApplyPending):
//  1. ADD COLUMN forwarding_rules.upstream_id UUID (nullable).
//  2. Relink rules whose service is type='upstream' → service.upstream_id.
//  3. Synthesize a single-target upstream per type='endpoint' service, then
//     relink rules to the synthesized upstream.
//  4. Assert no orphan rules (upstream_id IS NULL); else fail to trigger
//     rollback with `orphan rules detected: N`.
//  5. SET NOT NULL on upstream_id, drop service_id FK + column, add FK
//     upstream_id → upstreams(id) ON DELETE CASCADE.
//  6. Drop the services table and its supporting index.
//
// Endpoint synthesis is one-way: the Down function recreates the services
// table schema and reverse-maps type='upstream' rows only. Synthesized
// upstreams remain in place.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20240007_drop_services_and_link_rules_to_upstreams",
		Name: "Drop services table; link forwarding_rules directly to upstreams",

		Up: func(db *gorm.DB) error {
			// 1. Add nullable upstream_id column.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD COLUMN IF NOT EXISTS upstream_id UUID;
			`).Error; err != nil {
				return fmt.Errorf("add upstream_id column: %w", err)
			}

			// 2. Relink rules pointing to type='upstream' services.
			if err := db.Exec(`
				UPDATE forwarding_rules fr
				SET upstream_id = s.upstream_id
				FROM services s
				WHERE fr.service_id = s.id
				  AND s.type = 'upstream'
				  AND s.upstream_id IS NOT NULL;
			`).Error; err != nil {
				return fmt.Errorf("relink upstream-type services: %w", err)
			}

			// 3. Synthesize an upstream per endpoint-type service in a CTE,
			// then relink the rules to the freshly-inserted upstreams.
			// Naming: `svc-migrated-<service_uuid>` (D7 in design.md).
			//
			// Targets JSON is shaped to match upstream.Target with a single
			// target carrying host/port/protocol/path/headers/credentials
			// from the source service row. Headers/credentials are stored
			// as JSONB in both tables with the same schema, so we copy
			// them verbatim and fall back to '{}' when null.
			if err := db.Exec(`
				WITH synthesized AS (
					INSERT INTO upstreams (
						id, gateway_id, name, algorithm, targets,
						created_at, updated_at
					)
					SELECT
						gen_random_uuid(),
						s.gateway_id,
						'svc-migrated-' || s.id::text,
						'round-robin',
						jsonb_build_array(
							jsonb_build_object(
								'id',          's.' || s.id::text || '.t.0',
								'host',        COALESCE(s.host, ''),
								'port',        COALESCE(s.port, 0),
								'protocol',    COALESCE(s.protocol, 'https'),
								'path',        COALESCE(s.path, ''),
								'headers',     COALESCE(s.headers, '{}'::jsonb),
								'credentials', COALESCE(s.credentials, '{}'::jsonb),
								'stream',      COALESCE(s.stream, false)
							)
						),
						NOW(),
						NOW()
					FROM services s
					WHERE s.type = 'endpoint'
					RETURNING id, name
				),
				mapped AS (
					SELECT
						s.id           AS service_id,
						syn.id         AS upstream_id
					FROM services s
					JOIN synthesized syn
					  ON syn.name = 'svc-migrated-' || s.id::text
					WHERE s.type = 'endpoint'
				)
				UPDATE forwarding_rules fr
				SET upstream_id = m.upstream_id
				FROM mapped m
				WHERE fr.service_id = m.service_id;
			`).Error; err != nil {
				return fmt.Errorf("synthesize endpoint upstreams: %w", err)
			}

			// 4. Orphan-rule assertion. Any rule still without upstream_id
			// means we cannot guarantee a safe cut-over; rollback the Tx.
			var orphans int64
			if err := db.Raw(`
				SELECT COUNT(*) FROM forwarding_rules WHERE upstream_id IS NULL;
			`).Scan(&orphans).Error; err != nil {
				return fmt.Errorf("count orphan rules: %w", err)
			}
			if orphans > 0 {
				return fmt.Errorf("orphan rules detected: %d", orphans)
			}

			// 5. Lock down upstream_id and swap the foreign key.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ALTER COLUMN upstream_id SET NOT NULL;
			`).Error; err != nil {
				return fmt.Errorf("set upstream_id NOT NULL: %w", err)
			}

			// The FK constraint on service_id was created implicitly by the
			// initial schema (REFERENCES services(id) ON DELETE CASCADE).
			// Postgres auto-names it; dropping the column also drops the
			// constraint, so we just drop the column directly.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				DROP COLUMN IF EXISTS service_id;
			`).Error; err != nil {
				return fmt.Errorf("drop service_id column: %w", err)
			}

			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD CONSTRAINT forwarding_rules_upstream_id_fkey
				FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE CASCADE;
			`).Error; err != nil {
				return fmt.Errorf("add upstream_id fk: %w", err)
			}

			// 6. Drop the services table and its support index.
			if err := db.Exec(`DROP INDEX IF EXISTS idx_gateway_service_name;`).Error; err != nil {
				return fmt.Errorf("drop services index: %w", err)
			}
			if err := db.Exec(`DROP TABLE IF EXISTS services;`).Error; err != nil {
				return fmt.Errorf("drop services table: %w", err)
			}

			return nil
		},

		Down: func(db *gorm.DB) error {
			// Recreate services table (schema only, type='upstream' rows
			// will be reverse-mapped from forwarding_rules).
			if err := db.Exec(`
				CREATE TABLE IF NOT EXISTS services (
					id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
					gateway_id   UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					name         TEXT NOT NULL,
					type         TEXT NOT NULL,
					description  TEXT,
					tags         JSONB,
					upstream_id  UUID NULL REFERENCES upstreams(id) ON DELETE SET NULL,
					host         TEXT,
					port         INTEGER,
					protocol     TEXT,
					path         TEXT,
					headers      JSONB,
					credentials  JSONB,
					stream       BOOLEAN NOT NULL DEFAULT FALSE,
					created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
				);
			`).Error; err != nil {
				return fmt.Errorf("recreate services table: %w", err)
			}

			if err := db.Exec(`
				CREATE INDEX IF NOT EXISTS idx_gateway_service_name
				ON services (name, gateway_id);
			`).Error; err != nil {
				return fmt.Errorf("recreate services index: %w", err)
			}

			// Restore nullable service_id on forwarding_rules.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD COLUMN IF NOT EXISTS service_id UUID;
			`).Error; err != nil {
				return fmt.Errorf("add service_id column: %w", err)
			}

			// Reverse-map: for each forwarding_rule, create a type='upstream'
			// service row that points at the rule's current upstream_id and
			// set service_id accordingly. Synthesized upstreams (from the
			// Up migration) are NOT collapsed back — they remain in place
			// and get a placeholder service row pointing at them.
			if err := db.Exec(`
				WITH inserted AS (
					INSERT INTO services (
						id, gateway_id, name, type, upstream_id,
						created_at, updated_at
					)
					SELECT
						gen_random_uuid(),
						fr.gateway_id,
						'reverse-' || fr.id::text,
						'upstream',
						fr.upstream_id,
						NOW(),
						NOW()
					FROM forwarding_rules fr
					RETURNING id, name
				)
				UPDATE forwarding_rules fr
				SET service_id = i.id
				FROM inserted i
				WHERE i.name = 'reverse-' || fr.id::text;
			`).Error; err != nil {
				return fmt.Errorf("reverse-map service_id: %w", err)
			}

			// Drop upstream_id FK and column.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				DROP CONSTRAINT IF EXISTS forwarding_rules_upstream_id_fkey;
			`).Error; err != nil {
				return fmt.Errorf("drop upstream_id fk: %w", err)
			}
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				DROP COLUMN IF EXISTS upstream_id;
			`).Error; err != nil {
				return fmt.Errorf("drop upstream_id column: %w", err)
			}

			// Restore NOT NULL + FK on service_id.
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ALTER COLUMN service_id SET NOT NULL;
			`).Error; err != nil {
				return fmt.Errorf("set service_id NOT NULL: %w", err)
			}
			if err := db.Exec(`
				ALTER TABLE forwarding_rules
				ADD CONSTRAINT forwarding_rules_service_id_fkey
				FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE;
			`).Error; err != nil {
				return fmt.Errorf("add service_id fk: %w", err)
			}

			return nil
		},
	})
}
