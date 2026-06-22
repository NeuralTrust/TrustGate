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

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260610090000_add_roles_and_routing_mode",
		Name: "add roles and routing mode",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS routing_mode TEXT NOT NULL DEFAULT 'inline';
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1
						FROM pg_constraint
						WHERE conname = 'consumers_routing_mode_check'
					) THEN
						ALTER TABLE consumers ADD CONSTRAINT consumers_routing_mode_check CHECK (routing_mode IN ('inline','role_based'));
					END IF;
				END $$;
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS lb_config JSONB;
				ALTER TABLE consumers DROP COLUMN IF EXISTS algorithm;
				ALTER TABLE consumers DROP COLUMN IF EXISTS embedding_config;

				CREATE TABLE IF NOT EXISTS roles (
					id             UUID PRIMARY KEY,
					gateway_id     UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name           TEXT NOT NULL,
					model_policies JSONB,
					mcp_policies   JSONB,
					idp_mapping    JSONB,
					created_at     TIMESTAMPTZ NOT NULL,
					updated_at     TIMESTAMPTZ NOT NULL,
					CONSTRAINT roles_gateway_name_unique UNIQUE (gateway_id, name)
				);
				CREATE INDEX IF NOT EXISTS roles_gateway_id_idx ON roles (gateway_id);
				CREATE INDEX IF NOT EXISTS roles_name_lower_idx ON roles (lower(name));

				CREATE TABLE IF NOT EXISTS role_registry (
					role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
					registry_id UUID NOT NULL REFERENCES registries(id) ON DELETE RESTRICT,
					PRIMARY KEY (role_id, registry_id)
				);
				CREATE INDEX IF NOT EXISTS role_registry_registry_idx ON role_registry (registry_id);

				CREATE TABLE IF NOT EXISTS consumer_role (
					consumer_id UUID NOT NULL REFERENCES consumers(id) ON DELETE CASCADE,
					role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
					PRIMARY KEY (consumer_id, role_id)
				);
				CREATE INDEX IF NOT EXISTS consumer_role_role_idx ON consumer_role (role_id);

				CREATE OR REPLACE FUNCTION enforce_consumer_routing_mode() RETURNS trigger AS $$
				DECLARE
					m TEXT;
				BEGIN
					IF TG_TABLE_NAME = 'consumer_registry' THEN
						SELECT routing_mode INTO m FROM consumers WHERE id = NEW.consumer_id;
						IF m = 'role_based' THEN
							RAISE EXCEPTION 'routing_mode_conflict: registry on role_based consumer %', NEW.consumer_id USING ERRCODE = 'AG409';
						END IF;
						RETURN NEW;
					ELSIF TG_TABLE_NAME = 'consumer_role' THEN
						SELECT routing_mode INTO m FROM consumers WHERE id = NEW.consumer_id;
						IF m = 'inline' THEN
							RAISE EXCEPTION 'routing_mode_conflict: role on inline consumer %', NEW.consumer_id USING ERRCODE = 'AG409';
						END IF;
						RETURN NEW;
					ELSE
						IF NEW.routing_mode = 'role_based' AND EXISTS (SELECT 1 FROM consumer_registry WHERE consumer_id = NEW.id) THEN
							RAISE EXCEPTION 'routing_mode_conflict: consumer % has inline registries', NEW.id USING ERRCODE = 'AG409';
						END IF;
						IF NEW.routing_mode = 'inline' AND EXISTS (SELECT 1 FROM consumer_role WHERE consumer_id = NEW.id) THEN
							RAISE EXCEPTION 'routing_mode_conflict: consumer % has roles attached', NEW.id USING ERRCODE = 'AG409';
						END IF;
						RETURN NEW;
					END IF;
				END;
				$$ LANGUAGE plpgsql;

				DROP TRIGGER IF EXISTS consumer_registry_mode_guard ON consumer_registry;
				CREATE TRIGGER consumer_registry_mode_guard
					BEFORE INSERT ON consumer_registry
					FOR EACH ROW EXECUTE FUNCTION enforce_consumer_routing_mode();

				DROP TRIGGER IF EXISTS consumer_role_mode_guard ON consumer_role;
				CREATE TRIGGER consumer_role_mode_guard
					BEFORE INSERT ON consumer_role
					FOR EACH ROW EXECUTE FUNCTION enforce_consumer_routing_mode();

				DROP TRIGGER IF EXISTS consumers_mode_guard ON consumers;
				CREATE TRIGGER consumers_mode_guard
					BEFORE UPDATE OF routing_mode ON consumers
					FOR EACH ROW EXECUTE FUNCTION enforce_consumer_routing_mode();`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP TRIGGER IF EXISTS consumers_mode_guard ON consumers;
				DROP TRIGGER IF EXISTS consumer_role_mode_guard ON consumer_role;
				DROP TRIGGER IF EXISTS consumer_registry_mode_guard ON consumer_registry;
				DROP FUNCTION IF EXISTS enforce_consumer_routing_mode();
				DROP TABLE IF EXISTS consumer_role;
				DROP TABLE IF EXISTS role_registry;
				DROP TABLE IF EXISTS roles;
				ALTER TABLE consumers DROP COLUMN IF EXISTS lb_config;
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_routing_mode_check;
				ALTER TABLE consumers DROP COLUMN IF EXISTS routing_mode;
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS algorithm TEXT NOT NULL DEFAULT 'round-robin';
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS embedding_config JSONB;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
