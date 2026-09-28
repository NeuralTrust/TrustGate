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
		ID:   "20260909120000_drop_roles_and_routing_mode",
		Name: "drop role_based routing: roles tables, junctions, guards and consumers.routing_mode",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Every consumer now routes inline over its own registry
			// associations. Roles (IdP-claim → registry mappings) and the
			// routing_mode switch are gone, together with the triggers that
			// kept the two modes mutually exclusive. The cross-gateway junction
			// guard function stays: its consumer_role/role_registry branches
			// are simply never reached once those tables are dropped.
			const ddl = `
				DROP TRIGGER IF EXISTS consumers_mode_guard ON consumers;
				DROP TRIGGER IF EXISTS consumer_registry_mode_guard ON consumer_registry;
				DROP TRIGGER IF EXISTS consumer_role_mode_guard ON consumer_role;
				DROP TRIGGER IF EXISTS consumer_role_gateway_guard ON consumer_role;
				DROP TRIGGER IF EXISTS role_registry_gateway_guard ON role_registry;
				DROP FUNCTION IF EXISTS enforce_consumer_routing_mode();
				DROP TABLE IF EXISTS consumer_role;
				DROP TABLE IF EXISTS role_registry;
				DROP TABLE IF EXISTS roles;
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_routing_mode_check;
				ALTER TABLE consumers DROP COLUMN IF EXISTS routing_mode;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			// Restores the schema only; role rows and per-consumer routing
			// modes are not recoverable (every consumer comes back as inline).
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS routing_mode TEXT NOT NULL DEFAULT 'inline';
				DO $$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint WHERE conname = 'consumers_routing_mode_check'
					) THEN
						ALTER TABLE consumers ADD CONSTRAINT consumers_routing_mode_check CHECK (routing_mode IN ('inline','role_based'));
					END IF;
				END $$;
				CREATE TABLE IF NOT EXISTS roles (
					id             UUID PRIMARY KEY,
					gateway_id     UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
					name           TEXT NOT NULL,
					model_policies JSONB,
					mcp_policies   JSONB,
					oidc_mapping   JSONB,
					created_at     TIMESTAMPTZ NOT NULL,
					updated_at     TIMESTAMPTZ NOT NULL,
					CONSTRAINT roles_gateway_name_unique UNIQUE (gateway_id, name)
				);
				CREATE INDEX IF NOT EXISTS roles_gateway_id_idx ON roles (gateway_id);
				CREATE INDEX IF NOT EXISTS roles_name_lower_idx ON roles (lower(name));
				CREATE INDEX IF NOT EXISTS roles_gateway_created_at_id_idx ON roles (gateway_id, created_at DESC, id);
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
				CREATE INDEX IF NOT EXISTS consumer_role_role_idx ON consumer_role (role_id);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
