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
		ID:   "20260908120000_add_store_grants",
		Name: "add store_grants (Store access by catalog code / instance) and bind installs to a registry instance",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Store access grants move off the registry (mcp_target.store) onto their
			// own table keyed by catalog code, so the whole catalog is grantable before
			// any registry exists. registry_id narrows a grant to one configured
			// instance; the nil uuid means "the code, every instance". It is part of
			// the key rather than NULL so the natural-key upsert has a plain conflict
			// target.
			const ddl = `
				CREATE TABLE IF NOT EXISTS store_grants (
					gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					catalog_code TEXT NOT NULL,
					registry_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
					groups JSONB NOT NULL DEFAULT '[]'::jsonb,
					users JSONB NOT NULL DEFAULT '[]'::jsonb,
					created_at TIMESTAMPTZ NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL,
					PRIMARY KEY (gateway_id, catalog_code, registry_id)
				);
				-- Registry deletion cleans its instance grants (lookup by registry).
				CREATE INDEX IF NOT EXISTS idx_store_grants_registry
					ON store_grants (gateway_id, registry_id);
				-- An install may bind to one configured instance of its code (a
				-- registry). NULL = the code's canonical instance.
				ALTER TABLE store_installations
					ADD COLUMN IF NOT EXISTS registry_id UUID;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE store_installations DROP COLUMN IF EXISTS registry_id;
				DROP TABLE IF EXISTS store_grants;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
