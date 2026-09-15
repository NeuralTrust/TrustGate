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
		ID:   "20260830120000_add_store_installations",
		Name: "add store_installations for per-principal MCP Store installs",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				CREATE TABLE IF NOT EXISTS store_installations (
					id UUID PRIMARY KEY,
					gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					principal_sub TEXT NOT NULL,
					catalog_code TEXT NOT NULL,
					status TEXT NOT NULL,
					installed_by TEXT NOT NULL DEFAULT '',
					config JSONB,
					created_at TIMESTAMPTZ NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL,
					UNIQUE (gateway_id, principal_sub, catalog_code)
				);
				-- CatalogScoper: what a principal installed.
				CREATE INDEX IF NOT EXISTS idx_store_installations_principal
					ON store_installations (gateway_id, principal_sub);
				-- Admin visibility: who installed a given catalog entry.
				CREATE INDEX IF NOT EXISTS idx_store_installations_code
					ON store_installations (gateway_id, catalog_code);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS store_installations;`)
			return err
		},
	})
}
