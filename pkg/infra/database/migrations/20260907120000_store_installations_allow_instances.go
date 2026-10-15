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
		ID:   "20260907120000_store_installations_allow_instances",
		Name: "allow multiple MCP Store installs per (gateway, principal, code) as distinct instances",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// A principal can now install the same catalog server more than once as
			// separate instances (e.g. two Snowflake schemas), each distinguished by
			// its per-user config. Drop the (gateway, principal, code) uniqueness so
			// those rows can coexist; the row id (PK) is the stable instance handle,
			// and the app dedupes exact-config repeats. Installs are upserted by id.
			const ddl = `
				ALTER TABLE store_installations
					DROP CONSTRAINT IF EXISTS store_installations_gateway_id_principal_sub_catalog_code_key;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			// Restore the single-instance uniqueness. Best-effort: if duplicate
			// instances exist this will fail, which is the correct signal that the
			// data no longer fits the old one-per-code shape.
			const ddl = `
				ALTER TABLE store_installations
					ADD CONSTRAINT store_installations_gateway_id_principal_sub_catalog_code_key
					UNIQUE (gateway_id, principal_sub, catalog_code);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
