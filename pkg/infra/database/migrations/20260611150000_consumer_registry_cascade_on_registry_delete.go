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
		ID:   "20260611150000_consumer_registry_cascade_on_registry_delete",
		Name: "cascade consumer relation rows when a registry or auth is deleted",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_registry DROP CONSTRAINT IF EXISTS consumer_registry_registry_id_fkey;
				ALTER TABLE consumer_registry ADD CONSTRAINT consumer_registry_registry_id_fkey
					FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE;
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE CASCADE;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_registry DROP CONSTRAINT IF EXISTS consumer_registry_registry_id_fkey;
				ALTER TABLE consumer_registry ADD CONSTRAINT consumer_registry_registry_id_fkey
					FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE RESTRICT;
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE RESTRICT;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
