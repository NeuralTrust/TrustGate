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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260617180000_restrict_consumer_auth_on_auth_delete",
		Name: "restrict deleting an auth still referenced by a consumer",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE RESTRICT;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumer_auth DROP CONSTRAINT IF EXISTS consumer_auth_auth_id_fkey;
				ALTER TABLE consumer_auth ADD CONSTRAINT consumer_auth_auth_id_fkey
					FOREIGN KEY (auth_id) REFERENCES auths(id) ON DELETE CASCADE;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
