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
		ID:   "20260611120000_consumer_slug_replaces_path",
		Name: "replace consumer custom path with an auto-generated slug",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS slug TEXT;
				UPDATE consumers
				   SET slug = substr(md5(id::text || clock_timestamp()::text), 1, 8)
				 WHERE slug IS NULL;
				ALTER TABLE consumers ALTER COLUMN slug SET NOT NULL;
				CREATE UNIQUE INDEX IF NOT EXISTS consumers_slug_unique_idx ON consumers (slug);
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_gateway_path_unique;
				DROP INDEX IF EXISTS consumers_gateway_path_unique;
				ALTER TABLE consumers DROP COLUMN IF EXISTS path;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS path TEXT NOT NULL DEFAULT '';
				DROP INDEX IF EXISTS consumers_slug_unique_idx;
				ALTER TABLE consumers DROP COLUMN IF EXISTS slug;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
