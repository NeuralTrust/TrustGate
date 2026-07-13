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
		ID:   "20260713000000_add_model_release_date_and_modalities",
		Name: "add models_catalog.release_date and input/output modalities; order by release date",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE models_catalog ADD COLUMN IF NOT EXISTS release_date DATE;
				ALTER TABLE models_catalog ADD COLUMN IF NOT EXISTS input_modalities TEXT[] NOT NULL DEFAULT '{}';
				ALTER TABLE models_catalog ADD COLUMN IF NOT EXISTS output_modalities TEXT[] NOT NULL DEFAULT '{}';
				CREATE INDEX IF NOT EXISTS models_catalog_release_date_idx ON models_catalog (release_date DESC);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP INDEX IF EXISTS models_catalog_release_date_idx;
				ALTER TABLE models_catalog DROP COLUMN IF EXISTS output_modalities;
				ALTER TABLE models_catalog DROP COLUMN IF EXISTS input_modalities;
				ALTER TABLE models_catalog DROP COLUMN IF EXISTS release_date;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
