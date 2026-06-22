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
		ID:   "20260617000000_purge_openrouter_catalog",
		Name: "remove catalog models sourced from openrouter",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// The catalog now syncs provider-native model IDs from models.dev.
			// Rows from the previous OpenRouter sync carry OpenRouter-style slugs
			// (e.g. "claude-sonnet-4.6") that no provider API accepts; they are
			// derived data fully regenerated on the next sync.
			const ddl = `DELETE FROM models_catalog WHERE source = 'openrouter';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(_ context.Context, _ pgx.Tx) error {
			return nil
		},
	})
}
