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

// Nullable: pre-existing markers with no kind read as dirtying everything.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261106120000_outbox_dirty_scope",
		Name: "config snapshot outbox markers name what they dirty",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_snapshot_outbox
					ADD COLUMN IF NOT EXISTS gateway_id UUID NULL,
					ADD COLUMN IF NOT EXISTS kind TEXT NULL;`)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_snapshot_outbox
					DROP COLUMN IF EXISTS kind,
					DROP COLUMN IF EXISTS gateway_id;`)
			return err
		},
	})
}
