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
		ID:   "20260908160000_store_installations_decision",
		Name: "record the admin decision (approved/denied, by whom, when) on Store install requests",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// The approval queue keeps a history: a decided request stays on its
			// row with the verdict, so Access → Approvals can show what was
			// approved or denied, by whom and when. Empty for self-service installs.
			const ddl = `
				ALTER TABLE store_installations
					ADD COLUMN IF NOT EXISTS decision TEXT NOT NULL DEFAULT '',
					ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '',
					ADD COLUMN IF NOT EXISTS decided_at TIMESTAMPTZ NULL;
				CREATE INDEX IF NOT EXISTS idx_store_installations_decided
					ON store_installations (gateway_id, decided_at DESC)
					WHERE decision <> '';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				DROP INDEX IF EXISTS idx_store_installations_decided;
				ALTER TABLE store_installations
					DROP COLUMN IF EXISTS decision,
					DROP COLUMN IF EXISTS decided_by,
					DROP COLUMN IF EXISTS decided_at;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
