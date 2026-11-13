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
		ID:   "20261112180000_config_sync_connections_secret_stores",
		Name: "config sync data-plane secret stores columns",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Data planes that predate secret references leave both at their
			// defaults: no capability, no stores.
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_sync_connections
				ADD COLUMN IF NOT EXISTS accepts_secret_refs BOOLEAN NOT NULL DEFAULT FALSE,
				ADD COLUMN IF NOT EXISTS secret_stores JSONB`)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_sync_connections
				DROP COLUMN IF EXISTS secret_stores,
				DROP COLUMN IF EXISTS accepts_secret_refs`)
			return err
		},
	})
}
