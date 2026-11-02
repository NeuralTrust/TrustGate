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
		ID:   "20261029120000_config_sync_connections_heartbeat",
		Name: "config sync data-plane heartbeat columns",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// last_heartbeat stays NULL for data planes that predate heartbeats;
			// their open stream keeps last_seen fresh instead.
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_sync_connections
				ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ,
				ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '',
				ADD COLUMN IF NOT EXISTS region TEXT NOT NULL DEFAULT '',
				ADD COLUMN IF NOT EXISTS deployment_type TEXT NOT NULL DEFAULT '',
				ADD COLUMN IF NOT EXISTS trustguard_base_url TEXT NOT NULL DEFAULT '',
				ADD COLUMN IF NOT EXISTS trustguard_client_id TEXT NOT NULL DEFAULT ''`)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
				ALTER TABLE config_sync_connections
				DROP COLUMN IF EXISTS trustguard_client_id,
				DROP COLUMN IF EXISTS trustguard_base_url,
				DROP COLUMN IF EXISTS deployment_type,
				DROP COLUMN IF EXISTS region,
				DROP COLUMN IF EXISTS version,
				DROP COLUMN IF EXISTS last_heartbeat`)
			return err
		},
	})
}
