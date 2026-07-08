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
		ID:   "20260708000000_config_sync_connections",
		Name: "config sync data-plane connection registry",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			stmts := []string{
				`CREATE TABLE IF NOT EXISTS config_sync_connections (
					scope           TEXT NOT NULL,
					instance_id     TEXT NOT NULL,
					state           TEXT NOT NULL,
					first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
					applied_version TEXT NOT NULL DEFAULT '',
					PRIMARY KEY (scope, instance_id)
				);`,
				`CREATE INDEX IF NOT EXISTS idx_config_sync_connections_scope
					ON config_sync_connections (scope);`,
			}
			for _, stmt := range stmts {
				if _, err := tx.Exec(ctx, stmt); err != nil {
					return err
				}
			}
			return nil
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS config_sync_connections;`)
			return err
		},
	})
}
