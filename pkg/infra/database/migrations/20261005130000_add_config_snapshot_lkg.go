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
		ID:   "20261005130000_add_config_snapshot_lkg",
		Name: "add the admin's persisted last-good config snapshot table",
		Up:   upAddConfigSnapshotLKG,
		Down: downAddConfigSnapshotLKG,
	})
}

// config_snapshot_lkg holds the last good compiled snapshot of each scope, one
// row per scope (” is the global snapshot). payload is zstd-compressed then
// AES-GCM encrypted, so it is incompressible: EXTERNAL storage keeps TOAST from
// spending CPU trying. compiled_at guards the upsert so an older compile never
// overwrites a newer one. key_id names the key that sealed the row, so a row
// written under a rotated secret is skipped rather than failing to decrypt.
func upAddConfigSnapshotLKG(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		CREATE TABLE IF NOT EXISTS config_snapshot_lkg (
			scope       TEXT        PRIMARY KEY,
			version     TEXT        NOT NULL,
			compiled_at TIMESTAMPTZ NOT NULL,
			key_id      TEXT        NOT NULL,
			payload     BYTEA       NOT NULL
		);
		ALTER TABLE config_snapshot_lkg ALTER COLUMN payload SET STORAGE EXTERNAL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddConfigSnapshotLKG(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS config_snapshot_lkg;`)
	return err
}
