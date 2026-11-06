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
		ID:   "20261105120000_add_store_everyone",
		Name: "add store_everyone (the Store access every group passes on, per gateway)",
		Up:   upAddStoreEveryone,
		Down: downAddStoreEveryone,
	})
}

// upAddStoreEveryone stores one Everyone object per gateway: its Store level,
// the servers it grants as a JSON array, and the excluded group keys.
func upAddStoreEveryone(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		CREATE TABLE IF NOT EXISTS store_everyone (
			gateway_id      UUID PRIMARY KEY REFERENCES gateways(id) ON DELETE CASCADE,
			mode            TEXT NOT NULL CHECK (mode IN ('open', 'curated')),
			grants          JSONB NOT NULL DEFAULT '[]'::jsonb,
			excluded_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at      TIMESTAMPTZ NOT NULL,
			updated_at      TIMESTAMPTZ NOT NULL
		);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddStoreEveryone(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `DROP TABLE IF EXISTS store_everyone;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
