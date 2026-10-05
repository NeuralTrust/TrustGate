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
		ID:   "20261005120100_add_auth_owner",
		Name: "let an api key belong to one user per gateway",
		Up:   upAddAuthOwner,
		Down: downAddAuthOwner,
	})
}

func upAddAuthOwner(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE auths ADD COLUMN IF NOT EXISTS owner_id TEXT NULL;
		CREATE UNIQUE INDEX IF NOT EXISTS auths_gateway_owner_uniq ON auths (gateway_id, owner_id) WHERE owner_id IS NOT NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddAuthOwner(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		DROP INDEX IF EXISTS auths_gateway_owner_uniq;
		ALTER TABLE auths DROP COLUMN IF EXISTS owner_id;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
