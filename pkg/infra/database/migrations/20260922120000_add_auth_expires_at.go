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
		ID:   "20260922120000_add_auth_expires_at",
		Name: "give api keys an optional expiry",
		Up:   upAddAuthExpiresAt,
		Down: downAddAuthExpiresAt,
	})
}

// NULL means the key never expires, which is what every key written before
// this column existed was: the column is added nullable so no backfill can
// retire a credential somebody is using.
func upAddAuthExpiresAt(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE auths ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddAuthExpiresAt(ctx context.Context, tx pgx.Tx) error {
	const ddl = `ALTER TABLE auths DROP COLUMN IF EXISTS expires_at;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
