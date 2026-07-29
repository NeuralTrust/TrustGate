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
		ID:   "20260729120000_add_auth_key_preview",
		Name: "store non-secret api_key prefix/suffix for list/get recognition",
		Up:   upAddAuthKeyPreview,
		Down: downAddAuthKeyPreview,
	})
}

func upAddAuthKeyPreview(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE auths ADD COLUMN IF NOT EXISTS key_prefix TEXT;
		ALTER TABLE auths ADD COLUMN IF NOT EXISTS key_suffix TEXT;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddAuthKeyPreview(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE auths DROP COLUMN IF EXISTS key_suffix;
		ALTER TABLE auths DROP COLUMN IF EXISTS key_prefix;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
