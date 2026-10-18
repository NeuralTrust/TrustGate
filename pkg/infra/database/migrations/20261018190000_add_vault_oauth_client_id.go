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
		ID:   "20261018190000_add_vault_oauth_client_id",
		Name: "record the dynamic client a forwarded grant was issued to",
		Up:   upAddVaultOAuthClientID,
		Down: downAddVaultOAuthClientID,
	})
}

// upAddVaultOAuthClientID adds an empty column. Existing rows are not updated:
// an empty oauth_client_id means the grant was issued before the client was
// recorded, and refresh keeps the legacy registration for that grant.
func upAddVaultOAuthClientID(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE vault_credentials ADD COLUMN IF NOT EXISTS oauth_client_id TEXT NOT NULL DEFAULT '';`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddVaultOAuthClientID(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE vault_credentials DROP COLUMN IF EXISTS oauth_client_id;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
