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
		ID:   "20261018120000_add_installation_naming_version",
		Name: "record tool-naming version on new store installations",
		Up:   upAddInstallationNamingVersion,
		Down: downAddInstallationNamingVersion,
	})
}

// upAddInstallationNamingVersion adds a nullable column and does not backfill.
// On Postgres 11+ ADD COLUMN of a nullable column with no default is a catalog
// change: existing rows stay NULL, which the reader treats as the original
// tool names. New inserts write 2 only while MCP_NAMING_V2 is on; otherwise
// they write NULL. Nothing in this migration UPDATEs a row.
func upAddInstallationNamingVersion(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE store_installations
			ADD COLUMN IF NOT EXISTS naming_version SMALLINT NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

// downAddInstallationNamingVersion drops the column. The versions it held are
// gone for good: a later up adds the column empty, and every install reads as
// the original names. Do not run it while a row still needs version 2.
func downAddInstallationNamingVersion(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE store_installations DROP COLUMN IF EXISTS naming_version;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
