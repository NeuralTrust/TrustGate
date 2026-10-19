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

// Tool names no longer depend on a stored version, so the column
// 20261018120000_add_installation_naming_version added is dropped. This
// migration runs after that one. It does not rewrite installation rows.
// The down migration puts the column back, empty, so a rollback of this
// step alone can reapply the earlier migration's shape.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261018210000_drop_installation_naming_version",
		Name: "drop the unused tool-naming version from store installations",
		Up:   upDropInstallationNamingVersion,
		Down: downDropInstallationNamingVersion,
	})
}

func upDropInstallationNamingVersion(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE store_installations DROP COLUMN IF EXISTS naming_version;`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downDropInstallationNamingVersion(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		ALTER TABLE store_installations
			ADD COLUMN IF NOT EXISTS naming_version SMALLINT NULL;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
