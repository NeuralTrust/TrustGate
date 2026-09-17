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
		ID:   "20260909120000_store_installations_reason",
		Name: "keep the requester's reason on a Store install request",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Why the user asked for this server, in their own words. The
			// approval queue has had a Reason column since it was built and
			// nothing to put in it: an approver deciding on a request needs to
			// know what it is for. Empty for a self-service install, which asks
			// nobody, and for requests filed before this column existed.
			const ddl = `
				ALTER TABLE store_installations
					ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE store_installations
					DROP COLUMN IF EXISTS reason;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
