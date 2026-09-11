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
		ID:   "20260911120000_store_installations_requester_groups",
		Name: "keep the requester's groups on a Store install request",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// The group keys the requester carried when the request was filed.
			// An approval may grant one of their groups instead of the person,
			// and the gateway holds no group directory of its own — without this
			// the approver's choice could not be checked against what the
			// requester actually had, so an approval could close a request while
			// granting a group the requester is not in. Empty for a self-service
			// install, and for requests filed before this column existed.
			const ddl = `
				ALTER TABLE store_installations
					ADD COLUMN IF NOT EXISTS requester_groups TEXT[] NOT NULL DEFAULT '{}';`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE store_installations
					DROP COLUMN IF EXISTS requester_groups;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
