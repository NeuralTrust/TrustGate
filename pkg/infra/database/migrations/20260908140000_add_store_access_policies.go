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
		ID:   "20260908140000_add_store_access_policies",
		Name: "add store_access_policies (per-principal Store access level per gateway)",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// A principal's Store access level (open | curated | none) on a gateway,
			// set on the Access page and evaluated live by the gateway on every
			// request — so a change applies at once instead of riding a token claim
			// until the principal's next login. principal_type is "user" (subject)
			// or "group" (a group key matched against the token's groups claim).
			const ddl = `
				CREATE TABLE IF NOT EXISTS store_access_policies (
					gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
					principal_type TEXT NOT NULL,
					principal_id TEXT NOT NULL,
					mode TEXT NOT NULL,
					created_at TIMESTAMPTZ NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL,
					PRIMARY KEY (gateway_id, principal_type, principal_id)
				);`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DROP TABLE IF EXISTS store_access_policies;`)
			return err
		},
	})
}
