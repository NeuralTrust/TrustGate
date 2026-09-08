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
		ID:   "20260909140000_add_consumer_auth_binding",
		Name: "add consumers.auth_binding (allowed client ids / certificate subjects)",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// Which callers of a shared trust anchor (external IdP, mTLS CA) may
			// enter the consumer. Empty means every caller the anchor verifies,
			// which is today's behaviour for every existing consumer.
			const ddl = `
				ALTER TABLE consumers
					ADD COLUMN IF NOT EXISTS auth_binding JSONB NOT NULL DEFAULT '{}'::jsonb;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `ALTER TABLE consumers DROP COLUMN IF EXISTS auth_binding;`)
			return err
		},
	})
}
