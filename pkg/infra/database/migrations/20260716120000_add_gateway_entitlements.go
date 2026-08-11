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
		ID:   "20260716120000_add_gateway_entitlements",
		Name: "add gateways.entitlements for the gateway plan rate-limit tier",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways ADD COLUMN IF NOT EXISTS entitlements JSONB NOT NULL DEFAULT '{"tier":"free"}'::jsonb;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `ALTER TABLE gateways DROP COLUMN IF EXISTS entitlements;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
