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
		ID:   "20261022130000_add_key_group_budgets",
		Name: "give a directory group's keys a monthly budget per gateway",
		Up:   upAddKeyGroupBudgets,
		Down: downAddKeyGroupBudgets,
	})
}

// upAddKeyGroupBudgets stores one budget per (gateway, group): the group's
// monthly total and its per-member limit, in dollars, with per-member
// overrides as a JSON object of owner id to dollars. A NULL limit is no limit.
func upAddKeyGroupBudgets(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		CREATE TABLE IF NOT EXISTS key_group_budgets (
			gateway_id               UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
			group_id                 TEXT NOT NULL,
			monthly_limit_usd        DOUBLE PRECISION NULL,
			member_monthly_limit_usd DOUBLE PRECISION NULL,
			member_overrides         JSONB NULL,
			action                   TEXT NOT NULL CHECK (action IN ('alert', 'block')),
			created_at               TIMESTAMPTZ NOT NULL,
			updated_at               TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (gateway_id, group_id)
		);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddKeyGroupBudgets(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `DROP TABLE IF EXISTS key_group_budgets;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
