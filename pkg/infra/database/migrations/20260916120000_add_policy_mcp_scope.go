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
		ID:   "20260916120000_add_policy_mcp_scope",
		Name: "add policies.mcp_scope (MCP destinations and principals a policy applies to)",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			// RUN-1597: NULL keeps today's behaviour (the policy applies to every
			// tools/call of the consumer); '{}' is a scope that matches nothing,
			// which is what a registry delete leaves behind. No backfill.
			_, err := tx.Exec(ctx, `ALTER TABLE policies ADD COLUMN IF NOT EXISTS mcp_scope JSONB NULL;`)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `ALTER TABLE policies DROP COLUMN IF EXISTS mcp_scope;`)
			return err
		},
	})
}
