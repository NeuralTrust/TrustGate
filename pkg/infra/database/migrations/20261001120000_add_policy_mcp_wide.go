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
		ID:   "20261001120000_add_policy_mcp_wide",
		Name: "add policies.mcp_wide (runs on every MCP consumer and the Store), exclusive with global",
		Up:   upAddPolicyMCPWide,
		Down: downAddPolicyMCPWide,
	})
}

func upAddPolicyMCPWide(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE policies ADD COLUMN IF NOT EXISTS mcp_wide BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_global_mcp_wide_check;
		ALTER TABLE policies ADD CONSTRAINT policies_global_mcp_wide_check CHECK (NOT (global AND mcp_wide));`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddPolicyMCPWide(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_global_mcp_wide_check;
		ALTER TABLE policies DROP COLUMN IF EXISTS mcp_wide;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
