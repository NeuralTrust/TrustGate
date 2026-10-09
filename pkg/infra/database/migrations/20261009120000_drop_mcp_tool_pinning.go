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

// MCP tool pinning was withdrawn before it was released, and its migration
// (20261005120000_add_mcp_tool_pinning) went with it. A fresh database never
// gets the schema; this drops it from a database that applied that migration.
// Every statement is guarded, so it is a no-op on one that never did.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261009120000_drop_mcp_tool_pinning",
		Name: "drop the registry tool policy and the pinned tool table",
		Up:   upDropMCPToolPinning,
		Down: downDropMCPToolPinning,
	})
}

const dropMCPToolPinningDDL = `
	DROP TABLE IF EXISTS registry_tools;
	ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_tool_policy_check;
	ALTER TABLE registries DROP COLUMN IF EXISTS tool_policy;`

func upDropMCPToolPinning(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, dropMCPToolPinningDDL)
	return err
}

func downDropMCPToolPinning(_ context.Context, _ pgx.Tx) error {
	// Nothing reads the policy or the pinned tools any more, so there is
	// nothing to restore them for.
	return nil
}
