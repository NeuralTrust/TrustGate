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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260609200000_add_mcp_registry_and_toolkit",
		Name: "add registry type/mcp_target and consumer toolkit/fail_mode",
		Up: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE registries ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'LLM';
				ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_type_check;
				ALTER TABLE registries ADD CONSTRAINT registries_type_check CHECK (type IN ('LLM', 'MCP'));
				ALTER TABLE registries ADD COLUMN IF NOT EXISTS mcp_target JSONB;
				ALTER TABLE registries ALTER COLUMN provider DROP NOT NULL;
				ALTER TABLE registries ALTER COLUMN auth DROP NOT NULL;

				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS toolkit JSONB;
				-- Nullable on purpose: fail_mode only applies to MCP consumers (NULL for LLM/A2A).
				ALTER TABLE consumers ADD COLUMN IF NOT EXISTS fail_mode TEXT;
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_fail_mode_check;
				ALTER TABLE consumers ADD CONSTRAINT consumers_fail_mode_check CHECK (fail_mode IN ('closed', 'open'));`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
		Down: func(ctx context.Context, tx pgx.Tx) error {
			const ddl = `
				ALTER TABLE consumers DROP CONSTRAINT IF EXISTS consumers_fail_mode_check;
				ALTER TABLE consumers DROP COLUMN IF EXISTS fail_mode;
				ALTER TABLE consumers DROP COLUMN IF EXISTS toolkit;

				ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_type_check;
				ALTER TABLE registries DROP COLUMN IF EXISTS mcp_target;
				ALTER TABLE registries DROP COLUMN IF EXISTS type;`
			_, err := tx.Exec(ctx, ddl)
			return err
		},
	})
}
