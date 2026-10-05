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
		ID:   "20261005120000_add_mcp_tool_pinning",
		Name: "add the registry tool policy and the per-registry pinned tool table",
		Up:   upAddMCPToolPinning,
		Down: downAddMCPToolPinning,
	})
}

// registry_tools holds every (name, fingerprint) an MCP registry has been seen
// to expose. The primary key leads with registry_id, so it also serves "all
// rows for a registry"; a changed definition is a new row, never an update of
// the approved one. definition is the semantic {name, description, inputSchema} the
// fingerprint was computed from, kept so a reviewer can see what changed. jsonb
// re-serialises it, so it is not the hashed bytes and must never be re-hashed:
// identity is the fingerprint column.
// decided_at and decided_by stay NULL while a tool is pending.
func upAddMCPToolPinning(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		ALTER TABLE registries ADD COLUMN IF NOT EXISTS tool_policy TEXT NOT NULL DEFAULT 'auto';
		ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_tool_policy_check;
		ALTER TABLE registries ADD CONSTRAINT registries_tool_policy_check CHECK (tool_policy IN ('auto', 'pinned'));

		CREATE TABLE IF NOT EXISTS registry_tools (
			registry_id   UUID        NOT NULL REFERENCES registries (id) ON DELETE CASCADE,
			tool_name     TEXT        NOT NULL,
			fingerprint   TEXT        NOT NULL,
			definition    JSONB       NOT NULL,
			status        TEXT        NOT NULL DEFAULT 'pending',
			first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			decided_at    TIMESTAMPTZ NULL,
			decided_by    TEXT        NULL,
			CONSTRAINT registry_tools_pkey PRIMARY KEY (registry_id, tool_name, fingerprint),
			CONSTRAINT registry_tools_status_check CHECK (status IN ('approved', 'pending', 'rejected'))
		);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddMCPToolPinning(ctx context.Context, tx pgx.Tx) error {
	const ddl = `
		DROP TABLE IF EXISTS registry_tools;
		ALTER TABLE registries DROP CONSTRAINT IF EXISTS registries_tool_policy_check;
		ALTER TABLE registries DROP COLUMN IF EXISTS tool_policy;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
