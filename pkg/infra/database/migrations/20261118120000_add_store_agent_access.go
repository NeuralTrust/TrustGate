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
		ID:   "20261118120000_add_store_agent_access",
		Name: "add store_agent_access (which A2A agents each principal may call from the Employee portal)",
		Up:   upAddStoreAgentAccess,
		Down: downAddStoreAgentAccess,
	})
}

// upAddStoreAgentAccess stores one row per principal of a gateway: everyone
// (principal_type all, empty id), a group or a user, the mode, and the agents
// picked when the mode is selected, as a JSON array of registry ids.
func upAddStoreAgentAccess(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `
		CREATE TABLE IF NOT EXISTS store_agent_access (
			gateway_id     UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
			principal_type TEXT NOT NULL CHECK (principal_type IN ('all', 'group', 'user')),
			principal_id   TEXT NOT NULL,
			mode           TEXT NOT NULL CHECK (mode IN ('all', 'selected', 'none')),
			registry_ids   JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at     TIMESTAMPTZ NOT NULL,
			updated_at     TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (gateway_id, principal_type, principal_id)
		);`
	_, err := tx.Exec(ctx, ddl)
	return err
}

func downAddStoreAgentAccess(ctx context.Context, tx pgx.Tx) error {
	const ddl = llmStoreLockTimeout + `DROP TABLE IF EXISTS store_agent_access;`
	_, err := tx.Exec(ctx, ddl)
	return err
}
